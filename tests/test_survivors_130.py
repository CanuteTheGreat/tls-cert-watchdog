"""Second round of 1.3.0 mutation survivors (nightly run 63: 84 survivors the gate listed as new).

* DER lengths >= 128 bytes in the OCSP CertID / request: real certificates never produce a CertID that
  long, so hand-built DER (serials of any size, v1 certificates without [0] version, responses with an
  explicit [0] version and several SingleResponses) is compared with an independent reference encoder.
* The tool supports Python 3.8, where int.from_bytes / int.to_bytes REQUIRE the byte order; on 3.11+
  an omitted byte order silently defaults to big-endian, so the mutants that drop it only die when the
  call is made through a stand-in that insists on it (the pre-3.11 signature).
* Codec names / header names / struct formats / argument values that are equivalent to Python but not
  to the wire or an older Python are pinned with spies on the exact call.
"""
import contextlib
import hashlib
import io
import os
import ssl
import sys
import types
import unittest
import warnings
from unittest import mock

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cert_watch  # noqa: E402
from test_ocsp_oracle import issue, pair  # noqa: E402

DER = serialization.Encoding.DER
_len = len


# ---------------------------------------------------------------- reference DER encoder
def enc_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | _len(b)]) + b


def T(tag, body=b""):
    return bytes([tag]) + enc_len(_len(body)) + body


ALG = T(0x30, T(0x06, bytes.fromhex("2a864886f70d010101")) + T(0x05))
SHA1_ALG = T(0x30, T(0x06, bytes.fromhex("2b0e03021a")) + T(0x05))


def name(cn):
    return T(0x30, T(0x31, T(0x30, T(0x06, b"\x55\x04\x03") + T(0x0C, cn))))


def fake_cert(serial_content, version=True, issuer_cn=b"ca", key=b"\x04" + b"k" * 40):
    """(certificate DER, serial TLV, issuer Name TLV, subjectPublicKey bytes without the unused-bits byte)."""
    serial = T(0x02, serial_content)
    issuer = name(issuer_cn)
    spki = T(0x30, ALG + T(0x03, b"\x00" + key))
    kids = ([T(0xA0, T(0x02, b"\x02"))] if version else []) + [
        serial, ALG, issuer, T(0x30, T(0x17, b"260101000000Z") + T(0x17, b"270101000000Z")), name(b"s"), spki]
    return T(0x30, T(0x30, b"".join(kids)) + ALG + T(0x03, b"\x00")), serial, issuer, key


def ref_cert_id(serial, issuer_name, key):
    return T(0x30, SHA1_ALG + T(0x04, hashlib.sha1(issuer_name).digest())
             + T(0x04, hashlib.sha1(key).digest()) + serial)


class StrictInt(int):
    """int whose from_bytes needs the byte order (Python < 3.11 signature)."""

    @classmethod
    def from_bytes(cls, b, byteorder, *, signed=False):
        return int.from_bytes(b, byteorder, signed=signed)


class StrictLen(int):
    """The result of len(): to_bytes needs length AND byte order (Python < 3.11 signature)."""

    def to_bytes(self, length, byteorder, *, signed=False):
        return int.to_bytes(self, length, byteorder, signed=signed)


def strict_len(x):
    return StrictLen(_len(x))


@contextlib.contextmanager
def pre311():
    with mock.patch.object(cert_watch, "int", StrictInt, create=True), \
            mock.patch.object(cert_watch, "len", strict_len, create=True):
        yield


class Rec(bytes):
    """bytes that remember how they were decoded."""
    calls = None

    def decode(self, *a, **k):
        type(self).calls.append((a, k))
        return bytes.decode(self, *a, **k)

    def __getitem__(self, i):
        r = bytes.__getitem__(self, i)
        return type(self)(r) if isinstance(i, slice) else r


def rec_bytes(data):
    cls = type("Rec%d" % id(data), (Rec,), {"calls": []})
    return cls(data), cls.calls


# ---------------------------------------------------------------- DER helpers
class TestDerHelpers(unittest.TestCase):
    def test_oid_first_byte_is_split_by_40(self):
        for raw, want in ((b"\x28", "1.0"), (b"\x50", "2.0"), (b"\x51", "2.1"), (b"\x51\x04", "2.1.4"),
                          (b"\x2a\x86\x48", "1.2.840"), (b"\x00", "0.0"), (b"\x27", "0.39")):
            with self.subTest(raw=raw):
                self.assertEqual(cert_watch._oid_to_str(raw), want)

    def test_long_form_lengths_and_rsa_size_need_an_explicit_byte_order(self):
        ca_key = __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["x"]).generate_private_key(65537, 2048)
        ca = issue("rsa ca", None, ca_key, ca_key, ca=True)
        der = ca.public_bytes(DER)
        with pre311():
            self.assertEqual(cert_watch.public_key_info(der), ("RSA", 2048, None))
            self.assertEqual(cert_watch._der_read(der, 0)[0], 0x30)
            self.assertEqual(cert_watch._der_read(b"\x30\x82\x01\x00" + b"\0" * 256, 0), (0x30, 4, 260))
            self.assertEqual(cert_watch._der_read(b"\x30\x81\x80" + b"\0" * 128, 0), (0x30, 3, 131))

    def test_critical_extension_value_is_the_last_part_not_the_flag(self):
        ikey = __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["x"]).generate_private_key(
            __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["x"]).SECP256R1())
        ca = issue("crit ca", None, ikey, ikey, ca=True)        # BasicConstraints is critical here
        found = cert_watch.cert_extensions(ca.public_bytes(DER))
        self.assertEqual(found["2.5.29.19"], b"\x30\x03\x01\x01\xff")

    def test_decode_der_cert_without_the_private_decoder_is_empty(self):
        leaf, _, _ = pair()
        der = leaf.public_bytes(DER)
        for fake in (types.SimpleNamespace(), types.SimpleNamespace(_ssl=types.SimpleNamespace())):
            with self.subTest(fake=fake):
                with mock.patch.object(cert_watch, "ssl", fake):
                    self.assertEqual(cert_watch.decode_der_cert(der), {})


class TestOcspUrlDecoding(unittest.TestCase):
    def aia_with(self, url_bytes):
        desc = T(0x30, T(0x06, bytes.fromhex("2b06010505073001")) + T(0x86, url_bytes))
        return T(0x30, desc)

    def test_url_is_decoded_as_ascii_with_replacement_not_strict(self):
        value, calls = rec_bytes(self.aia_with(b"http://o\xe9.test/"))
        with mock.patch.object(cert_watch, "cert_extensions", return_value={cert_watch.OID_AIA: value}):
            urls, staple = cert_watch.ocsp_info(b"unused")
        self.assertEqual((urls, staple), (["http://o\ufffd.test/"], False))
        self.assertEqual(calls, [(("ascii", "replace"), {})])

    def test_plain_url(self):
        with mock.patch.object(cert_watch, "cert_extensions",
                               return_value={cert_watch.OID_AIA: self.aia_with(b"http://o.test/r")}):
            self.assertEqual(cert_watch.ocsp_info(b"unused"), (["http://o.test/r"], False))


# ---------------------------------------------------------------- CertID and request
class TestHandBuiltCertId(unittest.TestCase):
    def test_cert_id_for_every_serial_size_and_version_combination(self):
        sizes = list(range(60, 75)) + [125, 126, 127, 128, 190, 191, 192, 193, 194, 195, 196, 300, 70000]
        with pre311():
            for size in sizes:
                for leaf_v in (True, False):
                    for iss_v in (True, False):
                        with self.subTest(serial=size, leaf_v3=leaf_v, issuer_v3=iss_v):
                            serial = bytes([0x01]) + b"\x42" * (size - 1)
                            leaf, serial_tlv, _, _ = fake_cert(serial, version=leaf_v, issuer_cn=b"the issuer")
                            issuer, _, issuer_name, key = fake_cert(b"\x07", version=iss_v, issuer_cn=b"root",
                                                                    key=b"\x04" + bytes(range(1, 60)))
                            # the leaf's issuer Name is what goes into the CertID, the CA's key is hashed
                            want = ref_cert_id(serial_tlv, name(b"the issuer"), key)
                            self.assertEqual(cert_watch.ocsp_cert_id(leaf, issuer), want)

    def test_object_identifier_of_sha1_is_lower_case_hex(self):
        rec = []

        class SpyBytes(bytes):
            @staticmethod
            def fromhex(s):
                rec.append(s)
                return bytes.fromhex(s)

        leaf, _, _, _ = fake_cert(b"\x05")
        issuer, _, _, _ = fake_cert(b"\x06")
        with mock.patch.object(cert_watch, "bytes", SpyBytes, create=True):
            cert_watch.ocsp_cert_id(leaf, issuer)
        self.assertEqual(rec, ["2b0e03021a"])

    def test_request_for_every_cert_id_size(self):
        sizes = [0, 1, 100, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 250, 251, 252, 253, 254, 255,
                 256, 257, 65520, 65530, 65531, 65532, 65533, 65534, 65535, 65536, 70000]
        with pre311():
            for size in sizes:
                with self.subTest(cert_id=size):
                    cid = b"\x30" + b"\x55" * size
                    want = T(0x30, T(0x30, T(0x30, T(0x30, cid))))
                    self.assertEqual(cert_watch.build_ocsp_request(cid), want)


# ---------------------------------------------------------------- responses
CID = T(0x30, b"the-cert-id")
OTHER = T(0x30, b"another-cert-id")
GOOD, REVOKED, UNKNOWN = T(0x80), T(0xA1, T(0x18, b"20260101000000Z")), T(0x82)


def single(cid, status):
    return T(0x30, cid + status + T(0x18, b"20260101000000Z"))


def response(singles, version=False, status=0):
    tbs = T(0x30, (T(0xA0, T(0x02, b"\x00")) if version else b"") + T(0xA2, T(0x04, b"k" * 20))
            + T(0x18, b"20260101000000Z") + T(0x30, b"".join(singles)))
    basic = T(0x30, tbs + ALG + T(0x03, b"\x00"))
    body = T(0xA0, T(0x30, T(0x06, bytes.fromhex("2b0601050507300101")) + T(0x04, basic)))
    return T(0x30, T(0x0A, bytes([status])) + (body if status == 0 else b""))


class TestHandBuiltResponses(unittest.TestCase):
    def test_answers_with_and_without_an_explicit_version_field(self):
        want = {GOOD: ("good", "good"), REVOKED: ("revoked", "revoked"),
                UNKNOWN: ("unknown", "responder does not know this certificate")}
        with pre311():
            for version in (False, True):
                for status, answer in want.items():
                    with self.subTest(version=version, status=status[0]):
                        self.assertEqual(cert_watch.parse_ocsp_response(
                            response([single(CID, status)], version=version), CID), answer)

    def test_the_matching_single_response_is_found_after_others(self):
        for version in (False, True):
            with self.subTest(version=version):
                data = response([single(OTHER, REVOKED), single(OTHER, UNKNOWN), single(CID, GOOD)], version=version)
                self.assertEqual(cert_watch.parse_ocsp_response(data, CID), ("good", "good"))
                self.assertEqual(cert_watch.parse_ocsp_response(data, T(0x30, b"nobody")),
                                 ("error", "response is for a different certificate"))

    def test_responder_status_codes(self):
        with pre311():
            self.assertEqual(cert_watch.parse_ocsp_response(response([], status=3), CID),
                             ("error", "responder answered tryLater"))


# ---------------------------------------------------------------- ocsp_query wire details
class FakeResp:
    def __init__(self, body):
        self.body, self.read_args = body, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        self.read_args.append(a)
        return self.body


class TestOcspQueryWire(unittest.TestCase):
    def query(self, url, body=b""):
        resp = FakeResp(body)
        made, opened = [], []

        def request(u, **kw):
            made.append((u, kw))
            return "REQ"

        def urlopen(*a, **kw):
            opened.append((a, kw))
            return resp

        with mock.patch.object(cert_watch.urllib.request, "Request", request), \
                mock.patch.object(cert_watch.urllib.request, "urlopen", urlopen), \
                mock.patch.object(cert_watch, "parse_ocsp_response", return_value=("good", "good")):
            out = cert_watch.ocsp_query(url, CID, 7.5)
        return out, made, opened, resp

    def test_https_and_mixed_case_urls_are_queried(self):
        for url in ("https://o.test/r", "HTTPS://O.test/r", "http://o.test/r", "HTTP://o.test/r"):
            with self.subTest(url=url):
                out, made, opened, _ = self.query(url)
                self.assertEqual(out, ("good", "good"))
                self.assertEqual(len(made), 1)

    def test_other_schemes_are_refused(self):
        for url in ("ftp://o.test/", "file:///etc/passwd", "o.test"):
            with self.subTest(url=url):
                out, made, _, _ = self.query(url)
                self.assertEqual(out, ("error", "unsupported responder URL scheme"))
                self.assertEqual(made, [])

    def test_request_headers_are_exactly_cased_and_body_is_the_ocsp_request(self):
        _, made, opened, resp = self.query("http://o.test/r")
        self.assertEqual(made, [("http://o.test/r", {
            "data": cert_watch.build_ocsp_request(CID),
            "headers": {"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}})])
        self.assertEqual(opened, [(("REQ",), {"timeout": 7.5})])
        self.assertEqual(resp.read_args, [(1048576,)])


# ---------------------------------------------------------------- STARTTLS reads
class RecFile:
    def __init__(self, *lines):
        self.lines = list(lines)

    def readline(self, n):
        return self.lines.pop(0) if self.lines else b""


class RecSock:
    def __init__(self, *lines):
        self.f, self.sent = RecFile(*lines), []

    def makefile(self, mode):
        return self.f

    def sendall(self, b):
        self.sent.append(b)


class TestStartTlsExact(unittest.TestCase):
    def test_reply_keeps_trailing_spaces_and_letters_and_strips_only_line_ends(self):
        f = RecFile(b"250-A  \r\n", b"250 EXX\r\n")
        self.assertEqual(cert_watch._reply(f), ("250", ["250-A  ", "250 EXX"]))
        self.assertEqual(cert_watch._reply(RecFile(b"250 line\n")), ("250", ["250 line"]))
        self.assertEqual(cert_watch._reply(RecFile(b"250 line\r")), ("250", ["250 line"]))

    def test_reply_is_decoded_as_utf8_with_replacement(self):
        line, calls = rec_bytes(b"250 ok\r\n")
        cert_watch._reply(RecFile(line))
        self.assertEqual(calls, [(("utf-8", "replace"), {})])

    def test_imap_refusal_is_decoded_as_utf8_with_replacement(self):
        line, calls = rec_bytes(b"a1 NO later\r\n")
        with self.assertRaises(cert_watch.StartTLSError):
            cert_watch._negotiate_starttls(RecSock(b"* OK hi\r\n", line), "imap")
        self.assertEqual(calls, [(("utf-8", "replace"), {})])

    def test_postgres_ssl_request_is_two_signed_big_endian_ints(self):
        class S(RecSock):
            def recv(self, n):
                return b"S"

        s = S()
        with mock.patch.object(cert_watch.struct, "pack", wraps=cert_watch.struct.pack) as pack:
            cert_watch._negotiate_starttls(s, "postgres")
        pack.assert_called_once_with("!ii", 8, 80877103)
        self.assertEqual(s.sent, [b"\x00\x00\x00\x08\x04\xd2\x16\x2f"])


# ---------------------------------------------------------------- protocol probing / contexts
class WarnCtx:
    """A context whose version setters emit a DeprecationWarning and an unrelated UserWarning."""

    def __init__(self, *a):
        self.log = []

    def __setattr__(self, k, v):
        if k in ("minimum_version", "maximum_version"):
            warnings.warn("deprecated version", DeprecationWarning)
            warnings.warn("unrelated", UserWarning)
        object.__setattr__(self, k, v)

    def set_ciphers(self, c):
        pass


class TestProbeAndContext(unittest.TestCase):
    def recorded(self, fn):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            fn()
        return sorted(x.category.__name__ for x in w)

    def test_permissive_context_only_silences_deprecation_warnings(self):
        with mock.patch.object(cert_watch.ssl, "SSLContext", WarnCtx):
            got = self.recorded(cert_watch._permissive_context)
        self.assertEqual(got, ["UserWarning"])

    def test_permissive_context_is_not_verifying(self):
        ctx = cert_watch._permissive_context()
        self.assertIs(ctx.check_hostname, False)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        with mock.patch.object(cert_watch.ssl, "SSLContext", WarnCtx):
            ctx = cert_watch._permissive_context()
        self.assertIs(ctx.check_hostname, False)

    def test_probe_only_silences_deprecation_warnings(self):
        def run():
            with mock.patch.object(cert_watch, "_permissive_context", WarnCtx), \
                    mock.patch.object(cert_watch, "_handshake", return_value=(None, "TLSv1.2", None, None)):
                cert_watch.probe_protocols("h.test", 443, 3)
        self.assertEqual(self.recorded(run), ["UserWarning"] * 3 + ["UserWarning"] * 5)

    def test_unknown_version_name_is_untested_not_a_crash(self):
        class Ctx:
            def __setattr__(self, k, v):
                if v is None:
                    raise ValueError("no such version")
                object.__setattr__(self, k, v)

        with mock.patch.object(cert_watch, "PROTOCOL_VERSIONS", [("TLSvX", "NO_SUCH_VERSION")]), \
                mock.patch.object(cert_watch, "_permissive_context", Ctx):
            self.assertEqual(cert_watch.probe_protocols("h.test", 443, 3), {"TLSvX": None})

    def test_missing_tls13_support_skips_only_that_version(self):
        calls = []

        def hs(host, port, ctx, timeout, starttls):
            calls.append(ctx.maximum_version)
            return None, "TLSv1.2", None, None

        order = [("TLSv1.3", "TLSv1_3"), ("TLSv1.2", "TLSv1_2")]
        with mock.patch.object(cert_watch, "PROTOCOL_VERSIONS", order), \
                mock.patch.object(cert_watch.ssl, "HAS_TLSv1_3", False), \
                mock.patch.object(cert_watch, "_handshake", hs):
            out = cert_watch.probe_protocols("h.test", 443, 3)
        self.assertEqual(out, {"TLSv1.3": None, "TLSv1.2": True})
        self.assertEqual(calls, [ssl.TLSVersion.TLSv1_2])

    def test_tls13_flag_default_is_false(self):
        asked = []
        real = getattr

        def spy(obj, name, *default):
            if name == "HAS_TLSv1_3":
                asked.append(default)
            return real(obj, name, *default)

        with mock.patch.object(cert_watch, "getattr", spy, create=True), \
                mock.patch.object(cert_watch, "_handshake", return_value=(None, "TLSv1.2", None, None)):
            cert_watch.probe_protocols("h.test", 443, 3)
        self.assertEqual(asked, [(False,)])


# ---------------------------------------------------------------- check_host without a certificate
class TestNoCertificate(unittest.TestCase):
    def test_empty_certificate_is_never_decoded(self):
        boom = mock.Mock(side_effect=AssertionError("must not be called without a certificate"))
        for der in (None, b""):
            with self.subTest(der=der):
                with mock.patch.object(cert_watch, "_handshake",
                                       return_value=(der, "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), None)), \
                        mock.patch.object(cert_watch, "_permissive_context", mock.Mock()), \
                        mock.patch.object(cert_watch, "decode_der_cert", boom), \
                        mock.patch.object(cert_watch, "signature_oid", boom), \
                        mock.patch.object(cert_watch, "public_key_info", boom):
                    r = cert_watch.check_host("h.test", 443, 14, 5, "", False)
                self.assertNotIn("key", r)
                self.assertNotIn("signature_oid", r)
                self.assertNotIn("san", r)


# ---------------------------------------------------------------- command line
EXPECTED_HELP = (
    "hosts [scheme://]host[:port] to check (schemes: smtp, submission, imap, pop3, ftp, postgres, https) "
    "{OPTIONS}: -h, --help show this help message and exit --version show program's version number and exit "
    "--file FILE file with one [scheme://]host[:port] per line "
    "--starttls {smtp,imap,pop3,ftp,postgres,none} force a STARTTLS protocol for every target "
    "(default: from the scheme or well-known port) "
    "--warn-days WARN_DAYS HIGH-severity threshold for days until expiry (default 14) "
    "--json machine-readable JSON output "
    "--timeout TIMEOUT per-connection timeout in seconds (default 10) "
    "--no-protocol-scan don't try each TLS version separately (one handshake per host instead of five) "
    "--fail-on {high,medium,low,never} lowest severity that makes the exit code 1 (default: high) "
    "--ocsp ask the certificate's OCSP responder whether it is revoked (needs the server's chain: Python 3.13+)")


class TestHelpBody(unittest.TestCase):
    def test_whole_help_body(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as cm:
                cert_watch.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        flat = " ".join(out.getvalue().split())
        body = flat[flat.index("positional arguments:") + len("positional arguments:"):].strip()
        for title in ("optional arguments:", "options:"):          # the title differs across Pythons
            body = body.replace(" " + title + " ", " {OPTIONS}: ")
        body = body.replace("{OPTIONS}: ", "{OPTIONS}: ", 1)
        self.assertEqual(body.replace("{OPTIONS}:", "{OPTIONS}:"), EXPECTED_HELP)


if __name__ == "__main__":
    unittest.main()
