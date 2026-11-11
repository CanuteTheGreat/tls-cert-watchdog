"""More behaviour pinned after the 1.3.0 mutation run (survivors of check_host's OCSP branch, the text
report's OCSP line, --help, defaults and exit gates in main(), STARTTLS reads, protocol probing and
a few DER/target helpers). Network handshakes are replaced; OCSP answers come from stubs."""
import contextlib
import datetime
import io
import os
import re
import ssl
import sys
import tempfile
import types
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cert_watch  # noqa: E402
from cryptography import x509  # noqa: E402
from test_ocsp_oracle import OCSP_OID, aia, pair  # noqa: E402

DER = serialization.Encoding.DER
MODERN = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
FEAT = x509.TLSFeature([x509.TLSFeatureType.status_request])


def ocsp_leaf(url=True, staple=False):
    exts = [x509.SubjectAlternativeName([x509.DNSName("h.test")])] + (
        [aia((OCSP_OID, "http://ocsp.test/r"))] if url else []) + ([FEAT] if staple else [])
    leaf, ca, _ = pair(exts=exts)
    return leaf.public_bytes(DER), ca.public_bytes(DER)


def check(der, chain, ocsp=True, answer=("good", "good"), timeout=7.5, **kw):
    queries = []

    def fake_query(url, cid, tmo):
        queries.append((url, cid, tmo))
        return answer

    with mock.patch.object(cert_watch, "_handshake", return_value=(der, "TLSv1.3", MODERN, chain)), \
            mock.patch.object(cert_watch, "ocsp_query", fake_query):
        r = cert_watch.check_host("h.test", 443, 14, timeout, "", False, ocsp, **kw)
    return r, [(f["severity"], f["message"]) for f in r["findings"]], queries


def sev(f):
    return [s for s, _ in f if s != "x"]


class TestCheckHostOcsp(unittest.TestCase):
    def test_not_asked_means_no_status_no_query(self):
        der, ca = ocsp_leaf(staple=True)
        r, f, q = check(der, [der, ca], ocsp=False)
        self.assertEqual(q, [])
        self.assertNotIn("status", r["ocsp"])
        self.assertEqual(r["ocsp"]["urls"], ["http://ocsp.test/r"])
        self.assertIs(r["ocsp"]["must_staple"], True)
        self.assertEqual(r["ocsp"]["note"], "must-staple: clients refuse the certificate if the server does "
                                            "not staple a response")
        self.assertEqual(f, [])

    def test_no_note_without_must_staple(self):
        der, ca = ocsp_leaf()
        r, _, _ = check(der, [der, ca], ocsp=False)
        self.assertNotIn("note", r["ocsp"])
        self.assertIs(r["ocsp"]["must_staple"], False)

    def test_no_responder(self):
        der, _ = ocsp_leaf(url=False)
        r, f, q = check(der, None)
        self.assertEqual((r["ocsp"], f, q), ({"urls": [], "must_staple": False, "status": "no-responder"}, [], []))

    def test_no_responder_must_staple_is_medium(self):
        der, _ = ocsp_leaf(url=False, staple=True)
        r, f, q = check(der, None)
        self.assertEqual(r["ocsp"]["status"], "no-responder")
        self.assertEqual(f, [("MEDIUM", "Certificate is must-staple but names no OCSP responder.")])
        self.assertTrue(r["ok"])

    def test_chain_unavailable_is_skipped_with_a_low_finding(self):
        der, ca = ocsp_leaf()
        msg = ("OCSP not checked: the issuer certificate is needed and the server's chain is unavailable "
               "(needs Python 3.13+ and a server that sends its intermediate).")
        for chain in (None, [], [der]):
            with self.subTest(chain=chain):
                r, f, q = check(der, chain)
                self.assertEqual(r["ocsp"]["status"], "skipped")
                self.assertEqual(f, [("LOW", msg)])
                self.assertEqual(q, [])

    def test_good_asks_the_first_responder_with_the_issuers_cert_id_and_timeout(self):
        der, ca = ocsp_leaf()
        r, f, q = check(der, [der, ca])
        self.assertEqual(q, [("http://ocsp.test/r", cert_watch.ocsp_cert_id(der, ca), 7.5)])
        self.assertEqual((r["ocsp"]["status"], f), ("good", []))

    def test_revoked_is_high(self):
        der, ca = ocsp_leaf()
        r, f, _ = check(der, [der, ca], answer=("revoked", "revoked"))
        self.assertEqual(f, [("HIGH", "Certificate has been REVOKED (OCSP responder http://ocsp.test/r).")])
        self.assertFalse(r["ok"])
        self.assertEqual(r["ocsp"]["status"], "revoked")

    def test_unknown_is_medium(self):
        der, ca = ocsp_leaf()
        r, f, _ = check(der, [der, ca], answer=("unknown", "x"))
        self.assertEqual(f, [("MEDIUM", "OCSP responder http://ocsp.test/r does not know this certificate.")])
        self.assertTrue(r["ok"])
        self.assertEqual(r["ocsp"]["status"], "unknown")

    def test_error_is_low_with_the_detail(self):
        der, ca = ocsp_leaf()
        r, f, _ = check(der, [der, ca], answer=("error", "responder answered tryLater"))
        self.assertEqual(f, [("LOW", "OCSP check failed: responder answered tryLater.")])
        self.assertTrue(r["ok"])
        self.assertEqual(r["ocsp"]["status"], "error")


class TestCheckHostDefaults(unittest.TestCase):
    def test_defaults_scan_protocols_and_skip_ocsp(self):
        der, ca = ocsp_leaf()
        with mock.patch.object(cert_watch, "_handshake", return_value=(der, "TLSv1.3", MODERN, [der, ca])) as hs, \
                mock.patch.object(cert_watch, "probe_protocols", return_value={"TLSv1.2": True}) as probe, \
                mock.patch.object(cert_watch, "ocsp_query") as q:
            r = cert_watch.check_host("h.test", 443, 14)
        probe.assert_called_once_with("h.test", 443, 10, "")
        self.assertEqual(hs.call_args[0][3:], (10, ""))
        q.assert_not_called()
        self.assertIsNone(r["starttls"])
        self.assertNotIn("status", r["ocsp"])
        self.assertEqual(r["protocols"], {"TLSv1.2": True})

    def test_chain_certificate_expiring_exactly_at_the_warning_threshold_is_flagged(self):
        from test_contract import make_der
        leaf, _ = make_der()
        edge, _ = make_der(days=14, subject=(("CN", "Edge"),), sans=())
        past, _ = make_der(days=15, subject=(("CN", "Past"),), sans=())
        with mock.patch.object(cert_watch, "_handshake", return_value=(leaf, "TLSv1.3", MODERN, [leaf, edge, past])):
            r = cert_watch.check_host("h.test", 443, 14, 5, "", False)
        self.assertEqual([(f["severity"], f["message"]) for f in r["findings"]],
                         [("HIGH", "Chain certificate 'commonName=Edge' expires in 14 day(s).")])

    def test_standard_curves_are_not_flagged(self):
        from test_contract import make_der
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
            with self.subTest(curve=curve.name):
                der, _ = make_der(key=ec.generate_private_key(curve))
                with mock.patch.object(cert_watch, "_handshake", return_value=(der, "TLSv1.3", MODERN, None)):
                    r = cert_watch.check_host("h.test", 443, 14, 5, "", False)
                self.assertEqual(r["findings"], [])


class TestRenderOcspLine(unittest.TestCase):
    def render(self, **ocsp):
        r = {"host": "h.test", "port": 443, "ok": True, "findings": [], "ocsp": ocsp}
        return cert_watch.render_text([r]).split("\n")

    def test_no_line_without_url_or_must_staple(self):
        self.assertFalse([l for l in self.render(urls=[], must_staple=False, status="good") if "OCSP" in l])
        self.assertFalse([l for l in self.render(urls=[], must_staple=False) if "OCSP" in l])

    def test_url_only(self):
        self.assertIn("  OCSP: http://o.test/a", self.render(urls=["http://o.test/a", "http://o.test/b"],
                                                              must_staple=False))

    def test_must_staple_without_url(self):
        self.assertIn("  OCSP: no responder URL   must-staple", self.render(urls=[], must_staple=True))

    def test_url_staple_and_status(self):
        self.assertIn("  OCSP: http://o.test/a   must-staple   status: revoked",
                      self.render(urls=["http://o.test/a"], must_staple=True, status="revoked"))

    def test_url_and_status_no_staple(self):
        self.assertIn("  OCSP: http://o.test/a   status: good",
                      self.render(urls=["http://o.test/a"], must_staple=False, status="good"))

    def test_missing_keys_are_tolerated(self):
        self.assertIn("  OCSP: no responder URL   must-staple", self.render(must_staple=True))
        self.assertIn("  OCSP: http://o.test/a", self.render(urls=["http://o.test/a"]))


class FakeFile:
    def __init__(self, *lines):
        self.lines = list(lines)
        self.sizes = []

    def readline(self, n=-1):
        self.sizes.append(n)
        return self.lines.pop(0) if self.lines else b""


class FakeSock:
    def __init__(self, *lines, recv=b"S"):
        self.f = FakeFile(*lines)
        self.sent = []
        self.recv_sizes = []
        self._recv = recv

    def makefile(self, mode):
        assert mode == "rb"
        return self.f

    def sendall(self, b):
        self.sent.append(b)

    def recv(self, n):
        self.recv_sizes.append(n)
        return self._recv


class TestStartTlsReads(unittest.TestCase):
    def test_reply_strips_line_ends_and_keeps_every_line(self):
        f = FakeFile(b"250-first\r\n", b"250-\r\n", b"250 last\r\n")
        self.assertEqual(cert_watch._reply(f), ("250", ["250-first", "250-", "250 last"]))
        self.assertEqual(f.sizes, [4096, 4096, 4096])

    def test_reply_decodes_bad_utf8_instead_of_crashing(self):
        self.assertEqual(cert_watch._reply(FakeFile(b"250 caf\xe9\r\n")), ("250", ["250 caf\ufffd"]))
        self.assertEqual(cert_watch._reply(FakeFile(b"250 \xc3\xa9\r\n")), ("250", ["250 \u00e9"]))

    def test_reply_short_lines_are_complete(self):
        self.assertEqual(cert_watch._reply(FakeFile(b"220\r\n")), ("220", ["220"]))
        self.assertEqual(cert_watch._reply(FakeFile(b"2201\r\n")), ("220", ["2201"]))

    def test_reply_dash_ends_nothing(self):
        self.assertEqual(cert_watch._reply(FakeFile(b"250-\r\n", b"250 ok\r\n")), ("250", ["250-", "250 ok"]))

    def test_imap_reads_are_bounded_and_refusal_text_is_decoded(self):
        s = FakeSock(b"* OK hi\r\n", b"* CAPABILITY X\r\n", b"a1 OK go\r\n")
        cert_watch._negotiate_starttls(s, "imap")
        self.assertEqual(s.sent, [b"a1 STARTTLS\r\n"])
        self.assertEqual(s.f.sizes, [4096, 4096, 4096])
        s = FakeSock(b"* OK hi\r\n", b"a1 NO caf\xe9 not now\r\n")
        with self.assertRaises(cert_watch.StartTLSError) as cm:
            cert_watch._negotiate_starttls(s, "imap")
        self.assertEqual(str(cm.exception), "IMAP STARTTLS refused: a1 NO caf\ufffd not now")

    def test_pop3_reads_are_bounded(self):
        s = FakeSock(b"+OK hi\r\n", b"+OK go\r\n")
        cert_watch._negotiate_starttls(s, "pop3")
        self.assertEqual((s.sent, s.f.sizes), ([b"STLS\r\n"], [4096, 4096]))

    def test_postgres_asks_for_one_byte(self):
        s = FakeSock()
        cert_watch._negotiate_starttls(s, "postgres")
        self.assertEqual(s.sent, [b"\x00\x00\x00\x08\x04\xd2\x16\x2f"])
        self.assertEqual(s.recv_sizes, [1])


class TestConnectDefaults(unittest.TestCase):
    def test_connect_without_starttls_just_connects(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        s = cert_watch._connect("127.0.0.1", srv.getsockname()[1], 5)
        s.close()

    def test_handshake_passes_host_and_default_starttls_to_connect(self):
        class Boom(Exception):
            pass
        with mock.patch.object(cert_watch, "_connect", side_effect=Boom) as c:
            with self.assertRaises(Boom):
                cert_watch._handshake("h.test", 443, None, 3)
        c.assert_called_once_with("h.test", 443, 3, "")

    def test_chain_ders_converts_objects_and_keeps_bytes(self):
        class Cert:
            def public_bytes(self, enc):
                return b"obj-" + repr(enc == ssl._ssl.ENCODING_DER).encode()

        sock = types.SimpleNamespace(get_unverified_chain=lambda: [b"raw", Cert()])
        if hasattr(getattr(ssl, "_ssl", None), "ENCODING_DER"):
            self.assertEqual(cert_watch._chain_ders(sock), [b"raw", b"obj-True"])
        else:  # older ssl: converting a certificate object fails, and the chain is reported unavailable
            self.assertIsNone(cert_watch._chain_ders(sock))
        self.assertEqual(cert_watch._chain_ders(types.SimpleNamespace(get_unverified_chain=lambda: [b"r"])), [b"r"])
        self.assertIsNone(cert_watch._chain_ders(types.SimpleNamespace()))


VNAME = {ssl.TLSVersion.TLSv1: "TLSv1", ssl.TLSVersion.TLSv1_1: "TLSv1.1", ssl.TLSVersion.TLSv1_2: "TLSv1.2",
         ssl.TLSVersion.TLSv1_3: "TLSv1.3"}


class TestProbeProtocols(unittest.TestCase):
    def probe(self, handshake, has13=True, **kw):
        calls = []

        def hs(host, port, ctx, timeout, starttls=""):
            calls.append((host, port, ctx.maximum_version, timeout, starttls))
            return handshake(ctx.maximum_version)

        saved = getattr(ssl, "HAS_TLSv1_3", "absent")
        try:
            if has13 == "absent":
                delattr(ssl, "HAS_TLSv1_3")
            else:
                ssl.HAS_TLSv1_3 = has13
            with mock.patch.object(cert_watch, "_handshake", hs):
                out = cert_watch.probe_protocols("h.test", 443, 3, **kw)
        finally:
            if saved != "absent":
                ssl.HAS_TLSv1_3 = saved
        return out, calls

    def test_each_version_is_tried_alone_and_accepted_when_negotiated(self):
        out, calls = self.probe(lambda v: (None, VNAME[v], None, None))
        self.assertEqual(out, {"TLSv1": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True})
        self.assertEqual([c[2] for c in calls], list(VNAME))
        self.assertEqual({c[:2] + c[3:] for c in calls}, {("h.test", 443, 3, "")})

    def test_starttls_is_passed_through(self):
        _, calls = self.probe(lambda v: (None, VNAME[v], None, None), starttls="smtp")
        self.assertEqual({c[4] for c in calls}, {"smtp"})

    def test_tls13_without_client_support_is_untested_and_not_attempted(self):
        out, calls = self.probe(lambda v: (None, VNAME[v], None, None), has13=False)
        self.assertEqual(out, {"TLSv1": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": None})
        self.assertNotIn(ssl.TLSVersion.TLSv1_3, [c[2] for c in calls])

    def test_a_client_without_the_flag_counts_as_no_tls13(self):
        out, _ = self.probe(lambda v: (None, VNAME[v], None, None), has13="absent")
        self.assertIsNone(out["TLSv1.3"])

    def test_other_versions_unaffected_by_the_tls13_check(self):
        out, _ = self.probe(lambda v: (None, "TLSv1.2", None, None))
        self.assertEqual(out, {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": False})

    def test_failures_map_to_false_or_untested(self):
        def hs(v):
            name = VNAME[v]
            if name == "TLSv1":
                raise ssl.SSLError("no protocols available")
            if name == "TLSv1.1":
                raise ssl.SSLError("NO CIPHERS AVAILABLE")
            if name == "TLSv1.2":
                raise ssl.SSLError("handshake failure")
            raise cert_watch.StartTLSError("refused")
        out, _ = self.probe(hs)
        self.assertEqual(out, {"TLSv1": None, "TLSv1.1": None, "TLSv1.2": False, "TLSv1.3": False})

    def test_os_errors_are_refusals(self):
        out, _ = self.probe(lambda v: (_ for _ in ()).throw(ConnectionResetError("reset")))
        self.assertEqual(set(out.values()), {False})
        self.assertEqual(len(out), 4)

    def test_a_version_this_openssl_cannot_set_is_untested_and_the_rest_still_run(self):
        class Ctx:
            _min = _max = None
            protocol = 0

            @property
            def minimum_version(self):
                return self._min

            @minimum_version.setter
            def minimum_version(self, v):
                if v == ssl.TLSVersion.TLSv1_1:
                    raise ValueError("unsupported")
                self._min = v

            @property
            def maximum_version(self):
                return self._max

            @maximum_version.setter
            def maximum_version(self, v):
                self._max = v

        with mock.patch.object(cert_watch, "_permissive_context", Ctx):
            out, calls = self.probe(lambda v: (None, VNAME[v], None, None))
        self.assertEqual(out, {"TLSv1": True, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True})
        self.assertEqual(len(calls), 3)

    def test_permissive_context_accepts_anything(self):
        ctx = cert_watch._permissive_context()
        self.assertEqual(ctx.protocol, ssl.PROTOCOL_TLS_CLIENT)
        self.assertIs(ctx.check_hostname, False)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)


class TestSmallHelpers(unittest.TestCase):
    def test_oid_to_str(self):
        self.assertEqual(cert_watch._oid_to_str(bytes.fromhex("2a864886f70d010101")), "1.2.840.113549.1.1.1")
        self.assertEqual(cert_watch._oid_to_str(bytes.fromhex("551d11")), "2.5.29.17")
        self.assertEqual(cert_watch._oid_to_str(bytes.fromhex("6086480186f84201")), "2.16.840.1.113730.1")

    def test_der_read_long_form(self):
        self.assertEqual(cert_watch._der_read(b"\x30\x82\x01\x02" + b"x" * 258, 0), (0x30, 4, 262))
        self.assertEqual(cert_watch._der_read(b"\x30\x81\x80" + b"x" * 128, 0), (0x30, 3, 131))
        self.assertEqual(cert_watch._der_read(b"\x04\x03abc", 0), (4, 2, 5))

    def test_signature_oid_requires_an_oid(self):
        from test_contract import make_der
        der, _ = make_der()
        self.assertEqual(cert_watch.signature_oid(der), "1.2.840.113549.1.1.11")
        # swap the algorithm OID's tag (0x06) for an OCTET STRING: not an OID -> None
        raw = bytes.fromhex("2a864886f70d01010b")
        i = der.rindex(b"\x06\x09" + raw)
        self.assertIsNone(cert_watch.signature_oid(der[:i] + b"\x04" + der[i + 1:]))

    def test_public_key_info_unknown_algorithm_is_reported_by_oid(self):
        from test_contract import make_der
        der, _ = make_der(key=rsa.generate_private_key(65537, 2048))
        rsa_oid = bytes.fromhex("2a864886f70d010101")
        j = der.index(b"\x06\x09" + rsa_oid)
        odd = der[:j + 2] + bytes.fromhex("2a864886f70d010102") + der[j + 2 + 9:]  # 1.2.840.113549.1.1.2
        self.assertEqual(cert_watch.public_key_info(odd), ("1.2.840.113549.1.1.2", None, None))
        self.assertEqual(cert_watch.public_key_info(der)[:2], ("RSA", 2048))

    def test_extension_value_is_the_last_part(self):
        # a critical extension has [oid, BOOLEAN, OCTET STRING]; the value must be the OCTET STRING
        from test_contract import make_der
        der, cert = make_der()
        ext = cert_watch.cert_extensions(der)
        self.assertEqual(ext["2.5.29.17"], cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.public_bytes())

    def test_decode_der_cert_uses_a_pem_temp_file_and_survives_a_missing_decoder(self):
        from test_contract import make_der
        der, _ = make_der()
        seen = []
        real = tempfile.mkstemp

        def spy(*a, **k):
            seen.append(k)
            return real(*a, **k)
        with mock.patch.object(tempfile, "mkstemp", spy):
            self.assertIn("subject", cert_watch.decode_der_cert(der))
        self.assertEqual(seen, [{"suffix": ".pem"}])
        with mock.patch.object(ssl, "_ssl", types.SimpleNamespace()):
            self.assertEqual(cert_watch.decode_der_cert(der), {})
        with mock.patch.object(ssl, "_ssl", None):
            self.assertEqual(cert_watch.decode_der_cert(der), {})

    def test_target_parsing_edges(self):
        self.assertEqual(cert_watch.parse_target("https://hostX/"), ("hostX", 443, ""))
        self.assertEqual(cert_watch.parse_target("https://host.test///"), ("host.test", 443, ""))
        self.assertEqual(cert_watch.parse_host("[::1]x]"), ("::1", 443))
        self.assertEqual(cert_watch.parse_host("[::1]:99"), ("::1", 99))


class TestMain(unittest.TestCase):
    def run_main(self, *argv, results=None, env=None):
        out, err = io.StringIO(), io.StringIO()
        calls = []

        def fake_check(*a, **k):
            calls.append((a, k))
            return (results or [{"host": a[0], "port": a[1], "ok": True, "findings": []}])[0]

        code = None
        with mock.patch.object(cert_watch, "check_host", fake_check), \
                mock.patch.dict(os.environ, env or {"COLUMNS": "100"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cert_watch.main(list(argv))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue(), calls

    def test_defaults_reach_check_host(self):
        code, _, _, calls = self.run_main("a.test")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [(("a.test", 443, 14, 10, "", True, False), {})])

    def test_flags_reach_check_host(self):
        _, _, _, calls = self.run_main("a.test:8443", "--warn-days", "30", "--timeout", "2.5",
                                       "--no-protocol-scan", "--ocsp", "--starttls", "imap")
        self.assertEqual(calls, [(("a.test", 8443, 30, 2.5, "imap", False, True), {})])

    def test_starttls_choices(self):
        for choice, want in (("smtp", "smtp"), ("imap", "imap"), ("pop3", "pop3"), ("ftp", "ftp"),
                             ("postgres", "postgres"), ("none", "")):
            with self.subTest(choice=choice):
                _, _, _, calls = self.run_main("a.test", "--starttls", choice)
                self.assertEqual(calls[0][0][4], want)
        code, _, err, calls = self.run_main("a.test", "--starttls", "gopher")
        self.assertEqual((code, calls), (2, []))
        self.assertIn("invalid choice: 'gopher'", err)

    def test_fail_on_choices(self):
        code, _, err, _ = self.run_main("a.test", "--fail-on", "critical")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice: 'critical'", err)

    def test_no_hosts_message(self):
        code, _, err, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("error: no hosts given (pass as arguments or via --file)", err)

    def test_file_targets_and_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("a.test # one # two\n\n   # only a comment\nb.test:8443\n")
        self.addCleanup(os.unlink, f.name)
        _, _, _, calls = self.run_main("--file", f.name)
        self.assertEqual([c[0][:2] for c in calls], [("a.test", 443), ("b.test", 8443)])
        code, _, err, _ = self.run_main("--file", f.name + ".missing")
        self.assertEqual(code, 2)
        self.assertIn("can't read --file", err)

    def test_exit_gate_per_level(self):
        def res(severity):
            return [{"host": "a.test", "port": 443, "ok": severity != "HIGH",
                     "findings": [{"severity": severity, "message": "m"}] if severity else []}]
        table = {"high": {"HIGH": 1, "MEDIUM": 0, "LOW": 0, None: 0},
                 "medium": {"HIGH": 1, "MEDIUM": 1, "LOW": 0, None: 0},
                 "low": {"HIGH": 1, "MEDIUM": 1, "LOW": 1, None: 0},
                 "never": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, None: 0}}
        for level, row in table.items():
            for severity, want in row.items():
                with self.subTest(level=level, severity=severity):
                    code, _, _, _ = self.run_main("a.test", "--fail-on", level, results=res(severity))
                    self.assertEqual(code, want)
        code, _, _, _ = self.run_main("a.test", results=res("HIGH"))
        self.assertEqual(code, 1)  # the default is high

    def test_json_output(self):
        code, out, _, _ = self.run_main("a.test", "--json")
        self.assertIn('"host": "a.test"', out)
        self.assertIn('\n    "port": 443', out)  # indent=2 inside a list

    def test_help_text(self):
        code, out, _, _ = self.run_main("--help")
        self.assertEqual(code, 0)
        flat = " ".join(out.split())
        self.assertTrue(out.startswith("usage: tls-cert-watchdog"), out[:60])
        for line in cert_watch.__doc__.strip().splitlines():
            if line.strip():
                self.assertIn(line.rstrip(), out)           # RawDescriptionHelpFormatter keeps the layout
        for text in (
                "[scheme://]host[:port] to check (schemes: smtp, submission, imap, pop3, ftp, postgres, https)",
                "file with one [scheme://]host[:port] per line",
                "force a STARTTLS protocol for every target (default: from the scheme or well-known port)",
                "HIGH-severity threshold for days until expiry (default 14)",
                "machine-readable JSON output",
                "per-connection timeout in seconds (default 10)",
                "don't try each TLS version separately (one handshake per host instead of five)",
                "lowest severity that makes the exit code 1 (default: high)",
                "ask the certificate's OCSP responder whether it is revoked (needs the server's chain: Python 3.13+)",
                "{smtp,imap,pop3,ftp,postgres,none}", "{high,medium,low,never}"):
            self.assertIn(text, flat)


if __name__ == "__main__":
    unittest.main()
