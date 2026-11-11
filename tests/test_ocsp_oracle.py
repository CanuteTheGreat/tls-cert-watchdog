"""OCSP encoding and parsing pinned against the `cryptography` library as an independent oracle
(found as mutation-testing survivors of 1.3.0): the CertID and the request the tool builds must be
byte-identical to what `cryptography.x509.ocsp` builds, and every responder answer the library can
produce must be read the way the library says it is. Long (>127 byte) DER lengths, responder
statuses, the wire request (method, headers, body) and error wording are covered."""
import datetime
import http.server
import os
import sys
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cert_watch  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
DER = serialization.Encoding.DER


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_cn, issuer_cert, issuer_key, key, exts=(), ca=False, serial=None):
    b = (x509.CertificateBuilder().subject_name(_name(subject_cn))
         .issuer_name(issuer_cert.subject if issuer_cert is not None else _name(subject_cn))
         .public_key(key.public_key()).serial_number(serial or x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=30)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    for e in exts:
        b = b.add_extension(e, critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def pair(issuer_key=None, cert_key=None, exts=(), serial=None, issuer_cn="oracle CA"):
    ikey = issuer_key or rsa.generate_private_key(65537, 2048)
    ca = issue(issuer_cn, None, ikey, ikey, ca=True)
    ckey = cert_key or ec.generate_private_key(ec.SECP256R1())
    leaf = issue("leaf.test", ca, ikey, ckey, exts, serial=serial)
    return leaf, ca, ikey


def aia(*descs):
    return x509.AuthorityInformationAccess([
        x509.AccessDescription(oid, x509.UniformResourceIdentifier(url)) for oid, url in descs])


OCSP_OID = AuthorityInformationAccessOID.OCSP
CA_ISSUERS = AuthorityInformationAccessOID.CA_ISSUERS


def respond(leaf, ca, ikey, status, reason=None, other=None):
    """A signed OCSP response of `status` for `leaf` (DER)."""
    now = NOW
    b = ocsp.OCSPResponseBuilder().add_response(
        cert=other or leaf, issuer=ca, algorithm=hashes.SHA1(), cert_status=status,
        this_update=now, next_update=now + datetime.timedelta(days=1),
        revocation_time=now if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=reason if status == ocsp.OCSPCertStatus.REVOKED else None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca)
    return b.sign(ikey, hashes.SHA256()).public_bytes(DER)


def lib_request(leaf, ca):
    return ocsp.OCSPRequestBuilder().add_certificate(leaf, ca, hashes.SHA1()).build().public_bytes(DER)


class TestCertIdAndRequest(unittest.TestCase):
    def test_request_is_byte_identical_to_the_library_for_many_certs(self):
        # random serials / keys cover short and long (>127 byte, 2-byte length) CertID and request lengths
        for ikey, serial in ((None, None), (None, 1), (None, 127), (None, 128), (None, 2 ** 159 - 1),
                             (rsa.generate_private_key(65537, 4096), None),
                             (ec.generate_private_key(ec.SECP384R1()), None)):
            with self.subTest(serial=serial, key=type(ikey).__name__):
                leaf, ca, _ = pair(issuer_key=ikey, serial=serial)
                cid = cert_watch.ocsp_cert_id(leaf.public_bytes(DER), ca.public_bytes(DER))
                self.assertEqual(cert_watch.build_ocsp_request(cid), lib_request(leaf, ca))

    def test_cert_id_survives_unusual_issuer_names_and_extensions(self):
        ikey = rsa.generate_private_key(65537, 2048)
        leaf, ca, _ = pair(issuer_key=ikey, issuer_cn="x" * 60,
                           exts=[aia((OCSP_OID, "http://o.test/")),
                                 x509.TLSFeature([x509.TLSFeatureType.status_request])])
        cid = cert_watch.ocsp_cert_id(leaf.public_bytes(DER), ca.public_bytes(DER))
        self.assertEqual(cert_watch.build_ocsp_request(cid), lib_request(leaf, ca))

    def test_cert_id_is_sha1_of_issuer_name_and_key_then_serial(self):
        leaf, ca, _ = pair(serial=0x1234)
        cid = cert_watch.ocsp_cert_id(leaf.public_bytes(DER), ca.public_bytes(DER))
        self.assertEqual(cid[0], 0x30)
        self.assertTrue(cid.endswith(b"\x02\x02\x12\x34"))
        self.assertIn(bytes.fromhex("06052b0e03021a0500"), cid)

    def test_request_wraps_the_cert_id_four_sequences_deep(self):
        for n in (3, 120, 125, 126, 127, 128, 300):
            with self.subTest(n=n):
                cid = b"\x30" + (bytes([n]) if n < 128 else b"\x82" + n.to_bytes(2, "big")) + b"\x05" * n
                req = cert_watch.build_ocsp_request(cid)
                i = 0
                for _ in range(4):
                    tag, s, e = cert_watch._der_read(req, i)
                    self.assertEqual(tag, 0x30)
                    self.assertEqual(e, len(req))
                    i = s
                self.assertEqual(req[i:], cid)
                if n >= 253:
                    self.assertEqual(req[1], 0x82)  # a two-byte length, not the short form


class TestParseResponse(unittest.TestCase):
    def setUp(self):
        self.leaf, self.ca, self.ikey = pair()
        self.cid = cert_watch.ocsp_cert_id(self.leaf.public_bytes(DER), self.ca.public_bytes(DER))

    def test_good(self):
        r = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.GOOD)
        self.assertEqual(cert_watch.parse_ocsp_response(r, self.cid), ("good", "good"))

    def test_revoked_with_and_without_reason(self):
        for reason in (None, x509.ReasonFlags.key_compromise):
            r = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.REVOKED, reason)
            self.assertEqual(cert_watch.parse_ocsp_response(r, self.cid), ("revoked", "revoked"))

    def test_unknown(self):
        r = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.UNKNOWN)
        self.assertEqual(cert_watch.parse_ocsp_response(r, self.cid),
                         ("unknown", "responder does not know this certificate"))

    def test_response_for_another_certificate(self):
        other, _, _ = pair(issuer_key=self.ikey)
        r = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.GOOD, other=other)
        self.assertEqual(cert_watch.parse_ocsp_response(r, self.cid),
                         ("error", "response is for a different certificate"))

    def test_responder_error_statuses(self):
        names = {ocsp.OCSPResponseStatus.MALFORMED_REQUEST: "malformedRequest",
                 ocsp.OCSPResponseStatus.INTERNAL_ERROR: "internalError",
                 ocsp.OCSPResponseStatus.TRY_LATER: "tryLater",
                 ocsp.OCSPResponseStatus.SIG_REQUIRED: "sigRequired",
                 ocsp.OCSPResponseStatus.UNAUTHORIZED: "unauthorized"}
        for status, name in names.items():
            r = ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(DER)
            self.assertEqual(cert_watch.parse_ocsp_response(r, self.cid),
                             ("error", "responder answered " + name))

    def test_unlisted_status_code_is_reported_by_number(self):
        # OCSPResponse { responseStatus ENUMERATED 4 }
        self.assertEqual(cert_watch.parse_ocsp_response(b"\x30\x03\x0a\x01\x04", self.cid),
                         ("error", "responder answered status 4"))

    def test_garbage_and_truncated(self):
        good = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.GOOD)
        for data in (b"", b"\x30", b"not ocsp at all", good[:20], good[:60], b"\x30\x03\x0a\x01\x00"):
            with self.subTest(data=data[:10]):
                self.assertEqual(cert_watch.parse_ocsp_response(data, self.cid),
                                 ("error", "unparseable OCSP response"))

    def test_responder_id_by_name_and_by_key(self):
        for enc in (ocsp.OCSPResponderEncoding.HASH, ocsp.OCSPResponderEncoding.NAME):
            b = ocsp.OCSPResponseBuilder().add_response(
                cert=self.leaf, issuer=self.ca, algorithm=hashes.SHA1(),
                cert_status=ocsp.OCSPCertStatus.REVOKED, this_update=NOW,
                next_update=NOW + datetime.timedelta(days=1), revocation_time=NOW, revocation_reason=None)
            r = b.responder_id(enc, self.ca).sign(self.ikey, hashes.SHA256()).public_bytes(DER)
            self.assertEqual(cert_watch.parse_ocsp_response(r, self.cid), ("revoked", "revoked"))


class TestOcspInfo(unittest.TestCase):
    def info(self, *exts):
        leaf, _, _ = pair(exts=exts)
        return cert_watch.ocsp_info(leaf.public_bytes(DER))

    def test_plain(self):
        self.assertEqual(self.info(), ([], False))

    def test_url_and_staple(self):
        self.assertEqual(self.info(aia((OCSP_OID, "http://ocsp.example/x")),
                                   x509.TLSFeature([x509.TLSFeatureType.status_request])),
                         (["http://ocsp.example/x"], True))

    def test_multiple_urls_only_ocsp_entries_in_order(self):
        got = self.info(aia((CA_ISSUERS, "http://ca.example/ca.crt"), (OCSP_OID, "http://a.example/"),
                            (OCSP_OID, "http://b.example/")))
        self.assertEqual(got, (["http://a.example/", "http://b.example/"], False))

    def test_ca_issuers_alone_is_no_responder(self):
        self.assertEqual(self.info(aia((CA_ISSUERS, "http://ca.example/ca.crt"))), ([], False))

    def test_status_request_v2_alone_is_not_must_staple(self):
        self.assertEqual(self.info(x509.TLSFeature([x509.TLSFeatureType.status_request_v2])), ([], False))

    def test_both_features_is_must_staple(self):
        self.assertEqual(self.info(x509.TLSFeature([x509.TLSFeatureType.status_request_v2,
                                                    x509.TLSFeatureType.status_request]))[1], True)

    def test_other_extensions_do_not_confuse_it(self):
        self.assertEqual(self.info(x509.SubjectAlternativeName([x509.DNSName("a.test")]),
                                   aia((OCSP_OID, "http://o.test/")),
                                   x509.TLSFeature([x509.TLSFeatureType.status_request])),
                         (["http://o.test/"], True))

    def test_cert_extensions_maps_oid_to_value(self):
        leaf, _, _ = pair(exts=[aia((OCSP_OID, "http://o.test/"))])
        ext = cert_watch.cert_extensions(leaf.public_bytes(DER))
        self.assertIn(cert_watch.OID_AIA, ext)
        self.assertIn(b"http://o.test/", ext[cert_watch.OID_AIA])
        self.assertEqual(cert_watch.cert_extensions(b"junk"), {})
        self.assertEqual(cert_watch.cert_extensions(b""), {})


class Responder(http.server.BaseHTTPRequestHandler):
    seen = []
    reply = b""

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        Responder.seen.append((self.command, self.headers.get("Content-Type"), self.headers.get("Accept"),
                               self.rfile.read(n)))
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(Responder.reply)))
        self.end_headers()
        self.wfile.write(Responder.reply)

    def log_message(self, format, *args):
        pass


class TestOcspQuery(unittest.TestCase):
    def setUp(self):
        self.leaf, self.ca, self.ikey = pair()
        self.cid = cert_watch.ocsp_cert_id(self.leaf.public_bytes(DER), self.ca.public_bytes(DER))
        Responder.seen = []
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Responder)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = "http://127.0.0.1:%d/ocsp" % self.srv.server_address[1]

    def test_posts_the_request_with_ocsp_headers_and_reads_the_verdict(self):
        Responder.reply = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(cert_watch.ocsp_query(self.url, self.cid, 5), ("revoked", "revoked"))
        self.assertEqual(Responder.seen, [("POST", "application/ocsp-request", "application/ocsp-response",
                                           lib_request(self.leaf, self.ca))])

    def test_scheme_check_is_case_insensitive_and_http_only(self):
        Responder.reply = respond(self.leaf, self.ca, self.ikey, ocsp.OCSPCertStatus.GOOD)
        self.assertEqual(cert_watch.ocsp_query(self.url.replace("http", "HTTP", 1), self.cid, 5), ("good", "good"))
        for bad in ("ftp://x/", "file:///etc/passwd", "ldap://x", "/ocsp", ""):
            self.assertEqual(cert_watch.ocsp_query(bad, self.cid, 5), ("error", "unsupported responder URL scheme"))
        self.assertEqual(len(Responder.seen), 1)

    def test_unreachable_names_the_url(self):
        self.srv.shutdown()
        self.srv.server_close()
        state, detail = cert_watch.ocsp_query(self.url, self.cid, 2)
        self.assertEqual(state, "error")
        self.assertTrue(detail.startswith("responder %s unreachable: " % self.url), detail)

    def test_garbage_body_is_unparseable(self):
        Responder.reply = b"\x30\x00"
        self.assertEqual(cert_watch.ocsp_query(self.url, self.cid, 5), ("error", "unparseable OCSP response"))


if __name__ == "__main__":
    unittest.main()
