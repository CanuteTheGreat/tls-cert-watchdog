"""OCSP / must-staple: parsed from the certificate, and the revocation verdict compared with a real
`openssl ocsp` responder (server) and `openssl ocsp` client (oracle)."""
import os
import socket
import subprocess
import sys
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cert_watch  # noqa: E402
from test_cert_watch import Base, TLSServer  # noqa: E402

import ssl  # noqa: E402
HAS_CHAIN = hasattr(ssl.SSLSocket, "get_unverified_chain")


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def aia(url):
    return x509.AuthorityInformationAccess(
        [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(url))])


class OcspBase(Base):
    def make(self, state, with_url=True, must_staple=False):
        """A leaf (served with the CA appended) and an `openssl ocsp` responder that says `state`."""
        self.port = free_port()
        self.url = "http://127.0.0.1:%d/" % self.port
        exts = ([aia(self.url)] if with_url else []) + (
            [x509.TLSFeature([x509.TLSFeatureType.status_request])] if must_staple else [])
        self.cert, self.key = self.pki.leaf("ocsp-" + state, extensions=exts)
        leaf = x509.load_pem_x509_certificate(_read(self.cert))
        with open(self.cert, "ab") as f:  # the server sends leaf + issuer, so the tool can build the CertID
            f.write(self.pki.ca_cert.public_bytes(serialization.Encoding.PEM))
        serial = "%X" % leaf.serial_number
        serial = serial.rjust(len(serial) + len(serial) % 2, "0")
        expiry = "380101000000Z"
        rows = {"good": "V\t%s\t\t%s\tunknown\t/CN=localhost\n" % (expiry, serial),
                "revoked": "R\t%s\t261101000000Z\t%s\tunknown\t/CN=localhost\n" % (expiry, serial),
                "unknown": ""}
        idx = os.path.join(self.tmp, "index.txt")
        with open(idx, "w") as f:
            f.write(rows[state])
        cakey = os.path.join(self.tmp, "ca.key")
        with open(cakey, "wb") as f:
            f.write(self.pki.ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                  serialization.NoEncryption()))
        self.responder = subprocess.Popen(
            ["openssl", "ocsp", "-index", idx, "-CA", self.pki.ca_file, "-rsigner", self.pki.ca_file,
             "-rkey", cakey, "-port", str(self.port)], stdout=open(os.path.join(self.tmp, "resp.log"), "wb"), stderr=subprocess.STDOUT)
        self.addCleanup(self.responder.wait)
        self.addCleanup(self.responder.kill)
        log = os.path.join(self.tmp, "resp.log")
        for _ in range(100):  # do not probe by connecting: the single-threaded responder would block on the probe
            if "waiting for OCSP client connections" in _read(log).decode("utf-8", "replace"):
                break
            time.sleep(0.1)
        self.der = [x509.load_pem_x509_certificate(_read(self.cert)).public_bytes(serialization.Encoding.DER),
                    self.pki.ca_cert.public_bytes(serialization.Encoding.DER)]

    def oracle(self):
        """What a real OCSP client (openssl) concludes about the same certificate."""
        p = subprocess.run(["openssl", "ocsp", "-issuer", self.pki.ca_file, "-cert", self.cert, "-url", self.url,
                            "-noverify", "-no_nonce"], capture_output=True, text=True, timeout=30)
        line = [l for l in p.stdout.splitlines() if ": " in l and l.split(":")[0].endswith(".crt")][0]
        return line.split(": ", 1)[1].split()[0]


class TestOcspVerdicts(OcspBase):
    def test_tool_matches_openssl_ocsp_client(self):
        for state in ("good", "revoked", "unknown"):
            with self.subTest(state=state):
                self.make(state)
                self.assertEqual(self.oracle(), state)
                cid = cert_watch.ocsp_cert_id(self.der[0], self.der[1])
                self.assertEqual(cert_watch.ocsp_query(self.url, cid, 10), (state, state if state != "unknown"
                                 else "responder does not know this certificate"))

    def test_cli_revoked_is_high_and_fails(self):
        self.make("revoked")
        srv = TLSServer(self.cert, self.key)
        self.servers.append(srv)
        code, r, msgs = self.check(srv.port, "--ocsp", "--no-protocol-scan")
        self.assertEqual(r["ocsp"]["urls"], [self.url])
        if HAS_CHAIN:
            self.assertEqual(r["ocsp"]["status"], "revoked")
            self.assertIn("HIGH Certificate has been REVOKED", msgs)
            self.assertEqual(code, 1)
        else:  # Python < 3.13 cannot read the chain: say so instead of guessing
            self.assertEqual(r["ocsp"]["status"], "skipped")
            self.assertIn("LOW OCSP not checked", msgs)

    def test_cli_good_is_clean(self):
        self.make("good")
        srv = TLSServer(self.cert, self.key)
        self.servers.append(srv)
        code, r, msgs = self.check(srv.port, "--ocsp", "--no-protocol-scan")
        self.assertEqual(r["ocsp"]["status"], "good" if HAS_CHAIN else "skipped")
        self.assertNotIn("REVOKED", msgs)
        self.assertEqual(code, 0 if HAS_CHAIN else 0)

    def test_without_flag_nothing_is_sent(self):
        self.make("revoked")
        srv = TLSServer(self.cert, self.key)
        self.servers.append(srv)
        code, r, msgs = self.check(srv.port, "--no-protocol-scan")
        self.assertNotIn("status", r["ocsp"])
        self.assertNotIn("REVOKED", msgs)
        self.assertEqual(code, 0)

    def test_dead_responder_is_low_not_a_crash(self):
        self.make("good")
        self.responder.kill()
        self.responder.wait()
        cid = cert_watch.ocsp_cert_id(self.der[0], self.der[1])
        state, detail = cert_watch.ocsp_query(self.url, cid, 2)
        self.assertEqual(state, "error")
        self.assertIn("unreachable", detail)

    def test_file_url_is_refused(self):
        self.assertEqual(cert_watch.ocsp_query("file:///etc/passwd", b"x", 2),
                         ("error", "unsupported responder URL scheme"))


class TestParsing(OcspBase):
    def test_url_and_must_staple_read_from_certificate(self):
        self.make("good", must_staple=True)
        self.assertEqual(cert_watch.ocsp_info(self.der[0]), ([self.url], True))
        self.assertEqual(cert_watch.ocsp_info(self.der[1]), ([], False))  # the CA cert has neither

    def test_plain_certificate(self):
        self.make("good", with_url=False)
        self.assertEqual(cert_watch.ocsp_info(self.der[0]), ([], False))

    def test_must_staple_without_responder_is_medium(self):
        self.make("good", with_url=False, must_staple=True)
        srv = TLSServer(self.cert, self.key)
        self.servers.append(srv)
        code, r, msgs = self.check(srv.port, "--ocsp", "--no-protocol-scan")
        self.assertTrue(r["ocsp"]["must_staple"])
        self.assertIn("MEDIUM Certificate is must-staple but names no OCSP responder", msgs)
        self.assertEqual(code, 0)

    def test_text_report_shows_ocsp_line(self):
        self.make("good", must_staple=True)
        srv = TLSServer(self.cert, self.key)
        self.servers.append(srv)
        p = self.run_tool("--no-protocol-scan", "localhost:%d" % srv.port)
        self.assertIn("OCSP: %s   must-staple" % self.url, p.stdout)

    def test_garbage_is_not_a_crash(self):
        self.assertEqual(cert_watch.cert_extensions(b"\x30\x03\x01"), {})
        self.assertEqual(cert_watch.parse_ocsp_response(b"\x00", b"x"), ("error", "unparseable OCSP response"))
        self.assertEqual(cert_watch.parse_ocsp_response(bytes.fromhex("30030a0101"), b"x"),
                         ("error", "responder answered malformedRequest"))


if __name__ == "__main__":
    unittest.main()
