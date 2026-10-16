"""End-to-end tests for cert_watch.py against real local TLS servers.

Each test starts a real TLS listener (Python's ssl module = OpenSSL) serving
a certificate built for the scenario (expired, expiring, self-signed, wrong
hostname, CN-only, SHA-1 signed, TLS 1.0 only, ...) and runs the tool as a
subprocess, trusting the test CA through SSL_CERT_FILE exactly as a system
CA bundle would be trusted. Certificates are generated with `cryptography`
(test-only dependency, installed by ci/setup.sh); the tool itself stays
stdlib-only.
"""
import datetime
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "cert_watch.py")
NOW = datetime.datetime.now(datetime.timezone.utc)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class PKI:
    def __init__(self, tmp):
        self.tmp = tmp
        self.ca_key = _key()
        self.ca_cert = (x509.CertificateBuilder()
                        .subject_name(_name("cert-watch test CA")).issuer_name(_name("cert-watch test CA"))
                        .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(NOW - datetime.timedelta(days=1))
                        .not_valid_after(NOW + datetime.timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                     key_encipherment=False, data_encipherment=False,
                                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                     encipher_only=False, decipher_only=False), critical=True)
                        .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                                       critical=False)
                        .sign(self.ca_key, hashes.SHA256()))
        self.ca_file = os.path.join(tmp, "ca.pem")
        with open(self.ca_file, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def leaf(self, name, days_valid=90, not_before_days=-1, sans=("localhost",), self_signed=False,
             algorithm=None):
        key = _key()
        issuer_key, issuer = (key, _name("localhost")) if self_signed else (self.ca_key, self.ca_cert.subject)
        b = (x509.CertificateBuilder().subject_name(_name("localhost")).issuer_name(issuer)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(NOW + datetime.timedelta(days=not_before_days))
             .not_valid_after(NOW + datetime.timedelta(days=days_valid, hours=1)))
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        if not self_signed:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                                critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        cert = b.sign(issuer_key, algorithm or hashes.SHA256())
        cert_path = os.path.join(self.tmp, name + ".crt")
        key_path = os.path.join(self.tmp, name + ".key")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        return cert_path, key_path


def _leaf_sha1_via_openssl(self, name):
    """CA-signed leaf whose signature uses SHA-1 (cryptography refuses to make one)."""
    key = _key()
    csr = (x509.CertificateSigningRequestBuilder().subject_name(_name("localhost"))
           .sign(key, hashes.SHA256()))
    paths = {n: os.path.join(self.tmp, f"{name}.{n}") for n in ("csr", "key", "crt", "cakey", "ext")}
    with open(paths["csr"], "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    for path, k in ((paths["key"], key), (paths["cakey"], self.ca_key)):
        with open(path, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    with open(paths["ext"], "w") as f:
        f.write("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    subprocess.run(["openssl", "x509", "-req", "-in", paths["csr"], "-CA", self.ca_file, "-CAkey", paths["cakey"],
                    "-CAcreateserial", "-sha1", "-days", "90", "-extfile", paths["ext"], "-out", paths["crt"]],
                   check=True, capture_output=True)
    return paths["crt"], paths["key"]


PKI.leaf_sha1_via_openssl = _leaf_sha1_via_openssl


class TLSServer:
    """A real TLS listener on 127.0.0.1:<random port> in a background thread."""

    def __init__(self, cert, key, min_version=None, max_version=None, ciphers=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if ciphers or min_version:
            self.ctx.set_ciphers(ciphers or "ALL:@SECLEVEL=0")
        if min_version:
            self.ctx.minimum_version = min_version
        if max_version:
            self.ctx.maximum_version = max_version
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.settimeout(5)
                with self.ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass

    def close(self):
        self.stop = True
        self.thread.join(2)
        self.sock.close()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.pki = PKI(self.tmp)
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def serve(self, *leaf_args, server_kwargs=None, **leaf_kwargs):
        cert, key = self.pki.leaf(*leaf_args, **leaf_kwargs)
        srv = TLSServer(cert, key, **(server_kwargs or {}))
        self.servers.append(srv)
        return srv.port

    def run_tool(self, *args):
        env = dict(os.environ, SSL_CERT_FILE=self.pki.ca_file)
        env.pop("SSL_CERT_DIR", None)
        return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True,
                              env=env, timeout=120)

    def check(self, port, *extra, host="localhost"):
        p = self.run_tool("--json", *extra, f"{host}:{port}")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        res = json.loads(p.stdout)
        self.assertEqual(len(res), 1)
        return p.returncode, res[0], " | ".join(f["severity"] + " " + f["message"] for f in res[0]["findings"])


class TestCertChecks(Base):
    def test_healthy_host(self):
        code, r, msgs = self.check(self.serve("good", days_valid=200))
        self.assertEqual(code, 0, msgs)
        self.assertTrue(r["ok"])
        self.assertEqual(r["findings"], [])
        self.assertIn(r["days_left"], (199, 200))
        self.assertEqual(r["san"], ["localhost"])
        self.assertIn(r["protocol"], ("TLSv1.2", "TLSv1.3"))

    def test_expiring_inside_warn_window_is_high(self):
        code, r, msgs = self.check(self.serve("soon", days_valid=10))
        self.assertEqual(code, 1)
        self.assertIn("HIGH Certificate expires in", msgs)

    def test_heads_up_at_twice_warn_window_is_medium(self):
        code, r, msgs = self.check(self.serve("med", days_valid=20))
        self.assertEqual(code, 0)
        self.assertIn("MEDIUM Certificate expires in", msgs)

    def test_warn_days_option(self):
        port = self.serve("w", days_valid=20)
        code, _, msgs = self.check(port, "--warn-days", "21")
        self.assertEqual(code, 1, msgs)
        code, _, msgs = self.check(port, "--warn-days", "5")
        self.assertEqual(code, 0)
        self.assertNotIn("Certificate expires", msgs)

    def test_expired_cert_reports_verification_and_expiry(self):
        code, r, msgs = self.check(self.serve("expired", days_valid=-5, not_before_days=-60))
        self.assertEqual(code, 1)
        self.assertIn("Certificate verification failed", msgs)
        self.assertIn("EXPIRED", msgs)
        self.assertLess(r["days_left"], 0)

    def test_self_signed(self):
        code, r, msgs = self.check(self.serve("self", self_signed=True))
        self.assertEqual(code, 1)
        self.assertIn("self-signed", msgs)
        self.assertIn("days_left", r)  # details still reported from the unverified retry
        self.assertNotIn("Subject Alternative", msgs)

    def test_hostname_mismatch(self):
        code, r, msgs = self.check(self.serve("other", sans=("other.example",)))
        self.assertEqual(code, 1)
        self.assertIn("Hostname mismatch", msgs)
        self.assertEqual(r["san"], ["other.example"])

    def test_cn_only_cert_flags_missing_san(self):
        code, r, msgs = self.check(self.serve("cn", sans=()))
        self.assertEqual(r["san"], [])
        self.assertIn("MEDIUM No Subject Alternative Names", msgs)

    def test_sha1_signature_is_flagged(self):
        cert, key = self.pki.leaf_sha1_via_openssl("sha1")
        srv = TLSServer(cert, key, ciphers="ALL:@SECLEVEL=0")
        self.servers.append(srv)
        code, r, msgs = self.check(srv.port)
        self.assertEqual(code, 1)
        self.assertIn("weak algorithm: sha1WithRSAEncryption", msgs)

    def test_legacy_tls10_only_server(self):
        port = self.serve("tls10", server_kwargs={"min_version": ssl.TLSVersion.TLSv1,
                                                  "max_version": ssl.TLSVersion.TLSv1})
        code, r, msgs = self.check(port)
        self.assertEqual(code, 1)
        self.assertEqual(r["protocol"], "TLSv1")
        self.assertIn("Negotiated weak/legacy protocol: TLSv1", msgs)

    def test_legacy_tls11_only_server(self):
        port = self.serve("tls11", server_kwargs={"min_version": ssl.TLSVersion.TLSv1_1,
                                                  "max_version": ssl.TLSVersion.TLSv1_1})
        code, r, msgs = self.check(port)
        self.assertEqual(code, 1)
        self.assertEqual(r["protocol"], "TLSv1.1")

    def test_weak_cipher_is_flagged(self):
        # Current OpenSSL builds no longer ship RC4/DES at all; a NULL
        # (no-encryption) suite is the weak cipher a real server can still offer.
        port = self.serve("null", server_kwargs={"max_version": ssl.TLSVersion.TLSv1_2,
                                                 "ciphers": "NULL-SHA256:@SECLEVEL=0"})
        code, r, msgs = self.check(port)
        self.assertEqual(code, 1)
        self.assertIn("Weak cipher negotiated: NULL-SHA256", msgs)

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        code, r, msgs = self.check(port, host="127.0.0.1")
        self.assertEqual(code, 1)
        self.assertIn("Connection failed", msgs)


class TestCli(Base):
    def test_multiple_hosts_file_and_text_report(self):
        good = self.serve("g", days_valid=200)
        bad = self.serve("b", days_valid=3)
        hosts = os.path.join(self.tmp, "hosts.txt")
        with open(hosts, "w") as f:
            f.write(f"# comment line\n\n  localhost:{bad}   # inline comment\n")
        p = self.run_tool("--file", hosts, f"localhost:{good}")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn(f"localhost:{good}  [OK]", p.stdout)
        self.assertIn(f"localhost:{bad}  [ISSUES FOUND]", p.stdout)
        self.assertIn("Summary: 1/2 host(s) with HIGH-severity findings.", p.stdout)

    def test_all_healthy_exit_zero(self):
        p = self.run_tool(f"localhost:{self.serve('ok', days_valid=200)}")
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("Summary: 0/1", p.stdout)

    def test_ipv6_bracket_syntax(self):
        sys.path.insert(0, os.path.dirname(TOOL))
        import cert_watch
        self.assertEqual(cert_watch.parse_host("[::1]:8443"), ("::1", 8443))
        self.assertEqual(cert_watch.parse_host("[::1]"), ("::1", 443))
        self.assertEqual(cert_watch.parse_host("2001:db8::1"), ("2001:db8::1", 443))
        self.assertEqual(cert_watch.parse_host("example.com"), ("example.com", 443))
        self.assertEqual(cert_watch.parse_host("example.com:8443"), ("example.com", 8443))

    def test_no_hosts_is_usage_error(self):
        p = self.run_tool()
        self.assertEqual(p.returncode, 2)
        self.assertIn("no hosts given", p.stderr)

    def test_bad_port_is_usage_error(self):
        p = self.run_tool("localhost:notaport")
        self.assertEqual(p.returncode, 2)
        self.assertNotIn("Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
