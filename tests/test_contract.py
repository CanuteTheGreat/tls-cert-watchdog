"""The verdict contract of tls-cert-watchdog, pinned finding by finding (found as mutation-testing
survivors): the severity and wording of every finding for every key type, expiry boundary, chain
and handshake-failure path, the STARTTLS dialogues (what is sent, what each refusal reports), the
text report, --fail-on/--file/--starttls none and target parsing.

Verdict tests feed real certificates (built with `cryptography`) through check_host() with the
network handshake replaced, so every branch is reached deterministically, including key types a
stock OpenSSL server won't serve (P-224, secp256k1, DSA). STARTTLS and CLI tests use real sockets.
"""
import datetime
import json
import os
import socket
import ssl
import struct
import sys
import threading
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from test_cert_watch import TOOL, Base

sys.path.insert(0, os.path.dirname(TOOL))
import cert_watch  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
MODERN = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


def make_der(key=None, days=200, sans=("localhost",), subject=(("CN", "localhost"),), issuer_key=None,
             hours=1):
    key = key or rsa.generate_private_key(65537, 2048)
    oids = {"CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME}
    name = x509.Name([x509.NameAttribute(oids[k], v) for k, v in subject])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=400))
         .not_valid_after(NOW + datetime.timedelta(days=days, hours=hours)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    signer = issuer_key or key
    algo = None if isinstance(signer, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hashes.SHA256()
    cert = b.sign(signer, algo)
    return cert.public_bytes(serialization.Encoding.DER), cert


def not_after(cert):
    """cryptography >= 42 has not_valid_after_utc; the versions Python 3.8 gets have only the naive one."""
    na = getattr(cert, "not_valid_after_utc", None)
    return na if na is not None else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def run_check(*answers, warn_days=14, starttls="", protocols=None, calls=None):
    """check_host() with each handshake answered from `answers` (a tuple = success, an exception = raised)."""
    answers = list(answers)
    calls = calls if calls is not None else []

    def fake_handshake(host, port, ctx, timeout, st=""):
        calls.append((host, port, timeout, st, ctx.verify_mode))
        a = answers.pop(0)
        if isinstance(a, BaseException):
            raise a
        return a

    probe = mock.Mock(return_value=protocols) if protocols is not None else None
    with mock.patch.object(cert_watch, "_handshake", fake_handshake):
        if probe:
            with mock.patch.object(cert_watch, "probe_protocols", probe):
                r = cert_watch.check_host("h.test", 8443, warn_days, 7.5, starttls, True)
            probe.assert_called_once_with("h.test", 8443, 7.5, starttls)
        else:
            r = cert_watch.check_host("h.test", 8443, warn_days, 7.5, starttls, False)
    return r, [(f["severity"], f["message"]) for f in r["findings"]]


class TestKeys(unittest.TestCase):
    def verdict(self, key):
        der, _ = make_der(key)
        r, f = run_check((der, "TLSv1.3", MODERN, None))
        return r["key"], f, r["ok"]

    def test_key_types(self):
        cases = [
            (rsa.generate_private_key(65537, 1024), {"type": "RSA", "bits": 1024, "curve": None},
             [("HIGH", "RSA key is only 1024 bits (2048 is the minimum CAs and browsers accept).")]),
            (rsa.generate_private_key(65537, 2048), {"type": "RSA", "bits": 2048, "curve": None}, []),
            (ec.generate_private_key(ec.SECP224R1()), {"type": "EC", "bits": 224, "curve": "P-224"},
             [("HIGH", "EC key on weak curve P-224 (224 bits).")]),
            (ec.generate_private_key(ec.SECP256K1()), {"type": "EC", "bits": 256, "curve": "secp256k1"},
             [("MEDIUM", "EC key on non-standard curve secp256k1.")]),
            (ec.generate_private_key(ec.SECP256R1()), {"type": "EC", "bits": 256, "curve": "P-256"}, []),
            (ec.generate_private_key(ec.SECP521R1()), {"type": "EC", "bits": 521, "curve": "P-521"}, []),
            (ed25519.Ed25519PrivateKey.generate(), {"type": "Ed25519", "bits": 256, "curve": None}, []),
            (ed448.Ed448PrivateKey.generate(), {"type": "Ed448", "bits": 456, "curve": None}, []),
            (dsa.generate_private_key(2048), {"type": "DSA", "bits": None, "curve": None},
             [("HIGH", "DSA certificate key (no longer accepted by browsers).")]),
        ]
        for key, want_key, want_findings in cases:
            with self.subTest(key=want_key):
                got_key, findings, ok = self.verdict(key)
                self.assertEqual(got_key, want_key)
                self.assertEqual(findings, want_findings)
                self.assertEqual(ok, not any(s == "HIGH" for s, _ in want_findings))

    def test_unknown_curve_and_algorithm_oids_are_reported_by_oid(self):
        der, _ = make_der(ec.generate_private_key(ec.BrainpoolP256R1()))
        self.assertEqual(cert_watch.public_key_info(der), ("EC", None, "1.3.36.3.3.2.8.1.1.7"))
        r, f = run_check((der, "TLSv1.3", MODERN, None))
        self.assertEqual(f, [("MEDIUM", "EC key on non-standard curve 1.3.36.3.3.2.8.1.1.7.")])
        self.assertIsNone(cert_watch.public_key_info(b"\x30\x03\x02\x01"))  # truncated DER

    def test_oid_decoding(self):
        self.assertEqual(cert_watch._oid_to_str(bytes.fromhex("2a864886f70d01010b")), "1.2.840.113549.1.1.11")
        self.assertEqual(cert_watch._oid_to_str(bytes.fromhex("550403")), "2.5.4.3")
        # long-form DER length (a 2048-bit RSA modulus needs two length bytes)
        der, _ = make_der()
        self.assertEqual(cert_watch._der_read(der, 0)[0], 0x30)
        self.assertEqual(cert_watch._der_read(der, 0)[2], len(der))


class TestExpiry(unittest.TestCase):
    def findings(self, days, hours=1, warn_days=14):
        der, cert = make_der(days=days, hours=hours)
        r, f = run_check((der, "TLSv1.3", MODERN, None), warn_days=warn_days)
        self.cert = cert
        return r, f, not_after(cert).date()

    def test_boundaries(self):
        for days, sev in ((0, "HIGH"), (14, "HIGH"), (15, "MEDIUM"), (28, "MEDIUM"), (29, None)):
            with self.subTest(days=days):
                r, f, date = self.findings(days)
                self.assertEqual(r["days_left"], days)
                if sev == "HIGH":
                    self.assertEqual(f, [("HIGH", "Certificate expires in %d day(s) (%s) \u2014 inside the "
                                                  "14-day warning window." % (days, date))])
                elif sev == "MEDIUM":
                    self.assertEqual(f, [("MEDIUM", "Certificate expires in %d day(s) (%s)." % (days, date))])
                else:
                    self.assertEqual(f, [])
        r, f, date = self.findings(20, warn_days=10)  # the MEDIUM band is twice --warn-days
        self.assertEqual(f, [("MEDIUM", "Certificate expires in 20 day(s) (%s)." % date)])
        self.assertEqual(self.findings(21, warn_days=10)[1], [])
        r, f, date = self.findings(19, warn_days=20)
        self.assertEqual(f[0][0], "HIGH")
        self.assertIn("inside the 20-day warning window", f[0][1])

    def test_expired(self):
        r, f, date = self.findings(-2, hours=1)  # expired 47 hours ago
        self.assertEqual((r["days_left"], r["ok"]), (-2, False))
        self.assertEqual(f, [("HIGH", "Certificate EXPIRED 2 day(s) ago (%s)." % date)])
        self.assertEqual(r["expires"], not_after(self.cert).replace(microsecond=0).isoformat())


class TestSignatureAndSan(unittest.TestCase):
    def test_signature_oid_and_missing_san(self):
        der, _ = make_der(sans=())
        r, f = run_check((der, "TLSv1.3", MODERN, None))
        self.assertEqual(r["signature_oid"], "1.2.840.113549.1.1.11")
        self.assertEqual(r["san"], [])
        self.assertEqual(f, [("MEDIUM", "No Subject Alternative Names present (legacy CN-only cert).")])
        self.assertTrue(r["ok"])

    def test_sha1_signature(self):
        class Holder(Base):
            def runTest(self):
                pass
        h = Holder()
        h.setUp()
        try:
            crt, _ = h.pki.leaf_sha1_via_openssl("sha1c")
            with open(crt) as fh:
                der = ssl.PEM_cert_to_DER_cert(fh.read())
        finally:
            h.tearDown()
        r, f = run_check((der, "TLSv1.3", MODERN, None))
        self.assertEqual(r["signature_oid"], "1.2.840.113549.1.1.5")
        self.assertEqual(f, [("HIGH", "Certificate is signed with a weak algorithm: sha1WithRSAEncryption.")])
        self.assertFalse(r["ok"])


class TestHandshakePaths(unittest.TestCase):
    def setUp(self):
        self.der, _ = make_der()

    def test_modern_handshake_result_fields(self):
        calls = []
        r, f = run_check((self.der, "TLSv1.3", MODERN, None), calls=calls)
        self.assertEqual(f, [])
        self.assertEqual((r["host"], r["port"], r["starttls"], r["protocol"], r["cipher"], r["ok"]),
                         ("h.test", 8443, None, "TLSv1.3", "TLS_AES_256_GCM_SHA384", True))
        self.assertEqual(calls, [("h.test", 8443, 7.5, "", ssl.CERT_REQUIRED)])  # verified first

    def test_legacy_only_server(self):
        calls = []
        r, f = run_check(ssl.SSLError("unsupported protocol"), (self.der, "TLSv1", ("AES128-SHA", "TLSv1", 128), None),
                         starttls="smtp", calls=calls)
        self.assertEqual(f, [("HIGH", "Negotiated weak/legacy protocol: TLSv1.")])
        self.assertEqual(calls[1], ("h.test", 8443, 7.5, "smtp", ssl.CERT_NONE))  # retried without verification

    def test_weak_cipher_only_server(self):
        r, f = run_check(ssl.SSLError("no shared cipher"), (self.der, "TLSv1.2", ("RC4-SHA", "TLSv1.2", 128), None))
        self.assertEqual(f, [("HIGH", "Weak cipher negotiated: RC4-SHA.")])

    def test_modern_client_refused_for_another_reason(self):
        r, f = run_check(ssl.SSLError(1, "boom"), (self.der, "TLSv1.2", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128), None))
        self.assertEqual(f, [("HIGH", "TLS handshake failed with modern client defaults: boom")])

    def test_both_handshakes_fail(self):
        r, f = run_check(ssl.SSLError(1, "boom"), OSError("reset"))
        self.assertEqual(f, [("HIGH", "TLS handshake failed: boom")])
        self.assertEqual(set(r), {"host", "port", "starttls", "findings", "ok"})
        e = ssl.SSLCertVerificationError(1, "verify failed")
        e.verify_message = "self-signed certificate"
        r, f = run_check(e, OSError("gone"))
        self.assertEqual(f, [("HIGH", "Certificate verification failed: self-signed certificate"),
                             ("HIGH", "Could not retrieve certificate at all: gone")])
        self.assertFalse(r["ok"])

    def test_connection_and_starttls_failures(self):
        r, f = run_check(socket.timeout("timed out"))
        self.assertEqual(f, [("HIGH", "Connection failed: timed out")])
        r, f = run_check(cert_watch.StartTLSError("SMTP greeting was 554"), starttls="smtp")
        self.assertEqual(f, [("HIGH", "STARTTLS (smtp) failed: SMTP greeting was 554")])
        self.assertEqual(r["starttls"], "smtp")

    def test_undecodable_certificate(self):
        r, f = run_check((b"\x30\x03\x02\x01\x00", "TLSv1.3", MODERN, None))
        self.assertEqual(f, [("MEDIUM", "Could not decode the certificate's validity dates.")])
        self.assertNotIn("key", r)
        self.assertNotIn("san", r)


class TestChain(unittest.TestCase):
    def test_chain_entries_and_expiry(self):
        leaf, _ = make_der()
        ca_key = rsa.generate_private_key(65537, 2048)
        gone, _ = make_der(days=-3, subject=(("CN", "Inter A"), ("O", "Org")), sans=(), issuer_key=ca_key)
        soon, soon_cert = make_der(days=0, subject=(("CN", "Inter B"),), sans=())
        fine, _ = make_der(days=400, subject=(("CN", "Root",),), sans=())
        r, f = run_check((leaf, "TLSv1.3", MODERN, [leaf, gone, soon, fine]))
        self.assertEqual(f, [("HIGH", "Chain certificate 'commonName=Inter A, organizationName=Org' EXPIRED 3 day(s) ago."),
                             ("HIGH", "Chain certificate 'commonName=Inter B' expires in 0 day(s).")])
        self.assertEqual([(c["subject"], c["issuer"]) for c in r["chain"]],
                         [("commonName=localhost", "commonName=localhost"),
                          ("commonName=Inter A, organizationName=Org", "commonName=Inter A, organizationName=Org"),
                          ("commonName=Inter B", "commonName=Inter B"), ("commonName=Root", "commonName=Root")])
        self.assertEqual(datetime.datetime.strptime(r["chain"][2]["not_after"], "%b %d %H:%M:%S %Y GMT"),
                         not_after(soon_cert).replace(tzinfo=None, microsecond=0))
        # the leaf is chain[0] and judged by the leaf checks, never twice
        expired_leaf, _ = make_der(days=-3)
        r, f = run_check((expired_leaf, "TLSv1.3", MODERN, [expired_leaf]))
        self.assertEqual([s for s, m in f if "Chain" in m], [])
        self.assertEqual(cert_watch._dn(None), "")


class TestProtocolScan(unittest.TestCase):
    def setUp(self):
        self.der, _ = make_der()

    def test_legacy_and_untested_versions(self):
        offered = {"TLSv1": None, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False}
        r, f = run_check((self.der, "TLSv1.2", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128), None),
                         protocols=dict(offered))
        self.assertEqual(f, [("HIGH", "Server still accepts legacy TLSv1.1 (negotiated TLSv1.2 only because this "
                                      "client prefers it; old clients and downgrade attacks get the legacy version)."),
                             ("LOW", "TLS 1.3 is not offered.")])
        self.assertEqual((r["protocols"], r["protocols_untested"]), (offered, ["TLSv1"]))
        r, f = run_check((self.der, "TLSv1.2", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128), None),
                         protocols=dict(offered), starttls="imap")
        self.assertEqual(f[0][0], "MEDIUM")  # opportunistic STARTTLS: legacy still beats plaintext
        r, f = run_check((self.der, "TLSv1.3", MODERN, None),
                         protocols={"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True})
        self.assertEqual((f, "protocols_untested" in r), ([], False))

    def test_probe_classifies_each_version(self):
        outcomes = {"TLSv1": ssl.SSLError("[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available"),
                    "TLSv1.1": ssl.SSLError("[SSL] sslv3 alert handshake failure"),
                    "TLSv1.2": (None, "TLSv1.2", None, None),
                    "TLSv1.3": (None, "TLSv1.2", None, None)}  # answered with another version: not accepted
        seen = []

        def fake(host, port, ctx, timeout, st=""):
            name = {ssl.TLSVersion.TLSv1: "TLSv1", ssl.TLSVersion.TLSv1_1: "TLSv1.1",
                    ssl.TLSVersion.TLSv1_2: "TLSv1.2", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}[ctx.maximum_version]
            seen.append((name, host, port, timeout, st, ctx.minimum_version == ctx.maximum_version))
            o = outcomes[name]
            if isinstance(o, BaseException):
                raise o
            return o

        with mock.patch.object(cert_watch, "_handshake", fake):
            got = cert_watch.probe_protocols("p.test", 993, 3.0, "imap")
        tested = [s[0] for s in seen]
        self.assertTrue(set(tested) <= {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"})
        for name, host, port, timeout, st, pinned in seen:
            self.assertEqual((host, port, timeout, st, pinned), ("p.test", 993, 3.0, "imap", True))
        want = {"TLSv1": None, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": False}
        for name in tested:
            self.assertIs(got[name], want[name], name)
        for name in set(want) - set(tested):  # this OpenSSL can't even configure that version
            self.assertIsNone(got[name])
        self.assertEqual(list(got), ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"])
        with mock.patch.object(cert_watch, "_handshake", side_effect=cert_watch.StartTLSError("x")):
            self.assertNotIn(True, cert_watch.probe_protocols("p.test", 25, 1, "smtp").values())
        with mock.patch.object(cert_watch, "_handshake", side_effect=ConnectionResetError("x")):
            self.assertNotIn(True, cert_watch.probe_protocols("p.test", 443, 1).values())


class TestRenderText(unittest.TestCase):
    def test_report(self):
        results = [
            {"host": "a.test", "port": 443, "starttls": None, "ok": True, "findings": [],
             "expires": "2027-01-01T00:00:00+00:00", "days_left": 76, "protocol": "TLSv1.3",
             "cipher": "TLS_AES_256_GCM_SHA384",
             "protocols": {"TLSv1": False, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True},
             "key": {"type": "EC", "bits": 256, "curve": "P-256"}},
            {"host": "b.test", "port": 25, "starttls": "smtp", "ok": False, "protocol": "TLSv1.2",
             "findings": [{"severity": "HIGH", "message": "Bad thing."}, {"severity": "LOW", "message": "Meh."}],
             "key": {"type": "DSA", "bits": None, "curve": None}},
            {"host": "c.test", "port": 443, "starttls": None, "ok": False,
             "findings": [{"severity": "HIGH", "message": "Connection failed: refused"}]},
        ]
        self.assertEqual(cert_watch.render_text(results), "\n".join([
            "TLS Certificate Watchdog Report",
            "=" * 40,
            "",
            "a.test:443  [OK]",
            "  Expires: 2027-01-01T00:00:00+00:00  (76 days left)",
            "  Protocol: TLSv1.3   Cipher: TLS_AES_256_GCM_SHA384",
            "  Accepts: TLSv1 no, TLSv1.1 untested, TLSv1.2 yes, TLSv1.3 yes",
            "  Key: EC 256 bits (P-256)",
            "",
            "b.test:25  [ISSUES FOUND]",
            "  Protocol: TLSv1.2   Cipher: ?   (STARTTLS smtp)",
            "  Key: DSA ? bits",
            "  [HIGH] Bad thing.",
            "  [LOW] Meh.",
            "",
            "c.test:443  [ISSUES FOUND]",
            "  [HIGH] Connection failed: refused",
            "",
            "Summary: 2/3 host(s) with HIGH-severity findings."]))


class ScriptServer:
    """A plain-TCP server that plays one side of a STARTTLS dialogue and records what it receives."""

    def __init__(self, script):
        self.script, self.received = script, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        conn.settimeout(5)
        f = conn.makefile("rb")
        try:
            for step in self.script:
                if isinstance(step, bytes):
                    conn.sendall(step)
                elif step == "line":
                    self.received.append(f.readline())
                else:  # number of raw bytes to read
                    self.received.append(f.read(step))
        except OSError:
            pass
        finally:
            f.close()
            conn.close()

    def close(self):
        self.sock.close()


class TestStartTLSDialogues(unittest.TestCase):
    CASES = [
        ("smtp", [b"554 go away\r\n"], [], "SMTP greeting was 554"),
        ("smtp", [b"220 hi\r\n", "line", b"250-mail.test\r\n250-STARTTLS\r\n250 SIZE 1\r\n", "line",
                  b"454 TLS not available\r\n"],
         [b"EHLO cert-watch.invalid\r\n", b"STARTTLS\r\n"], "SMTP STARTTLS refused (454)"),
        ("smtp", [b"220 hi\r\n", "line", b"250-mail.test\r\n250 SIZE 1\r\n"],
         [b"EHLO cert-watch.invalid\r\n"], "SMTP server does not offer STARTTLS"),
        ("smtp", [b"220-first\r\n220-second\r\n"], [], "server closed the connection"),
        ("imap", [b"* BYE busy\r\n"], [], "unexpected IMAP greeting"),
        ("imap", [b"* OK ready\r\n", "line", b"* NOTE untagged\r\na1 NO not now\r\n"], [b"a1 STARTTLS\r\n"],
         "IMAP STARTTLS refused: a1 NO not now"),
        ("imap", [b"* OK ready\r\n", "line"], [b"a1 STARTTLS\r\n"], "server closed the connection"),
        ("pop3", [b"-ERR busy\r\n"], [], "unexpected POP3 greeting"),
        ("pop3", [b"+OK hi\r\n", "line", b"-ERR no\r\n"], [b"STLS\r\n"], "POP3 STLS refused"),
        ("ftp", [b"421 busy\r\n"], [], "FTP greeting was 421"),
        ("ftp", [b"220 hi\r\n", "line", b"500 no\r\n"], [b"AUTH TLS\r\n"], "FTP AUTH TLS refused (500)"),
        ("postgres", [8, b"N"], [struct.pack("!ii", 8, 80877103)], "PostgreSQL server does not accept SSL"),
    ]

    def test_refusals(self):
        for proto, script, want_sent, want_error in self.CASES:
            with self.subTest(proto=proto, error=want_error):
                srv = ScriptServer(script)
                try:
                    with self.assertRaises(cert_watch.StartTLSError) as cm:
                        cert_watch._connect("127.0.0.1", srv.port, 5, proto)
                finally:
                    srv.close()
                self.assertEqual(str(cm.exception), want_error)
                self.assertEqual(srv.received[:len(want_sent)], want_sent)

    def test_unknown_protocol(self):
        srv = ScriptServer([])
        try:
            with self.assertRaises(cert_watch.StartTLSError) as cm:
                cert_watch._connect("127.0.0.1", srv.port, 5, "gopher")
        finally:
            srv.close()
        self.assertEqual(str(cm.exception), "unknown STARTTLS protocol 'gopher'")

    def test_short_reply_lines(self):
        srv = ScriptServer([b"220\r\n", "line", b"250 STARTTLS\r\n", "line", b"220\r\n"])
        try:
            sock = cert_watch._connect("127.0.0.1", srv.port, 5, "smtp")  # bare codes are complete replies
            sock.close()
        finally:
            srv.close()


class TestCliContract(Base):
    def test_fail_on_levels(self):
        medium_port = self.serve("m", days_valid=20)
        high_port = self.serve("h", days_valid=3)
        for level, want_medium, want_high in (("high", 0, 1), ("medium", 1, 1), ("low", 1, 1), ("never", 0, 0)):
            with self.subTest(level=level):
                self.assertEqual(self.run_tool("--fail-on", level, "--no-protocol-scan",
                                               "localhost:%d" % medium_port).returncode, want_medium)
                self.assertEqual(self.run_tool("--fail-on", level, "--no-protocol-scan",
                                               "localhost:%d" % high_port).returncode, want_high)
        self.assertEqual(self.run_tool("--fail-on", "HIGH", "localhost:1").returncode, 2)

    def test_file_comments_and_errors(self):
        port = self.serve("f", days_valid=200)
        hosts = os.path.join(self.tmp, "hosts.txt")
        with open(hosts, "w") as f:
            f.write("# my hosts\n\n   \nlocalhost:%d   # web # really\n" % port)
        p = self.run_tool("--json", "--no-protocol-scan", "--file", hosts)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith('[\n  {\n    "host": "localhost",\n    "port": %d,' % port))
        self.assertEqual([(r["host"], r["port"]) for r in json.loads(p.stdout)], [("localhost", port)])
        p = self.run_tool("--file", os.path.join(self.tmp, "missing.txt"))
        self.assertEqual(p.returncode, 2)
        self.assertIn("error: can't read --file: [Errno 2] No such file or directory", p.stderr)
        p = self.run_tool("gopher://example.com")
        self.assertIn("error: bad [scheme://]host[:port]: unknown scheme gopher:// (use ftp, https, imap, pop3, "
                      "postgres, postgresql, smtp, submission, tls)", p.stderr)

    def test_starttls_none_overrides_the_scheme(self):
        port = self.serve("n", days_valid=200)
        p = self.run_tool("--json", "--no-protocol-scan", "--starttls", "none", "smtp://localhost:%d" % port)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)[0]
        self.assertEqual((r["starttls"], r["findings"]), (None, []))

    def test_target_parsing_edges(self):
        self.assertEqual(cert_watch.parse_target("SMTP://mail.example.com:2525/"), ("mail.example.com", 2525, "smtp"))
        self.assertEqual(cert_watch.parse_target("https://example.com//"), ("example.com", 443, ""))
        self.assertEqual(cert_watch.parse_target("[2001:db8::1]:993"), ("2001:db8::1", 993, ""))
        self.assertEqual(cert_watch.parse_target("[2001:db8::1]"), ("2001:db8::1", 443, ""))
        self.assertEqual(cert_watch.parse_target("2001:db8::1"), ("2001:db8::1", 443, ""))
        self.assertEqual(cert_watch.parse_target("postgres://[::1]:6543"), ("::1", 6543, "postgres"))
        self.assertEqual(cert_watch.parse_target("  example.com:21 "), ("example.com", 21, "ftp"))
        self.assertEqual(cert_watch.parse_target("example.com:110", "imap"), ("example.com", 110, "imap"))
        with self.assertRaises(ValueError) as cm:  # only the first :// separates the scheme
            cert_watch.parse_target("tls://a://b")
        self.assertIn("'//b'", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
