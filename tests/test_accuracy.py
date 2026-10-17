"""Detection accuracy against OpenSSL's own client (`openssl s_client`).

Certificate verdicts: for every certificate variant (valid, expired, not yet valid, self-signed,
wrong host, CN-only, a chain whose intermediate the server forgets to send, a full chain via an
intermediate, a SHA-1 signature) the tool must report a verification failure exactly when
`openssl s_client -verify_return_error -verify_hostname` (same CA file, the distribution's default
OpenSSL policy, which like browsers refuses SHA-1 signatures) refuses the connection.

Protocol verdicts: for every protocol range a server is configured with, the versions the tool
says the server accepts must be exactly the versions `openssl s_client -tls1 / -tls1_1 /
-tls1_2 / -tls1_3` can complete a handshake with (run with OPENSSL_CONF=/dev/null and
SECLEVEL=0, so the reference client itself refuses nothing).
"""
import os
import ssl
import subprocess
import unittest

from test_cert_watch import Base, TLSServer

VERSIONS = [("TLSv1", "-tls1"), ("TLSv1.1", "-tls1_1"), ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")]


def s_client(port, *args, ca=None, system_policy=False):
    cmd = ["openssl", "s_client", "-connect", "127.0.0.1:%d" % port, "-servername", "localhost"] + list(args)
    if ca:
        cmd += ["-CAfile", ca]
    env = dict(os.environ) if system_policy else dict(os.environ, OPENSSL_CONF="/dev/null")
    p = subprocess.run(cmd, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, env=env)
    return p.returncode == 0, (p.stdout + p.stderr).decode("utf-8", "replace")


class TestVerificationAgainstOpenSSL(Base):
    def variants(self):
        inter_key, inter = self.pki.intermediate(400)
        yield "valid", self.pki.leaf("valid")
        yield "expired", self.pki.leaf("expired", days_valid=-3, not_before_days=-90)
        yield "not yet valid", self.pki.leaf("future", not_before_days=5, days_valid=90)
        yield "self-signed", self.pki.leaf("self", self_signed=True)
        yield "wrong host", self.pki.leaf("wrong", sans=("www.example.org",))
        yield "wildcard host", self.pki.leaf("wild", sans=("*.localhost", "localhost"))
        yield "full chain", self.pki.leaf("chain", issuer_pair=(inter_key, inter))
        cert, key = self.pki.leaf("nochain", issuer_pair=(inter_key, inter))
        with open(cert, "rb") as f:  # keep only the leaf: the intermediate is not sent
            pem = f.read()
        with open(cert, "wb") as f:
            f.write(pem[:pem.index(b"-----END CERTIFICATE-----") + 26])
        yield "intermediate not sent", (cert, key)
        yield "sha1 signature", self.pki.leaf_sha1_via_openssl("sha1")

    def test_verification_verdicts(self):
        for name, (cert, key) in self.variants():
            with self.subTest(variant=name):
                srv = TLSServer(cert, key, ciphers="ALL:@SECLEVEL=0")
                self.servers.append(srv)
                # a default, modern OpenSSL client (the distribution's policy: SHA-1 signatures refused)
                ok, out = s_client(srv.port, "-verify_return_error", "-verify_hostname", "localhost",
                                   ca=self.pki.ca_file, system_policy=True)
                code, r, msgs = self.check(srv.port)
                tool_failed = any(f["message"].startswith(("Certificate verification failed", "Hostname mismatch"))
                                  for f in r["findings"])
                self.assertEqual(tool_failed, not ok, "%s: openssl %s; tool: %s\n%s" % (
                    name, "verified" if ok else "refused", msgs, out[-400:]))
                if not ok:
                    self.assertEqual(code, 1)


class TestProtocolsAgainstOpenSSL(Base):
    RANGES = [(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3), (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
              (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_3), (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2),
              (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2), (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)]

    def test_accepted_versions(self):
        for lo, hi in self.RANGES:
            with self.subTest(range="%s-%s" % (lo.name, hi.name)):
                port = self.serve("p%s%s" % (lo.value, hi.value), server_kwargs={
                    "min_version": lo, "max_version": hi, "ciphers": "ALL:@SECLEVEL=0"})
                want = {}
                for name, flag in VERSIONS:
                    extra = ["-cipher", "ALL:@SECLEVEL=0"] if flag != "-tls1_3" else []
                    want[name] = s_client(port, flag, *extra)[0]
                code, r, msgs = self.check(port)
                self.assertEqual(r["protocols"], want, msgs)
                legacy = want["TLSv1"] or want["TLSv1.1"]
                self.assertEqual("Server still accepts legacy" in msgs or "Negotiated weak/legacy protocol" in msgs,
                                 legacy, msgs)
                # (only worth a LOW note when TLS 1.2 is there; a legacy-only server already gets a HIGH)
                self.assertEqual("TLS 1.3 is not offered" in msgs, want["TLSv1.2"] and not want["TLSv1.3"], msgs)


if __name__ == "__main__":
    unittest.main()
