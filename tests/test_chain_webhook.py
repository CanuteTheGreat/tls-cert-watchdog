"""--chain text listing and --webhook notification."""
import http.server
import io
import json
import os
import sys
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cert_watch  # noqa: E402

CHAIN = [{"subject": "CN=leaf", "issuer": "CN=ca", "not_after": "Jan 1 00:00:00 2030 GMT"},
         {"subject": "CN=ca", "issuer": "CN=root", "not_after": "Jan 1 00:00:00 2031 GMT"}]


def res(findings, chain=True):
    r = {"host": "h.test", "port": 443, "ok": not findings, "findings": findings}
    if chain:
        r["chain"] = CHAIN
    return r


def run_main(argv, results):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(cert_watch, "check_host", side_effect=results), redirect_stdout(out), redirect_stderr(err):
        code = cert_watch.main(argv)
    return code, out.getvalue(), err.getvalue()


class Hook(http.server.BaseHTTPRequestHandler):
    bodies = []
    status = 200

    def do_POST(self):
        Hook.bodies.append((self.headers.get("Content-Type"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(Hook.status)
        self.end_headers()

    def log_message(self, *a):
        pass


class TestChain(unittest.TestCase):
    def test_chain_listed_only_with_flag(self):
        _, plain, _ = run_main(["h.test", "--no-protocol-scan"], [res([])])
        self.assertNotIn("Chain sent", plain)
        _, out, _ = run_main(["h.test", "--chain"], [res([])])
        self.assertIn("  Chain sent by the server:\n    0: CN=leaf  <- CN=ca  (expires Jan 1 00:00:00 2030 GMT)\n"
                      "    1: CN=ca  <- CN=root  (expires Jan 1 00:00:00 2031 GMT)\n", out)

    def test_chain_unavailable_is_said(self):
        _, out, _ = run_main(["h.test", "--chain"], [res([], chain=False)])
        self.assertIn("  Chain: not available (needs Python 3.13+ or the handshake failed)", out)


class TestWebhook(unittest.TestCase):
    def setUp(self):
        Hook.bodies, Hook.status = [], 200
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Hook)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = "http://127.0.0.1:%d/hook" % self.srv.server_address[1]

    def test_posts_findings_at_or_above_gate(self):
        f = [{"severity": "HIGH", "message": "expires in 3 days"}, {"severity": "LOW", "message": "minor"}]
        code, _, _ = run_main(["h.test", "--webhook", self.url], [res(f)])
        self.assertEqual(code, 1)
        ctype, body = Hook.bodies[0]
        self.assertEqual(ctype, "application/json")
        self.assertEqual(body["findings"], [{"host": "h.test", "port": 443, "severity": "HIGH", "message": "expires in 3 days"}])
        self.assertEqual(body["text"], "tls-cert-watchdog: 1 finding(s) on 1 host(s)\n[HIGH] h.test:443 expires in 3 days")
        self.assertEqual(body["content"], body["text"])

    def test_fail_on_low_includes_low(self):
        f = [{"severity": "LOW", "message": "minor"}]
        run_main(["h.test", "--webhook", self.url, "--fail-on", "low"], [res(f)])
        self.assertEqual(len(Hook.bodies[0][1]["findings"]), 1)

    def test_nothing_sent_when_clean_or_below_gate_or_never(self):
        run_main(["h.test", "--webhook", self.url], [res([])])
        run_main(["h.test", "--webhook", self.url], [res([{"severity": "LOW", "message": "m"}])])
        run_main(["h.test", "--webhook", self.url, "--fail-on", "never"], [res([{"severity": "HIGH", "message": "m"}])])
        self.assertEqual(Hook.bodies, [])

    def test_failure_reported_on_stderr_exit_code_unchanged(self):
        Hook.status = 500
        code, _, err = run_main(["h.test", "--webhook", self.url], [res([{"severity": "HIGH", "message": "m"}])])
        self.assertEqual(code, 1)
        self.assertIn("webhook failed:", err)

    def test_bad_scheme_rejected(self):
        self.assertEqual(cert_watch.send_webhook("file:///etc/passwd", {}, 1), "webhook URL must start with http:// or https://")

    def test_text_truncated_for_slack(self):
        f = [{"severity": "HIGH", "message": "x" * 100}] * 50
        self.assertLessEqual(len(cert_watch.webhook_payload([res(f)], ("HIGH",))["text"]), 1900)


if __name__ == "__main__":
    unittest.main()
