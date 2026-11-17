"""Pins for --webhook wire details and --chain wording (killed mutation survivors of 1.4.0)."""
import http.server
import io
import os
import sys
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cert_watch  # noqa: E402


class _Resp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return b""


class TestSendWebhookDepth(unittest.TestCase):
    def test_https_url_accepted_http_case_insensitive(self):
        for url in ("https://127.0.0.1:1/x", "HTTPS://127.0.0.1:1/x", "HTTP://127.0.0.1:1/x"):
            err = cert_watch.send_webhook(url, {}, 2)
            self.assertTrue(err.startswith("webhook failed: "), (url, err))

    def test_header_dict_exact(self):
        with mock.patch.object(cert_watch.urllib.request, "Request", wraps=cert_watch.urllib.request.Request) as rq, \
                mock.patch.object(cert_watch.urllib.request, "urlopen", return_value=_Resp()):
            self.assertIsNone(cert_watch.send_webhook("http://h.test/x", {"a": 1}, 3))
        args = rq.call_args[0]
        self.assertEqual(args[0], "http://h.test/x")
        self.assertEqual(args[1], b'{"a": 1}')
        self.assertEqual(args[2], {"Content-Type": "application/json",
                                   "User-Agent": "tls-cert-watchdog/" + cert_watch.__version__})

    def test_user_agent_and_type_on_the_wire(self):
        seen = {}

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen["ua"] = self.headers.get("User-Agent")
                seen["ct"] = self.headers.get("Content-Type")
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.assertIsNone(cert_watch.send_webhook("http://127.0.0.1:%d/" % srv.server_address[1], {}, 5))
        self.assertEqual(seen["ua"], "tls-cert-watchdog/" + cert_watch.__version__)
        self.assertEqual(seen["ct"], "application/json")

    def test_timeout_passed_to_urlopen(self):
        with mock.patch.object(cert_watch.urllib.request, "urlopen", return_value=_Resp()) as uo:
            cert_watch.send_webhook("http://h.test/x", {}, 2.5)
        self.assertEqual(uo.call_args[1], {"timeout": 2.5})

    def test_error_text_exact(self):
        with mock.patch.object(cert_watch.urllib.request, "urlopen", side_effect=OSError("boom")):
            self.assertEqual(cert_watch.send_webhook("http://h.test/x", {}, 1), "webhook failed: boom")

    def test_main_passes_timeout_to_send_webhook(self):
        r = {"host": "h.test", "port": 443, "ok": False, "findings": [{"severity": "HIGH", "message": "m"}]}
        with mock.patch.object(cert_watch, "check_host", return_value=r), \
                mock.patch.object(cert_watch, "send_webhook", return_value=None) as sw, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cert_watch.main(["h.test", "--webhook", "http://h.test/x", "--timeout", "7"])
        self.assertEqual(sw.call_args[0][0], "http://h.test/x")
        self.assertEqual(sw.call_args[0][2], 7)


class TestChainWordingDepth(unittest.TestCase):
    def render(self, r):
        return cert_watch.render_text([r], True).split("\n")

    def test_missing_fields_shown_as_question_mark(self):
        r = {"host": "h.test", "port": 443, "ok": True, "findings": [],
             "chain": [{"subject": "", "issuer": "", "not_after": ""}]}
        self.assertIn("    0: ?  <- ?  (expires ?)", self.render(r))

    def test_each_missing_field_alone(self):
        full = {"subject": "CN=a", "issuer": "CN=b", "not_after": "N"}
        for k, want in (("subject", "    0: ?  <- CN=b  (expires N)"), ("issuer", "    0: CN=a  <- ?  (expires N)"),
                        ("not_after", "    0: CN=a  <- CN=b  (expires ?)")):
            c = dict(full, **{k: None})
            r = {"host": "h.test", "port": 443, "ok": True, "findings": [], "chain": [c]}
            self.assertIn(want, self.render(r))

    def test_unavailable_line_exact(self):
        r = {"host": "h.test", "port": 443, "ok": True, "findings": []}
        self.assertIn("  Chain: not available (needs Python 3.13+ or the handshake failed)", self.render(r))


if __name__ == "__main__":
    unittest.main()
