"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors.

Local TLS servers from test_cert_watch.py (a test CA trusted through SSL_CERT_FILE) and a local webhook
receiver; nothing here touches the real network. The tool runs as a subprocess.
"""
import http.server
import io
import json
import os
import sys
import threading
import unittest
from contextlib import redirect_stderr
from unittest import mock

import contract_support as cs
from test_cert_watch import TOOL, Base
from test_chain_webhook import Hook

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import cert_watch as tool  # noqa: E402

SCHEMA = cs.load_schema(ROOT, "tls-cert-watchdog")


class Contract(Base):
    def cli(self, *a):
        env = {"SSL_CERT_FILE": self.pki.ca_file}
        return cs.run_cli(TOOL, a, env=env)

    def clean(self):
        return ("--no-protocol-scan", "localhost:%d" % self.serve("ok", days_valid=200))

    def findings(self):
        return ("--no-protocol-scan", "localhost:%d" % self.serve("soon", days_valid=3))


class TestExitCodes(Contract):
    def test_clean_is_0(self):
        self.assertEqual(self.cli(*self.clean())[0], 0)

    def test_findings_is_1(self):
        self.assertEqual(self.cli(*self.findings())[0], 1)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for a in ((), ("--no-such-flag", "localhost:1"), ("--warn-days", "many", "localhost:1"),
                  ("--fail-on", "critical", "localhost:1")):
            rc, out, err = self.cli(*a)
            self.assertEqual(rc, 2, a)
            self.assertEqual(out, "", a)
            self.assertIn("usage:", err)

    def test_missing_input_file_is_2(self):
        rc, out, err = self.cli("--file", os.path.join(self.tmp, "missing.txt"))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("can't read --file", err)

    def test_unreachable_host_keeps_documented_legacy_code_1(self):
        s = self.serve("gone", days_valid=200)
        self.servers.pop().close()  # the port is now closed
        rc, out, err = self.cli("--no-protocol-scan", "localhost:%d" % s)
        self.assertEqual(rc, 1)
        self.assertIn("Connection failed", out)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), redirect_stderr(buf):
            self.assertEqual(tool.main(["a.test"]), 3)
        self.assertIn("RuntimeError: boom", buf.getvalue())
        buf = io.StringIO()
        with mock.patch.object(tool, "check_host", side_effect=ValueError("bad")), redirect_stderr(buf):
            self.assertEqual(tool.main(["a.test"]), 3)
        self.assertEqual(buf.getvalue(), "tls-cert-watchdog: error: ValueError: bad\n")


class TestJson(Contract):
    def check(self, args, code):
        rc, out, err = self.cli("--json", *args)
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "tls-cert-watchdog")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        doc = self.check(self.clean(), 0)
        self.assertEqual([r["findings"] for r in doc["results"]], [[]])

    def test_findings(self):
        doc = self.check(self.findings(), 1)
        self.assertEqual(len(doc["results"]), 1)
        self.assertFalse(doc["results"][0]["ok"])

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = self.cli("--json")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_runtime_error_leaves_stdout_empty(self):
        out = io.StringIO()
        with mock.patch.object(tool, "check_host", side_effect=OSError("x")), \
                mock.patch("sys.stdout", out), redirect_stderr(io.StringIO()):
            self.assertEqual(tool.main(["--json", "a.test"]), 3)
        self.assertEqual(out.getvalue(), "")

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate([], SCHEMA), [])
        self.assertNotEqual(cs.validate({"results": []}, SCHEMA), [])
        good = {"schema_version": 1, "tool": "tls-cert-watchdog", "version": "2", "exit_code": 0,
                "results": [{"host": "h", "port": 443, "starttls": None, "ok": True, "findings": []}]}
        self.assertEqual(cs.validate(good, SCHEMA), [])
        self.assertNotEqual(cs.validate(dict(good, exit_code=9), SCHEMA), [])


class TestQuiet(Contract):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for setup, code in ((self.clean, 0), (self.findings, 1)):
            args = setup()
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = self.cli(flag, *(extra + args))
                    self.assertEqual((rc, out), (code, ""), (flag, extra, args))

    def test_quiet_still_posts_the_webhook(self):
        Hook.bodies, Hook.status = [], 200
        srv = http.server.HTTPServer(("127.0.0.1", 0), Hook)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        url = "http://127.0.0.1:%d/hook" % srv.server_address[1]
        rc, out, err = self.cli("--quiet", "--webhook", url, *self.findings())
        self.assertEqual((rc, out), (1, ""))
        self.assertEqual(len(Hook.bodies), 1)

    def test_without_quiet_the_report_is_printed(self):
        self.assertIn("localhost", self.cli(*self.clean())[1])


if __name__ == "__main__":
    unittest.main()
