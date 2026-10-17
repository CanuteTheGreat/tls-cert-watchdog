"""Claims that hold for the whole tool, checked mechanically (claims ledger: claims.json).

* every --option the README mentions is a real option of the tool (it appears in --help);
* "stdlib only" / "zero dependencies": every module the tool imports is part of Python itself
  (optional extras the README names, e.g. boto3, are listed in claims.json "optional_imports");
* "no network" / "offline" (only where claims.json says "offline": true): the tool imports no
  networking module at all;
* the version printed by --version is the newest CHANGELOG entry.
"""
import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import sysconfig
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "claims.json")) as _f:
    LEDGER = json.load(_f)
with open(os.path.join(ROOT, "pyproject.toml")) as _f:
    MODULE = re.search(r'^path = "([\w]+)\.py"', _f.read(), re.M).group(1)
TOOL = os.path.join(ROOT, MODULE + ".py")
with open(os.path.join(ROOT, "README.md")) as _f:
    README = _f.read()

NETWORK_MODULES = {"socket", "ssl", "http", "urllib.request", "urllib.error", "smtplib", "ftplib", "poplib",
                   "imaplib", "telnetlib", "xmlrpc", "asyncio", "socketserver", "select", "selectors"}


def run(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=60)


def imported_modules(dotted=False):
    with open(TOOL) as f:
        tree = ast.parse(f.read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names if dotted else {n.split(".")[0] for n in names}


# stdlib modules newer than the oldest Python some tools support (imported behind try/except there)
NEWER_STDLIB = {"zoneinfo", "graphlib", "tomllib", "dataclasses", "contextvars"}


def is_stdlib(name):
    if name in sys.builtin_module_names or name in NEWER_STDLIB:
        return True
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return name in names
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin in (None, "built-in", "frozen"):
        return spec is not None
    stdlib = os.path.realpath(sysconfig.get_paths()["stdlib"])
    origin = os.path.realpath(spec.origin)
    return origin.startswith(stdlib + os.sep) and "site-packages" not in origin and "dist-packages" not in origin


class TestClaims(unittest.TestCase):
    def test_readme_options_exist(self):
        sys.path.insert(0, os.path.join(ROOT, "ci"))
        from check_claims import readme_claims
        _, options, _ = readme_claims(README, LEDGER.get("foreign_options", []))
        options -= set(LEDGER.get("hidden_options", []))
        help_text = run("--help").stdout
        missing = sorted(o for o in options if o not in help_text)
        self.assertEqual(missing, [], "README mentions options that --help doesn't have")

    def test_stdlib_only(self):
        optional = set(LEDGER.get("optional_imports", []))
        # (mutation testing runs a mutmut-instrumented copy of the tool, which imports mutmut)
        third_party = sorted(m for m in imported_modules() - optional - {"__future__", "mutmut"} if not is_stdlib(m))
        self.assertEqual(third_party, [], "the tool imports non-stdlib modules")
        self.assertTrue(re.search(r"stdlib|standard library|[Zz]ero dependencies", README))

    def test_offline_claim(self):
        if not LEDGER.get("offline"):
            # the tool talks to the network: the README must not claim otherwise
            self.assertNotRegex(README, r"(?i)no network calls|works entirely offline")
            return
        used = {m for m in imported_modules(dotted=True)
                if m in NETWORK_MODULES or m.split(".")[0] in NETWORK_MODULES - {"urllib"}}
        self.assertEqual(sorted(used), [], "the README says the tool never touches the network")

    def test_version_is_latest_changelog_entry(self):
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            versions = re.findall(r"^## (\d+\.\d+\.\d+)", f.read(), re.M)
        out = run("--version").stdout.strip()
        self.assertTrue(out.endswith(" " + versions[0]), (out, versions[0]))


if __name__ == "__main__":
    unittest.main()
