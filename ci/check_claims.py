#!/usr/bin/env python3
"""Claims ledger check: every claim the README makes must name a test that proves it.

    python3 ci/check_claims.py            # run by ci/run-tests.sh (fails CI on any gap)

claims.json:
  {"claims": [{"id": "...", "text": "<exact phrase from README.md>", "also": ["<more phrases>"],
               "flags": ["--json", ...],                 # README options this claim covers
               "tests": ["tests/test_x.py::TestClass::test_method",
                         ".forgejo/workflows/test.yml#<text that must be in the file>",
                         "repo:homebrew-errant-tools/Formula/x.rb#<text>"]}]}   # another repo, main

It fails when
  * a claim's text no longer appears in README.md (README changed, ledger not),
  * a claim names no test, or a named test file/class/method (or CI file text) doesn't exist,
  * the README makes a claim that is not in the ledger: a feature bullet (any top-level `- `
    line outside Install/License/Tests/Why sections; matched by its bold lead-in or first line),
    a `--option` anywhere in the README, or the exit-code contract.
The test suite itself runs in the same CI job and fails on any failing/skipped test, so
"exists" here plus a green suite means "proven".
"""
import ast
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORGEJO = "https://git.canutethegreat.com/CanuteTheGreat"


def norm(s):
    return re.sub(r"\s+", " ", s.replace("`", "").replace("*", "")).strip().lower()


def test_exists(ref, cache):
    if "::" in ref:
        path, _, rest = ref.partition("::")
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full):
            return "no such test file %s" % path
        if full not in cache:
            with open(full, encoding="utf-8") as f:
                cache[full] = ast.parse(f.read())
        names = rest.split("::")
        node = cache[full]
        for name in names:
            found = None
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.ClassDef, ast.FunctionDef)) and child.name == name:
                    found = child
                    break
            if found is None:
                return "%s has no %s" % (path, "::".join(names))
            node = found
        if not names[-1].startswith("test"):
            return "%s is not a test method" % ref
        return None
    path, _, needle = ref.partition("#")
    if path.startswith("repo:"):  # a file in another Errant Solutions repo (e.g. the Homebrew tap)
        repo, _, rel = path[5:].partition("/")
        url = "%s/%s/raw/branch/main/%s" % (FORGEJO, repo, rel)
        text = None
        for attempt in range(5):
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    text = r.read().decode("utf-8", "replace")
                break
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return "no such file %s (%s)" % (path, url)
                time.sleep(3)
            except (OSError, http.client.HTTPException):
                time.sleep(3)
        if text is None:
            return "could not fetch %s" % url
        if needle and needle not in text:
            return "%s does not contain %r" % (path, needle)
        return None
    full = os.path.join(ROOT, path)
    if not os.path.isfile(full):
        return "no such file %s" % path
    if needle:
        with open(full, encoding="utf-8") as f:
            if needle not in f.read():
                return "%s does not contain %r" % (path, needle)
    return None


SKIP_SECTIONS = re.compile(r"(?i)^#+ *(install|license|licen[cs]e / pricing|tests|why|pricing|support|roadmap)\b")


def readme_claims(readme, foreign=()):
    """Things in the README that are claims and must be in the ledger: every top-level bullet
    outside the install/license/tests/background/roadmap sections and outside code blocks
    (identified by its bold lead-in, else its first line), every --option outside those
    sections (minus `foreign` ones that belong to other commands, e.g. pipx's --spec), and
    the exit-code contract."""
    bullets, kept, skipped, fenced = [], [], False, False
    for line in readme.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif line.startswith("#") and not fenced:
            skipped = bool(SKIP_SECTIONS.match(line))
            continue
        if skipped:
            continue
        kept.append(line)
        if fenced or not re.match(r"^[-*] ", line):
            continue
        m = re.match(r"^[-*] \*\*(.+?)\*\*", line)
        bullets.append(m.group(1) if m else line[2:].strip())
    flags = set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", "\n".join(kept))) - set(foreign)
    flags -= {"--", "--user", "--break-system-packages"}
    exit_codes = bool(re.search(r"exit code", readme, re.I))
    return bullets, flags, exit_codes


def main():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    with open(os.path.join(ROOT, "claims.json"), encoding="utf-8") as f:
        ledger = json.load(f)
    nreadme = norm(readme)
    problems, cache, ids = [], {}, set()
    covered_text, covered_flags, exit_ok = [], set(), False
    for c in ledger["claims"]:
        cid = c.get("id", "?")
        if cid in ids:
            problems.append("duplicate claim id %s" % cid)
        ids.add(cid)
        text = c.get("text", "")
        for t in [text] + c.get("also", []):
            if not t or norm(t) not in nreadme:
                problems.append("claim %s: text not found in README.md: %r" % (cid, t))
            covered_text.append(norm(t))
        covered_flags.update(c.get("flags", []))
        if cid == "exit-codes":
            exit_ok = True
        if not c.get("tests"):
            problems.append("claim %s names no test" % cid)
        for ref in c.get("tests", []):
            err = test_exists(ref, cache)
            if err:
                problems.append("claim %s: %s" % (cid, err))
    bullets, flags, exit_codes = readme_claims(readme, ledger.get("foreign_options", []))
    for b in bullets:
        if not any(norm(b) in t or t in norm(b) for t in covered_text if t):
            problems.append("README feature bullet has no ledger entry: %r" % b)
    for fl in sorted(flags - covered_flags):
        problems.append("README option %s has no ledger entry (add it to a claim's \"flags\")" % fl)
    if exit_codes and not exit_ok:
        problems.append("README documents exit codes but the ledger has no 'exit-codes' claim")
    # prose claims every tool README tends to make; each needs its ledger entry
    for pattern, cid in ((r"stdlib|standard library|[Zz]ero dependencies", "stdlib-only"),
                         (r"(?i)no network calls|works entirely offline", "offline"),
                         (r"Python 3\.\d+\+", "python-versions"),
                         (r"(?i)\bpipx install\b", "install-pipx"),
                         (r"(?i)\bbrew install\b", "install-homebrew"),
                         (r"(?i)\bscoop install\b", "install-scoop"),
                         (r"errant\.solutions/downloads/", "install-download"),
                         (r"(?i)SHA256SUMS", "release-assets")):
        if re.search(pattern, readme) and cid not in ids:
            problems.append("README claims %r but the ledger has no %r claim" % (pattern, cid))
    ntests = sum(len(c.get("tests", [])) for c in ledger["claims"])
    for p in problems:
        print("CLAIMS LEDGER: " + p)
    print("CLAIMS SUMMARY: claims=%d test_refs=%d readme_bullets=%d readme_options=%d problems=%d"
          % (len(ledger["claims"]), ntests, len(bullets), len(flags), len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
