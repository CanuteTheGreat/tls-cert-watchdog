#!/usr/bin/env python3
"""Publish a Forgejo release for the pushed tag (run by .forgejo/workflows/release.yml).

Steps, all of which must pass or the job fails:
  1. the tag (vX.Y.Z) must equal the tool's __version__ and have a CHANGELOG.md section
  2. build the sdist + wheel in a throwaway, resource-capped python container
  3. install the wheel into a fresh venv there and check `<command> --version` prints X.Y.Z
     and `<command> --help` exits 0
  4. write SHA256SUMS for the standalone script, the wheel and the sdist
  5. create (or update) the Forgejo release with the changelog section as notes and
     upload every file + SHA256SUMS as release assets, then download each asset back
     and re-check its hash
  6. if a PYPI_API_TOKEN secret is configured, upload the same wheel + sdist to PyPI

Stdlib only; talks to the Forgejo API with the job's automatic token.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(*cmd, capture=False, check=True):
    print("+ " + " ".join(cmd), flush=True)
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE if capture else None)
    if check and p.returncode != 0:
        sys.exit("command failed (%d): %s" % (p.returncode, " ".join(cmd)))
    return p.stdout if capture else p.returncode


def pyproject():
    with open(os.path.join(ROOT, "pyproject.toml")) as f:
        text = f.read()
    name = re.search(r'^name = "([^"]+)"', text, re.M).group(1)
    script = re.search(r'^\[project\.scripts\]\n([\w-]+) = "([\w]+):main"', text, re.M)
    vpath = re.search(r'^\[tool\.hatch\.version\]\npath = "([^"]+)"', text, re.M).group(1)
    return name, script.group(1), vpath


def module_version(path):
    with open(os.path.join(ROOT, path)) as f:
        m = re.search(r'^__version__ = "([^"]+)"', f.read(), re.M)
    return m.group(1) if m else None


def changelog_section(version):
    with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
        text = f.read()
    m = re.search(r"^## \[?%s\]?[^\n]*\n(.*?)(?=^## |\Z)" % re.escape(version), text, re.M | re.S)
    if not m or not m.group(1).strip():
        sys.exit("CHANGELOG.md has no non-empty section for %s" % version)
    return m.group(1).strip()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


class Api:
    def __init__(self):
        self.base = os.environ.get("GITHUB_SERVER_URL", "https://git.canutethegreat.com").rstrip("/")
        self.repo = os.environ["GITHUB_REPOSITORY"]
        self.token = os.environ.get("FORGEJO_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            sys.exit("no FORGEJO_TOKEN/GITHUB_TOKEN in the environment")

    def call(self, method, path, body=None, data=None, ctype="application/json", raw=False):
        url = path if path.startswith("http") else "%s/api/v1/repos/%s%s" % (self.base, self.repo, path)
        if body is not None:
            data = json.dumps(body).encode()
        last = None
        for attempt in range(5):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", "token " + self.token)
            if data is not None:
                req.add_header("Content-Type", ctype)
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    out = r.read()
                    return out if raw else (json.loads(out) if out else None)
            except urllib.error.HTTPError as e:
                if e.code == 404 and method == "GET":
                    return None
                if e.code < 500:
                    sys.exit("%s %s -> %d %s" % (method, url, e.code, e.read()[:500]))
                last = e
            except (urllib.error.URLError, OSError) as e:
                last = e
            time.sleep(3 * (attempt + 1))
        sys.exit("%s %s failed: %s" % (method, url, last))

    def upload(self, release_id, path):
        name = os.path.basename(path)
        boundary = "----errant-release-%d" % int(time.time() * 1000)
        with open(path, "rb") as f:
            payload = f.read()
        body = (("--%s\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"%s\"\r\n"
                 "Content-Type: application/octet-stream\r\n\r\n" % (boundary, name)).encode()
                + payload + ("\r\n--%s--\r\n" % boundary).encode())
        return self.call("POST", "/releases/%d/assets?name=%s" % (release_id, name), data=body,
                         ctype="multipart/form-data; boundary=" + boundary)


def build_in_container(command, version, py="3.13"):
    name = "release-%s-%s-%d" % (os.path.basename(ROOT), os.environ.get("GITHUB_RUN_ID", "local"), os.getpid())
    sh("docker", "run", "-d", "--name", name, "--memory", "1g", "--cpus", "2", "--pids-limit", "512",
       "python:%s-bookworm" % py, "sleep", "1200")
    try:
        sh("docker", "cp", ".", name + ":/src")
        script = """set -e
cd /src && rm -rf dist build
python -m pip install -q --upgrade pip build twine
python -m build --sdist --wheel --outdir dist .
python -m twine check dist/*
python -m venv /tmp/v && /tmp/v/bin/pip install -q dist/*.whl
out=$(/tmp/v/bin/{cmd} --version); echo "$out"
case "$out" in *" {ver}"*) ;; *) echo "--version printed '$out', expected {ver}"; exit 1;; esac
/tmp/v/bin/{cmd} --help > /dev/null
echo "wheel installs and runs: OK"
""".format(cmd=command, ver=version)
        sh("docker", "exec", name, "sh", "-c", script)
        sh("rm", "-rf", "dist")
        sh("docker", "cp", name + ":/src/dist", "dist")
        token = os.environ.get("PYPI_API_TOKEN", "")
        if token:
            sh("docker", "exec", "-e", "TWINE_USERNAME=__token__", "-e", "TWINE_PASSWORD=" + token, name,
               "sh", "-c", "cd /src && python -m twine upload --skip-existing --non-interactive dist/*")
            print("published to PyPI")
        else:
            print("PYPI_API_TOKEN not configured: skipping the PyPI upload (Forgejo release only)")
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], stdout=subprocess.DEVNULL)


def main():
    tag = os.environ.get("GITHUB_REF_NAME") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not re.match(r"^v\d+\.\d+\.\d+$", tag):
        sys.exit("not a release tag: %r" % tag)
    version = tag[1:]
    dist_name, command, vpath = pyproject()
    mv = module_version(vpath)
    if mv != version:
        sys.exit("tag %s but %s has __version__ = %r" % (tag, vpath, mv))
    notes = changelog_section(version)

    build_in_container(command, version)
    files = sorted(os.path.join(ROOT, "dist", f) for f in os.listdir(os.path.join(ROOT, "dist")))
    files.insert(0, os.path.join(ROOT, vpath))
    sums = {os.path.basename(f): sha256(f) for f in files}
    sums_path = os.path.join(ROOT, "dist", "SHA256SUMS")
    with open(sums_path, "w") as f:
        for n, h in sums.items():
            f.write("%s  %s\n" % (h, n))
    print(open(sums_path).read())

    repo_url = "%s/%s" % (os.environ.get("GITHUB_SERVER_URL", "https://git.canutethegreat.com").rstrip("/"),
                          os.environ["GITHUB_REPOSITORY"])
    body = "%s\n\n### Install\n\n```sh\npipx install git+%s.git@%s\n# or the wheel attached to this release:\n" \
           "pipx install %s/releases/download/%s/%s\n# or the single file (stdlib-only Python %s):\n" \
           "curl -fsSLO %s/releases/download/%s/%s\n```\n\n### SHA-256\n\n```\n%s```\n" % (
               notes, repo_url, tag, repo_url, tag,
               next(n for n in sums if n.endswith(".whl")), "3", repo_url, tag, os.path.basename(vpath),
               open(sums_path).read())

    api = Api()
    rel = api.call("GET", "/releases/tags/" + tag)
    if rel:
        rel = api.call("PATCH", "/releases/%d" % rel["id"], {"name": "%s %s" % (dist_name, tag), "body": body})
        for a in rel.get("assets") or []:
            api.call("DELETE", "/releases/%d/assets/%d" % (rel["id"], a["id"]))
    else:
        rel = api.call("POST", "/releases", {"tag_name": tag, "name": "%s %s" % (dist_name, tag), "body": body,
                                             "draft": False, "prerelease": False})
    for f in files + [sums_path]:
        api.upload(rel["id"], f)
    # read every asset back and verify it byte-for-byte against SHA256SUMS
    rel = api.call("GET", "/releases/%d" % rel["id"])
    got = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    want = set(sums) | {"SHA256SUMS"}
    if set(got) != want:
        sys.exit("release assets %s != expected %s" % (sorted(got), sorted(want)))
    for n, h in sums.items():
        data = api.call("GET", got[n], raw=True)
        if hashlib.sha256(data).hexdigest() != h:
            sys.exit("asset %s does not match its SHA256SUMS entry" % n)
    print("release %s published with %d verified assets: %s" % (tag, len(got), rel["html_url"]))


if __name__ == "__main__":
    main()
