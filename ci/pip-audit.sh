#!/bin/sh
# pip-audit.sh: blocking dependency-vulnerability gate. Installs the package exactly as a user does
# (`pip install .` into a fresh venv, so every runtime dependency resolves to what a user would get
# today) and runs pip-audit (PyPI advisory database) over that environment. Any known
# vulnerability, or an audit that cannot run, exits non-zero. Runs in a throwaway capped container;
# the same command works on any host with docker.
#
#   ci/pip-audit.sh [python-version]      (default 3.13)
#
# A finding that cannot be fixed by an upgrade yet is recorded, with a reason, in ci/pip-audit-ignore
# (one advisory id per line, `#` comments); an entry is a deliberate, reviewed decision.
set -eu
PY="${1:-3.13}"
REPO="$(basename "$(pwd)")"
NAME="audit-${REPO}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker run -d --name "$NAME" --memory 1g --cpus 2 --pids-limit 512 "python:$PY-bookworm" sleep 900 >/dev/null
docker cp . "$NAME:/src"
docker exec -w /src "$NAME" sh -ec '
  python -m venv /tmp/target
  /tmp/target/bin/pip install -q --disable-pip-version-check --upgrade pip
  /tmp/target/bin/pip install -q --disable-pip-version-check /src
  if [ -s ci/download-deps ]; then
    # extra packages the single-file download needs (what a user installs next to the file)
    /tmp/target/bin/pip install -q --disable-pip-version-check $(grep -v "^#" ci/download-deps)
  fi
  # the tool itself is not on PyPI: audit its dependency closure, not the tool
  PKG=$(sed -n "s/^name = \"\(.*\)\"/\1/p" pyproject.toml | head -1)
  /tmp/target/bin/pip uninstall -q -y "$PKG"
  /tmp/target/bin/pip list --format=freeze
  python -m venv /tmp/auditor
  /tmp/auditor/bin/pip install -q --disable-pip-version-check pip-audit
  IGN=""
  if [ -f ci/pip-audit-ignore ]; then
    for id in $(sed "s/#.*//" ci/pip-audit-ignore); do IGN="$IGN --ignore-vuln $id"; done
  fi
  SP=$(/tmp/target/bin/python -c "import sysconfig;print(sysconfig.get_paths()[\"purelib\"])")
  /tmp/auditor/bin/pip-audit --path "$SP" --progress-spinner off --strict $IGN
  echo "PIP-AUDIT: no known vulnerabilities in the installed package set"
'
