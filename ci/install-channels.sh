#!/bin/sh
# Install this tool through every channel the README documents that can run on Linux CI, the
# way a user does, in a throwaway resource-capped container with nothing preinstalled, and run
# the installed command:
#   1. pipx from the Forgejo git URL (default branch)      -> --version == __version__ on main
#   2. pipx from the Forgejo git URL pinned to the latest release tag -> --version == that tag
#   3. the latest Forgejo release: every asset matches SHA256SUMS, the wheel installs and runs
#   4. the single-file download from https://errant.solutions/downloads/ runs on a bare python
#      and is byte-identical to this repo's default-branch file
# Homebrew and Scoop are exercised by the homebrew-errant-tools / scoop-errant-tools repos' CI.
#
#   ci/install-channels.sh [python-version]
set -eu
PY="${1:-3.13}"
REPO=$(sed -n 's/^name = "\(.*\)"/\1/p' pyproject.toml | head -1)   # == the Forgejo repo name
CMD=$(sed -n '/^\[project.scripts\]/{n;s/ =.*//p;}' pyproject.toml)
VPATH=$(sed -n '/^\[tool.hatch.version\]/{n;s/^path = "\(.*\)"/\1/p;}' pyproject.toml)
NAME="inst-${REPO}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker run -d --name "$NAME" --memory 1g --memory-swap 1g --cpus 2 --pids-limit 512 \
  "python:$PY-bookworm" sleep 1800 >/dev/null
# extra packages the README says the single-file download needs (e.g. boto3), installed the way a user would
DEPS=$(cat ci/download-deps 2>/dev/null || true)
docker exec -e REPO="$REPO" -e CMD="$CMD" -e VPATH="$VPATH" -e DEPS="$DEPS" "$NAME" sh -ec '
  FORGEJO=https://git.canutethegreat.com
  API=$FORGEJO/api/v1/repos/CanuteTheGreat/$REPO
  fetch() { for i in 1 2 3 4 5; do curl -fsSL --retry 3 "$@" && return 0; sleep 5; done; return 1; }
  MAIN=$(fetch "$API" | python -c "import json,sys; print(json.load(sys.stdin)[\"default_branch\"])")
  WANT=$(fetch "$FORGEJO/CanuteTheGreat/$REPO/raw/branch/$MAIN/$VPATH" | sed -n "s/^__version__ = \"\(.*\)\"/\1/p")
  TAG=$(fetch "$API/releases/latest" | python -c "import json,sys; print(json.load(sys.stdin)[\"tag_name\"])")
  echo "repo=$REPO command=$CMD default-branch=$MAIN version=$WANT latest-release=$TAG"
  pip install -q --disable-pip-version-check --root-user-action=ignore pipx
  export PIPX_HOME=/tmp/pipx PIPX_BIN_DIR=/tmp/pipx-bin PATH=/tmp/pipx-bin:$PATH

  pipx install -q "git+$FORGEJO/CanuteTheGreat/$REPO.git"
  OUT=$($CMD --version); echo "pipx (default branch): $OUT"
  [ "$OUT" = "$CMD $WANT" ] || { echo "CHANNEL FAILED: pipx default branch printed \"$OUT\", want \"$CMD $WANT\""; exit 1; }
  $CMD --help >/dev/null
  pipx uninstall -q "$REPO" >/dev/null

  pipx install -q "git+$FORGEJO/CanuteTheGreat/$REPO.git@$TAG"
  OUT=$($CMD --version); echo "pipx ($TAG): $OUT"
  [ "$OUT" = "$CMD ${TAG#v}" ] || { echo "CHANNEL FAILED: pipx @$TAG printed \"$OUT\""; exit 1; }
  pipx uninstall -q "$REPO" >/dev/null

  mkdir -p /tmp/rel && cd /tmp/rel
  fetch "$API/releases/latest" | python -c "import json,sys
for a in json.load(sys.stdin)[\"assets\"]: print(a[\"name\"], a[\"browser_download_url\"])" > assets.txt
  while read -r n u; do fetch -o "$n" "$u"; done < assets.txt
  sha256sum -c SHA256SUMS
  [ "$(grep -c . SHA256SUMS)" -ge 3 ] || { echo "CHANNEL FAILED: SHA256SUMS lists fewer than 3 files"; exit 1; }
  python -m venv /tmp/whl && /tmp/whl/bin/pip install -q --disable-pip-version-check ./*.whl
  OUT=$(/tmp/whl/bin/$CMD --version); echo "release wheel: $OUT"
  [ "$OUT" = "$CMD ${TAG#v}" ] || { echo "CHANNEL FAILED: release wheel printed \"$OUT\""; exit 1; }
  echo "release assets: $(wc -l < assets.txt) files, SHA256SUMS verified"

  FILE=$(basename "$VPATH")
  cd /tmp && fetch -o "dl-$FILE" "https://errant.solutions/downloads/$FILE"
  fetch -o "repo-$FILE" "$FORGEJO/CanuteTheGreat/$REPO/raw/branch/$MAIN/$VPATH"
  cmp "dl-$FILE" "repo-$FILE" || { echo "CHANNEL FAILED: errant.solutions/downloads/$FILE differs from $MAIN"; exit 1; }
  DLPY=python
  if [ -n "$DEPS" ]; then
    # without them the tool must name what is missing (not a traceback), then work once installed
    if python -I "dl-$FILE" --help > dl-nodeps.txt 2>&1; then echo "CHANNEL FAILED: --help ran without $DEPS"; exit 1; fi
    if ! grep -q "$(echo "$DEPS" | head -1 | cut -d" " -f1)" dl-nodeps.txt || grep -q Traceback dl-nodeps.txt; then
      echo "CHANNEL FAILED: no friendly message without $DEPS"; cat dl-nodeps.txt; exit 1; fi
    echo "direct download without $(echo $DEPS): $(head -1 dl-nodeps.txt)"
    python -m venv /tmp/dl && /tmp/dl/bin/pip install -q --disable-pip-version-check $DEPS && DLPY=/tmp/dl/bin/python
  fi
  OUT=$($DLPY -I "dl-$FILE" --version); echo "direct download: $OUT"
  [ "$OUT" = "$CMD $WANT" ] || { echo "CHANNEL FAILED: download printed \"$OUT\""; exit 1; }
  $DLPY -I "dl-$FILE" --help >/dev/null
  echo "INSTALL CHANNELS OK: pipx(main) pipx($TAG) release-assets direct-download"
'
