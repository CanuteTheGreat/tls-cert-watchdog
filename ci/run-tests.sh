#!/bin/sh
# Run this repo's unit/integration tests inside a throwaway, resource-capped
# python:<version>-bookworm (or python:<version>-<distro>) container (Forgejo CI runs this; the same command
# works on any host with docker). Fails if any test errors, fails OR is
# skipped -- a skipped test is an untested feature.
#
#   ci/run-tests.sh 3.13
#   EXTRA_DOCKER_ARGS="-v /var/run/docker.sock:/var/run/docker.sock" ci/run-tests.sh 3.13
set -eu
PY="${1:?usage: ci/run-tests.sh <python-version>[-<debian>]}"
case "$PY" in *-*) IMAGE="python:$PY" ;; *) IMAGE="python:$PY-bookworm" ;; esac
REPO="$(basename "$(pwd)")"
NAME="ci-${REPO}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-py${PY}-$$"
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# shellcheck disable=SC2086
docker run -d --name "$NAME" --memory 1g --cpus 2 --pids-limit 512 \
  ${EXTRA_DOCKER_ARGS:-} "$IMAGE" sleep 1800 >/dev/null
docker cp . "$NAME:/src"
docker exec -w /src "$NAME" sh -ec '
  if [ -x ci/setup.sh ]; then ci/setup.sh; fi
  python --version
  python - <<EOF
import sys, unittest
suite = unittest.defaultTestLoader.discover("tests")
r = unittest.TextTestRunner(verbosity=2).run(suite)
print("TEST SUMMARY: ran=%d failures=%d errors=%d skipped=%d" % (r.testsRun, len(r.failures), len(r.errors), len(r.skipped)))
sys.exit(0 if r.wasSuccessful() and not r.skipped and r.testsRun > 0 else 1)
EOF
'
