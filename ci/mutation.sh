#!/bin/sh
# Mutation testing (mutmut) inside a throwaway, resource-capped python container,
# same isolation as ci/run-tests.sh. Every mutant mutmut makes in the tool is a
# small bug (flipped comparison, changed constant, dropped call...); a mutant the
# test suite does not catch ("survived") is behaviour no test checks.
#
# Fails when the score drops below ci/mutation-min-score. That number only ever
# goes up: raise it when you add tests, never lower it to get CI green.
#
#   ci/mutation.sh               # python 3.13
#   ci/mutation.sh 3.13 report   # also print every surviving mutant's diff
#
# tests/conftest.py makes the suite's `subprocess.run([sys.executable, TOOL, ...])`
# calls run the mutated tool in-process while mutmut drives pytest, so mutmut can
# see which test exercises which function (unittest ignores conftest.py).
set -eu
PY="${1:-3.13}"
REPORT="${2:-}"
IMAGE="python:$PY-bookworm"
REPO="$(basename "$(pwd)")"
NAME="mut-${REPO}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
MIN=$(cat ci/mutation-min-score)
# parallel mutant runs; a repo whose suite is memory-hungry (e.g. moto) pins fewer in ci/mutation-children
CHILDREN=$(cat ci/mutation-children 2>/dev/null || echo 4)
MEMORY=$(cat ci/mutation-memory 2>/dev/null || echo 3g)
# a repo whose every mutant needs a slow end-to-end suite tests a fixed 1-in-N sample of its mutants
# (chosen by a hash of the mutant name, so the same mutants every night and the score stays comparable)
SAMPLE=$(cat ci/mutation-sample 2>/dev/null || echo 1)
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# shellcheck disable=SC2086
docker run -d --name "$NAME" --memory "$MEMORY" --memory-swap "$MEMORY" --cpus 4 --pids-limit 2048 \
  ${EXTRA_DOCKER_ARGS:-} "$IMAGE" sleep 7200 >/dev/null
docker cp . "$NAME:/src"
docker exec -w /src -e MIN="$MIN" -e REPORT="$REPORT" -e CHILDREN="$CHILDREN" -e SAMPLE="$SAMPLE" "$NAME" sh -ec '
  if [ -x ci/setup.sh ]; then ci/setup.sh; fi
  pip install -q --disable-pip-version-check --root-user-action=ignore "mutmut==3.8.0" "pytest>=8" >/dev/null
  rm -rf mutants
  NAMES=""
  if [ "$SAMPLE" -gt 1 ]; then
    # generate the mutants (a filter that matches nothing stops mutmut right after that), then pick the sample
    mutmut run "__generate_only__" > /tmp/mutmut-gen.log 2>&1 || true
    NAMES=$(python - <<EOF
import glob, json, os, zlib
keys = sorted(k for p in glob.glob("mutants/**/*.meta", recursive=True)
              for k in json.load(open(p)).get("exit_code_by_key", {}))
pick = [k for k in keys if zlib.crc32(k.encode()) % int(os.environ["SAMPLE"]) == 0]
print(" ".join(pick))
EOF
)
    [ -n "$NAMES" ] || { echo "no mutants generated"; tail -c 4000 /tmp/mutmut-gen.log; exit 1; }
    echo "MUTATION SAMPLE: 1 in $SAMPLE -> $(echo $NAMES | wc -w) mutants"
  fi
  # shellcheck disable=SC2086
  mutmut run --max-children "$CHILDREN" $NAMES > /tmp/mutmut.log 2>&1 || { tail -c 4000 /tmp/mutmut.log; exit 1; }
  mutmut export-cicd-stats >/dev/null
  rc=0
  python - <<EOF || rc=1
import json, os, sys
s = json.load(open("mutants/mutmut-cicd-stats.json"))
caught = s["killed"] + s["timeout"] + s["segfault"]
judged = caught + s["survived"] + s["no_tests"] + s["suspicious"]
score = 100.0 * caught / judged if judged else 0.0
print("MUTATION SUMMARY: total=%d killed=%d timeout=%d survived=%d no_tests=%d suspicious=%d skipped=%d"
      % (s["total"], s["killed"], s["timeout"], s["survived"], s["no_tests"], s["suspicious"], s["skipped"]))
print("MUTATION SCORE: %.2f%% (minimum %s%%)" % (score, os.environ["MIN"]))
open("/tmp/score", "w").write("%.2f" % score)
sys.exit(0 if score + 1e-9 >= float(os.environ["MIN"]) else 1)
EOF
  mutmut results 2>/dev/null | grep -E ": (survived|no tests|suspicious)" | sed "s/^ */SURVIVOR /" || true
  if [ -n "$REPORT" ]; then
    for m in $(mutmut results 2>/dev/null | sed -n "s/^ *\([^:]*\): survived/\1/p"); do mutmut show "$m"; done
  fi
  exit $rc
'
