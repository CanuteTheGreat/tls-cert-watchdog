#!/bin/sh
# Mutation testing (mutmut) inside a throwaway, resource-capped python container,
# same isolation as ci/run-tests.sh. Every mutant mutmut makes in the tool is a
# small bug (flipped comparison, changed constant, dropped call...); a mutant the
# test suite does not catch ("survived") is behaviour no test checks.
#
# Two modes (chosen by ci/mutation-incremental.py plan in nightly.yml, env MUT_MODE):
#   full         every mutant; fails when the score drops below ci/mutation-min-score. That
#                number only ever goes up: raise it when you add tests, never lower it to get
#                CI green. Weekly, on the repo's own weekday (nightly.yml).
#   incremental  only the mutants of functions changed since the last green run (MUT_DIFF), plus
#                the functions whose tests changed; fails on any NEW surviving mutant there (one
#                the last full run did not already list). The other nights.
# Unset MUT_MODE (a hand run) = full.
#
#   ci/mutation.sh               # python 3.13
#   ci/mutation.sh 3.13 report   # also print every surviving mutant's diff
#
# tests/conftest.py makes the suite's `subprocess.run([sys.executable, TOOL, ...])`
# calls run the mutated tool in-process while mutmut drives pytest, so mutmut can
# see which test exercises which function (unittest ignores conftest.py).
set -eu
# Mutation testing runs only on the colo host (rw-man-01, `runs-on: colo-x86_64`): rw-man-02..05
# are EC2 instances under GuardDuty, which flags mutated code as malware (2026-10-17). Refuse on
# EC2 whether called from CI or by hand (DMI is visible inside containers too).
# Opt-in since 2026-10-18 (owner: the colo backlog was too big; GuardDuty suppression kept, all
# rw-man-01..05 may run mutation/chaos again): refuses only when CI_COLO_ONLY=1 is set, so setting
# that one variable (workflow env or runner envs:) re-enables the colo-only rule.
if [ "${CI_COLO_ONLY:-0}" = 1 ] && [ "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)" = "Amazon EC2" ]; then
  echo "mutation testing refused: this is an EC2 host; run it on the colo lane (rw-man-01)" >&2
  exit 1
fi
PY="${1:-3.13}"
REPORT="${2:-}"
IMAGE="python:$PY-bookworm"
REPO="$(basename "$(pwd)")"
NAME="mut-${REPO}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
MIN=$(cat ci/mutation-min-score)
MODE="${MUT_MODE:-full}"
MUT_ID="${MUT_ID:-$REPO}"
# the diff, relative to the repo root (it is copied into the container with the checkout)
DIFF=""
[ "$MODE" = incremental ] && DIFF=".mutation-baseline/$MUT_ID/diff.patch"
# parallel mutant runs; a repo whose suite is memory-hungry (e.g. moto) pins fewer in ci/mutation-children
CHILDREN=$(cat ci/mutation-children 2>/dev/null || echo 3)
MEMORY=$(cat ci/mutation-memory 2>/dev/null || echo 3g)
# a repo whose every mutant needs a slow end-to-end suite tests a fixed 1-in-N sample of its mutants
# (chosen by a hash of the mutant name, so the same mutants every night and the score stays comparable)
SAMPLE=$(cat ci/mutation-sample 2>/dev/null || echo 1)
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# the container must outlive the job's timeout-minutes (the trap removes it): a 2 h lifetime
# killed slow runs on the shared colo lane with exit 137 (aws-waste-finder, 2026-10-18)
# --cpus matches CHILDREN (one pytest per child) and the shared lane's 3-CPU EC2 slots (rw-man-02..05).
# shellcheck disable=SC2086
docker run -d --name "$NAME" --memory "$MEMORY" --memory-swap "$MEMORY" --cpus 3 --pids-limit 2048 \
  ${EXTRA_DOCKER_ARGS:-} "$IMAGE" sleep 14400 >/dev/null
docker cp . "$NAME:/src"
rc=0
docker exec -w /src -e MIN="$MIN" -e REPORT="$REPORT" -e CHILDREN="$CHILDREN" -e SAMPLE="$SAMPLE" \
  -e MODE="$MODE" -e DIFF="$DIFF" -e MUT_ID="$MUT_ID" "$NAME" sh -ec '
  # the checkout belongs to the runner uid; mutmut and the gate read git history
  git config --global --add safe.directory "*"
  if [ -x ci/setup.sh ]; then ci/setup.sh; fi
  pip install -q --disable-pip-version-check --root-user-action=ignore "mutmut==3.8.0" "pytest>=8" >/dev/null
  rm -rf mutants
  NAMES=""
  if [ "$MODE" = incremental ] || [ "$SAMPLE" -gt 1 ]; then
    # generate the mutants and the test->function map (a filter that matches nothing stops
    # mutmut right after that), then pick the mutants to run
    mutmut run "__generate_only__" > /tmp/mutmut-gen.log 2>&1 || true
  fi
  if [ "$MODE" = incremental ]; then
    NAMES=$(python3 ci/mutation-incremental.py mutmut-targets --diff "$DIFF" --mutants mutants --sample "$SAMPLE")
    if [ -z "$NAMES" ]; then
      echo "MUTATION: no mutants in the code changed since the last green run"
      python3 ci/mutation-incremental.py gate --id "$MUT_ID" --kind mutmut --mode incremental --allow-empty -- mutants
      exit 0
    fi
    echo "MUTATION INCREMENTAL: $(echo $NAMES | wc -w) mutants of the changed code"
  elif [ "$SAMPLE" -gt 1 ]; then
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
  if [ "$MODE" = full ]; then
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
  fi
  mutmut results 2>/dev/null | grep -E ": (survived|no tests|suspicious)" | sed "s/^ */SURVIVOR /" || true
  if [ -n "$REPORT" ]; then
    for m in $(mutmut results 2>/dev/null | sed -n "s/^ *\([^:]*\): survived/\1/p"); do mutmut show "$m"; done
  fi
  # full: record this run as the new baseline; incremental: fail on new survivors
  if [ $rc = 0 ]; then
    python3 ci/mutation-incremental.py gate --id "$MUT_ID" --kind mutmut --mode "$MODE" -- mutants || rc=1
  fi
  exit $rc
' || rc=$?
# the new baseline (nightly.yml caches .mutation-baseline when the job succeeds)
if [ $rc = 0 ]; then
  mkdir -p .mutation-baseline
  docker cp "$NAME:/src/.mutation-baseline/$MUT_ID" .mutation-baseline/ 2>/dev/null || true
fi
exit $rc
