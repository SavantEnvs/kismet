#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Kismet's own assertion programs (test/btle_tracker, test/cell_decisions, test/linuxwifi_channels), built
# by mayhem/build.sh with normal flags. Each prints a fixed success line only after all its checks held, so
# a binary that merely exits 0 (or prints nothing) fails here.
T="$SRC/mayhem/out/test"
passed=0 failed=0

run_case() {  # <name> <binary> <expected success-line regex>
  local name="$1" bin="$2" want="$3" out rc
  if [ ! -x "$bin" ]; then echo "FAIL $name: $bin missing (build.sh did not produce it)"; failed=$((failed+1)); return; fi
  out=$("$bin" 2>&1); rc=$?
  if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -Eq "$want"; then
    echo "PASS $name: $(printf '%s\n' "$out" | grep -E "$want" | tail -1)"; passed=$((passed+1))
  else
    echo "FAIL $name (rc=$rc):"; printf '%s\n' "$out" | tail -15; failed=$((failed+1))
  fi
}

run_case btle_tracker_decoders "$T/btle_tracker_test" '^btle_tracker decoder: all tests passed$'
run_case cell_decisions "$T/cell_decisions_test" '^all cell decision tests passed$'
run_case linux_freq_to_chan "$T/freq_to_chan_test" '^ok: [1-9][0-9]* frequencies, 0 failed$'

emit_ctrf "kismet-unit" "$passed" "$failed" 0
