#!/usr/bin/env bash
#
# gate_report.sh — reproducible gate-measurement report runner.
#
# Runs the five #[ignore]d gate benchmarks, captures every `GATE-*` line
# they print (verbatim, from stdout), and writes:
#
#   reports/gate-report-<UTC-date>.md    human-readable report
#   reports/gate-report-<UTC-date>.json  machine-readable report
#
# JSON schema (extra fields beyond {name, command, lines} exist so that
# individual failures are machine-recordable too):
#
#   {
#     "generated_utc": "2026-09-24T12:34:56Z",
#     "git_commit": "<sha>" | null,        # null when git / repo absent
#     "git_dirty": true | false | null,
#     "rustc": "rustc 1.98.0 ..." | null,
#     "cpu": "Intel(R) ..." | null,        # /proc/cpuinfo "model name"
#     "benchmarks": [
#       {
#         "name": "gate_a_concolic_speed",
#         "command": "cargo test --release ...",
#         "exit_code": 0,                   # 124 = per-benchmark timeout
#         "duration_s": 74,
#         "lines": ["GATE-A speed: ..."],   # captured verbatim
#         "stderr_tail": ["..."] | null     # last 20 stderr lines on failure
#       }
#     ]
#   }
#
# Benchmarks (debug vs release is deliberate per gate — gate_b footprint is
# measured in the debug build; the speed/preemption gates are release):
#
#   gate_a_concolic_speed    GATE-A  release  ~60 s warm (cold build: minutes)
#   gate_b_footprint         GATE-B  debug    ~30 s warm (10k-state memory)
#   gate_b_solver_migration  GATE-B  debug    seconds warm (depth-500)
#   gate_c_preemption        GATE-C  release  ~20 s warm
#   gate_c_alpha             GATE-C  debug    seconds warm
#
# Per-benchmark timeouts (seconds) — generous to absorb cold builds and
# cargo build-lock waits; a hung run cannot wedge the report. Override via
# environment:
#
#   GATE_TIMEOUT_A=1800
#   GATE_TIMEOUT_B_FOOTPRINT=900
#   GATE_TIMEOUT_B_SOLVER=900
#   GATE_TIMEOUT_C_PREEMPTION=900
#   GATE_TIMEOUT_C_ALPHA=600
#
# Usage:
#   scripts/gate_report.sh [--dry-run] [NAME ...]
#
#     --dry-run   print the commands (and timeouts) that would run; no report
#     NAME ...    run only the named benchmarks (see list above)
#
# Exit status: 0 if at least one benchmark exited 0 (individual failures are
# recorded without aborting the rest); 1 if every benchmark failed; 2 on a
# usage error or when no JSON encoder (jq or python3) is available.
#
# reports/ is intentionally NOT gitignored: gate reports are meant to be
# committed as the reproducible measurement record. Do not add it.
#
# ── Benchmark-sink wiring (angryier-bench) ────────────────────────────────
# Where a GATE line carries the numbers, it maps onto the existing
# `angryier_bench::BenchmarkRecord` sink without any new Rust
# infrastructure. Example — "GATE-B footprint: symbolic 10000 states,
# RSS +115.0 MB (11.5 KB/state), fork cost 130.0 us/state ...":
#
#   BenchmarkRecord {
#       run: RunId(20260924),               // report date; (run, case) unique
#       case: "gate_b_footprint_symbolic",  // one record per gate leg
#       fidelity: FidelityProfile::Prove,   // symbolic leg; Explore for concolic
#       wall_seconds: <fork-cost elapsed>,  // seconds; record() rejects < 0
#       states: 10_000,                     // record() rejects states == 0
#       solver_queries: 0,                  // where the gate carries them
#       coverage_units: 0,
#       replay_verified: true,
#       semantic_verified: true,
#   }
#
# Gate lines that carry rates instead of state counts (GATE-A steps/ms,
# GATE-C queries/s) do not fit the sink's fixed numeric fields — the JSON
# report is the complete record; the sink is for aggregation only.
#
# Requires: cargo on PATH (or set CARGO=...); jq or python3 for the JSON
# report; `timeout` recommended (runs without it if absent, unguarded).

set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
REPORT_DIR=$REPO_ROOT/reports
CARGO=${CARGO:-cargo}
UTC_DATE=$(date -u +%Y-%m-%d)
GENERATED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
MD_PATH=$REPORT_DIR/gate-report-$UTC_DATE.md
JSON_PATH=$REPORT_DIR/gate-report-$UTC_DATE.json
STDERR_TAIL_LINES=20
DRY_RUN=false
SELECTED=()
ALL_NAMES=(
  gate_a_concolic_speed
  gate_b_footprint
  gate_b_solver_migration
  gate_c_preemption
  gate_c_alpha
)

usage() {
  cat <<'EOF'
Usage: scripts/gate_report.sh [--dry-run] [NAME ...]

Runs the five gate benchmarks and writes reports/gate-report-<UTC-date>.{md,json}.

  --dry-run   print the commands that would run (with timeouts); write nothing
  NAME ...    run only the named benchmarks:
                gate_a_concolic_speed   (GATE-A, release, ~60 s warm)
                gate_b_footprint        (GATE-B, debug,   ~30 s warm)
                gate_b_solver_migration (GATE-B, debug,   seconds warm)
                gate_c_preemption       (GATE-C, release, ~20 s warm)
                gate_c_alpha            (GATE-C, debug,   seconds warm)

Per-benchmark timeouts are overridable: GATE_TIMEOUT_A,
GATE_TIMEOUT_B_FOOTPRINT, GATE_TIMEOUT_B_SOLVER, GATE_TIMEOUT_C_PREEMPTION,
GATE_TIMEOUT_C_ALPHA (seconds; defaults 1800/900/900/900/600).

Exit status: 0 if any benchmark succeeded, 1 if all failed, 2 on usage error.
EOF
}

# ── argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --*)
      printf 'error: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      SELECTED+=("$1")
      shift
      ;;
  esac
done

for s in ${SELECTED[@]+"${SELECTED[@]}"}; do
  valid=false
  for n in "${ALL_NAMES[@]}"; do
    if [[ $s == "$n" ]]; then
      valid=true
      break
    fi
  done
  if [[ $valid == false ]]; then
    printf 'error: unknown benchmark: %s\n' "$s" >&2
    usage >&2
    exit 2
  fi
done

name_selected() {
  local target=$1 s
  if [[ ${#SELECTED[@]} -eq 0 ]]; then
    return 0
  fi
  for s in ${SELECTED[@]+"${SELECTED[@]}"}; do
    if [[ $s == "$target" ]]; then
      return 0
    fi
  done
  return 1
}

# ── JSON encoding helpers (jq preferred, python3 fallback) ────────────────

HAVE_JQ=false
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=true
fi
HAVE_PY=false
if command -v python3 >/dev/null 2>&1; then
  HAVE_PY=true
fi

# jstr STRING -> JSON string literal
jstr() {
  if [[ $HAVE_JQ == true ]]; then
    jq -Rn --arg v "$1" '$v'
  else
    python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
  fi
}

# jarr FILE -> JSON array of the file's non-empty lines (verbatim)
jarr() {
  if [[ $HAVE_JQ == true ]]; then
    jq -Rsc 'split("\n") | map(select(length > 0))' <"$1"
  else
    python3 -c 'import json, sys
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    lines = [l for l in f.read().splitlines() if l]
print(json.dumps(lines))' "$1"
  fi
}

if [[ $DRY_RUN != true && $HAVE_JQ != true && $HAVE_PY != true ]]; then
  printf 'error: the JSON report needs jq or python3 on PATH\n' >&2
  exit 2
fi

# ── environment metadata (each probe tolerates absence) ───────────────────

GIT_COMMIT_JSON=null
GIT_DIRTY_JSON=null
GIT_SUMMARY=unavailable
if command -v git >/dev/null 2>&1; then
  commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)
  if [[ -n $commit ]]; then
    GIT_COMMIT_JSON=$(jstr "$commit")
    dirty_line=$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null | head -n 1 || true)
    if [[ -n $dirty_line ]]; then
      GIT_DIRTY_JSON=true
      GIT_SUMMARY="${commit:0:12} (dirty)"
    else
      GIT_DIRTY_JSON=false
      GIT_SUMMARY="${commit:0:12} (clean)"
    fi
  fi
fi

RUSTC_DESC=
if command -v rustc >/dev/null 2>&1; then
  RUSTC_DESC=$(rustc --version 2>/dev/null || true)
fi
RUSTC_JSON=null
if [[ -n $RUSTC_DESC ]]; then
  RUSTC_JSON=$(jstr "$RUSTC_DESC")
fi

CPU_DESC=
if [[ -r /proc/cpuinfo ]]; then
  cpu_line=$(grep -m1 '^model name' /proc/cpuinfo || true)
  CPU_DESC=${cpu_line#*:}
  CPU_DESC=${CPU_DESC#"${CPU_DESC%%[![:space:]]*}"} # left-trim
fi
CPU_JSON=null
if [[ -n $CPU_DESC ]]; then
  CPU_JSON=$(jstr "$CPU_DESC")
fi

# ── benchmark runner ──────────────────────────────────────────────────────

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

RAN_NAMES=()

TIMEOUT_CMD=(timeout --foreground)
if ! command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD=()
  printf 'warning: timeout(1) not found — benchmarks run unguarded\n' >&2
fi

# run_bench NAME TIMEOUT_S CMD... — runs one benchmark, records exit code,
# duration, verbatim GATE- stdout lines, and a stderr tail for failures.
run_bench() {
  local name=$1 timeout_s=$2
  shift 2
  local cmd_str
  cmd_str="${*}"
  local out_file=$TMP_DIR/$name.stdout
  local err_file=$TMP_DIR/$name.stderr
  local lines_file=$TMP_DIR/$name.gate_lines
  local tail_file=$TMP_DIR/$name.stderr_tail
  local start=$SECONDS code duration line_count

  if [[ $DRY_RUN == true ]]; then
    printf '[dry-run] %s (timeout %ss): %s\n' "$name" "$timeout_s" "$cmd_str"
    return
  fi

  printf '==> %s (timeout %ss)\n' "$name" "$timeout_s"
  set +e
  if [[ ${#TIMEOUT_CMD[@]} -gt 0 ]]; then
    "${TIMEOUT_CMD[@]}" "$timeout_s" "$@" >"$out_file" 2>"$err_file"
  else
    "$@" >"$out_file" 2>"$err_file"
  fi
  code=$?
  set -e
  duration=$((SECONDS - start))

  grep '^GATE-' "$out_file" >"$lines_file" || true
  tail -n "$STDERR_TAIL_LINES" "$err_file" >"$tail_file" || true

  RAN_NAMES+=("$name")
  printf '%s\n' "$code" >"$TMP_DIR/$name.exit_code"
  printf '%s\n' "$duration" >"$TMP_DIR/$name.duration"
  printf '%s\n' "$cmd_str" >"$TMP_DIR/$name.command"

  line_count=$(wc -l <"$lines_file" | tr -d '[:space:]')
  if [[ $code -eq 124 ]]; then
    printf '    timed out after %ss (exit 124); partial GATE lines: %s\n' "$timeout_s" "$line_count"
  elif [[ $code -ne 0 ]]; then
    printf '    FAILED exit %s in %ss; see report for stderr tail\n' "$code" "$duration"
  else
    printf '    exit 0 in %ss; GATE lines: %s\n' "$duration" "$line_count"
    if [[ $line_count -eq 0 ]]; then
      printf '    warning: benchmark passed but printed no GATE- lines (skipped fixture?)\n'
    fi
  fi
}

if name_selected gate_a_concolic_speed; then
  run_bench gate_a_concolic_speed "${GATE_TIMEOUT_A:-1800}" \
    "$CARGO" test --release -p angryier-runtime --features xed --test concolic_speed -- --ignored --nocapture
fi
if name_selected gate_b_footprint; then
  run_bench gate_b_footprint "${GATE_TIMEOUT_B_FOOTPRINT:-900}" \
    "$CARGO" test -p angryier-runtime --features xed --test gate_b -- --ignored --nocapture
fi
if name_selected gate_b_solver_migration; then
  run_bench gate_b_solver_migration "${GATE_TIMEOUT_B_SOLVER:-900}" \
    "$CARGO" test -p angryier-solver-z3-ffi --test migration_bench -- --ignored --nocapture
fi
if name_selected gate_c_preemption; then
  run_bench gate_c_preemption "${GATE_TIMEOUT_C_PREEMPTION:-900}" \
    "$CARGO" test --release -p angryier-solver-z3-ffi --test preemption_bench -- --ignored --nocapture
fi
if name_selected gate_c_alpha; then
  run_bench gate_c_alpha "${GATE_TIMEOUT_C_ALPHA:-600}" \
    "$CARGO" test -p angryier-solver -- --ignored --nocapture
fi

if [[ $DRY_RUN == true ]]; then
  printf '[dry-run] would write %s\n' "$MD_PATH"
  printf '[dry-run] would write %s\n' "$JSON_PATH"
  printf '[dry-run] note: reports/ is intentionally committable (not gitignored)\n'
  exit 0
fi

if [[ ${#RAN_NAMES[@]} -eq 0 ]]; then
  printf 'error: no benchmarks ran\n' >&2
  exit 2
fi

# ── machine-readable report ───────────────────────────────────────────────

benches_jsonl=$TMP_DIR/benches.jsonl
: >"$benches_jsonl"
for name in "${RAN_NAMES[@]}"; do
  code=$(<"$TMP_DIR/$name.exit_code")
  duration=$(<"$TMP_DIR/$name.duration")
  cmd_str=$(<"$TMP_DIR/$name.command")
  lines_json=$(jarr "$TMP_DIR/$name.gate_lines")
  tail_json=null
  if [[ $code -ne 0 && -s $TMP_DIR/$name.stderr_tail ]]; then
    tail_json=$(jarr "$TMP_DIR/$name.stderr_tail")
  fi
  printf '{"name": %s, "command": %s, "exit_code": %s, "duration_s": %s, "lines": %s, "stderr_tail": %s}\n' \
    "$(jstr "$name")" "$(jstr "$cmd_str")" "$code" "$duration" "$lines_json" "$tail_json" \
    >>"$benches_jsonl"
done

if [[ $HAVE_JQ == true ]]; then
  benchmarks_json=$(jq -sc '.' "$benches_jsonl")
else
  benchmarks_json=$(python3 -c 'import json, sys
objs = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
print(json.dumps(objs))' "$benches_jsonl")
fi

mkdir -p "$REPORT_DIR"
{
  printf '{\n'
  printf '  "generated_utc": %s,\n' "$(jstr "$GENERATED_UTC")"
  printf '  "git_commit": %s,\n' "$GIT_COMMIT_JSON"
  printf '  "git_dirty": %s,\n' "$GIT_DIRTY_JSON"
  printf '  "rustc": %s,\n' "$RUSTC_JSON"
  printf '  "cpu": %s,\n' "$CPU_JSON"
  printf '  "benchmarks": %s\n' "$benchmarks_json"
  printf '}\n'
} >"$JSON_PATH"

# ── human-readable report ─────────────────────────────────────────────────

{
  printf '# Gate measurement report — %s\n\n' "$UTC_DATE"
  printf -- '- Generated (UTC): %s\n' "$GENERATED_UTC"
  printf -- '- Git: %s\n' "$GIT_SUMMARY"
  printf -- '- rustc: %s\n' "${RUSTC_DESC:-unavailable}"
  printf -- '- CPU: %s\n' "${CPU_DESC:-unavailable}"
  printf -- '- Runner: scripts/gate_report.sh (GATE- lines captured verbatim from stdout)\n'
  printf '\n'
  for name in "${RAN_NAMES[@]}"; do
    code=$(<"$TMP_DIR/$name.exit_code")
    duration=$(<"$TMP_DIR/$name.duration")
    cmd_str=$(<"$TMP_DIR/$name.command")
    printf '## %s\n\n' "$name"
    printf '%s\n\n' "Command: \`$cmd_str\`"
    printf 'Exit: %s, duration %s s\n\n' "$code" "$duration"
    if [[ -s $TMP_DIR/$name.gate_lines ]]; then
      printf '```text\n'
      cat "$TMP_DIR/$name.gate_lines"
      printf '```\n\n'
    else
      printf '(no GATE- lines captured — benchmark skipped its fixture or produced no measurements)\n\n'
    fi
    if [[ $code -ne 0 && -s $TMP_DIR/$name.stderr_tail ]]; then
      printf 'stderr tail (last %s lines):\n\n' "$STDERR_TAIL_LINES"
      printf '```text\n'
      cat "$TMP_DIR/$name.stderr_tail"
      printf '```\n\n'
    fi
  done
} >"$MD_PATH"

# ── summary and exit status ───────────────────────────────────────────────

total=${#RAN_NAMES[@]}
failed=0
for name in "${RAN_NAMES[@]}"; do
  code=$(<"$TMP_DIR/$name.exit_code")
  if [[ $code -ne 0 ]]; then
    failed=$((failed + 1))
  fi
done

printf 'wrote %s\n' "$MD_PATH"
printf 'wrote %s\n' "$JSON_PATH"
printf 'benchmarks: %s run, %s failed\n' "$total" "$failed"
printf 'note: reports/ is intentionally committable — gate reports are the reproducible measurement record; it is not gitignored\n'

if [[ $failed -ge $total ]]; then
  exit 1
fi
exit 0
