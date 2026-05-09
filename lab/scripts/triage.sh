#!/usr/bin/env bash
# Run a harness under ASan, capture the report, and dedupe by crash signature.
#
# Crash signature = ASan error type + top 4 non-libc frames (pruned to function
# names). Two crashes with the same signature go into the same findings/ dir.
#
# Usage:
#   lab/scripts/triage.sh path/to/harness.js [bun args...]
#   lab/scripts/triage.sh path/to/harness.js < some-input
#   TIMEOUT=30 lab/scripts/triage.sh ...      # default 60s
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./env.sh
. "$LAB_ROOT/scripts/env.sh"

if [ $# -lt 1 ]; then
  echo "usage: $0 <harness.js> [bun args...]" >&2
  exit 2
fi

HARNESS="$1"; shift
# Default 30s — generous for a hand-crafted harness, short enough that a wedged
# process (e.g. macOS 26 ASan post-detection wedge) doesn't gate the whole run.
# Set TIMEOUT explicitly for long-running mutation loops: TIMEOUT=300 ...
TIMEOUT="${TIMEOUT:-30}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
OUT_DIR="$LAB_ROOT/findings/runs/$RUN_ID"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/asan.log"

BIN="${BUN_ASAN_BIN}"
if [ ! -x "$BIN" ]; then
  if [ -x "$BUN_DEBUG_BIN" ]; then
    BIN="$BUN_DEBUG_BIN"
    echo "[triage] using debug build (no release-asan binary present)" | tee -a "$LOG"
  else
    echo "error: no ASan binary. Run lab/scripts/build-asan.sh first." >&2
    exit 127
  fi
fi

echo "[triage] run-id=$RUN_ID" | tee -a "$LOG"
echo "[triage] harness=$HARNESS" | tee -a "$LOG"
echo "[triage] bin=$BIN" | tee -a "$LOG"
echo "[triage] timeout=${TIMEOUT}s" | tee -a "$LOG"
echo "[triage] ASAN_OPTIONS=$ASAN_OPTIONS" | tee -a "$LOG"
echo "---" | tee -a "$LOG"

# Run the harness in the background so we can watch the log and kill it early
# if we detect the macOS 26 ASan post-detection wedge (the process never exits
# after sanitizer_procmaps_mac.cpp:272 CHECK fails). Without this, every crash
# would idle for the full timeout.
set +e
"$BIN" "$HARNESS" "$@" >>"$LOG" 2>&1 &
PID=$!

deadline=$(( $(date +%s) + TIMEOUT ))
EXIT=""
while :; do
  if ! kill -0 "$PID" 2>/dev/null; then
    wait "$PID" 2>/dev/null
    EXIT=$?
    break
  fi
  # Wedge detector: ASan printed an ERROR followed by the secondary CHECK ⇒
  # the report is complete and the process is stuck. Give it 0.5s to drain
  # any final lines, then kill.
  if grep -q "ERROR: AddressSanitizer\|UndefinedBehaviorSanitizer:" "$LOG" 2>/dev/null \
     && grep -q "CHECK failed: sanitizer_procmaps_mac" "$LOG" 2>/dev/null; then
    sleep 0.5
    kill -9 "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null
    EXIT=137
    echo "[triage] process wedged post-ASan-report (macOS 26 known bug); killed" | tee -a "$LOG"
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    kill -9 "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null
    EXIT=124
    echo "[triage] timed out after ${TIMEOUT}s; killed" | tee -a "$LOG"
    break
  fi
  sleep 0.2
done
set -e

echo "---" >>"$LOG"
echo "[triage] exit=$EXIT" | tee -a "$LOG"

# Extract crash signature.
# On macOS 26, ASan's post-detection stack walker hits a CHECK failure in
# sanitizer_procmaps_mac.cpp before printing frames (LLVM bug, not fixed in
# 22.1.4). When that happens we still get error type + crashing PC, which we
# fall back to for the signature. See lab/docs/SANITIZERS.md.
SIG=""
if grep -q "AddressSanitizer\|UndefinedBehaviorSanitizer\|SEGV\|runtime error" "$LOG"; then
  TYPE="$(grep -m1 -oE 'ERROR: AddressSanitizer: [a-z-]+|UndefinedBehaviorSanitizer:[^,]*|SEGV[^,]*' "$LOG" | head -1 | tr -d '\r' | tr -s ' ' | head -c 80 || true)"

  # `|| true` matters: under set -euo pipefail an empty grep (no frames at all,
  # which is the macOS 26 ASan case) would kill the script before we can fall
  # back to a frames-less signature.
  FRAMES="$( { grep -E '^\s*#[0-9]+ ' "$LOG" \
    | sed -E 's/^\s*#[0-9]+ +0x[0-9a-f]+ +in +//' \
    | awk -F'(' '{print $1}' \
    | head -4 | tr '\n' '|' ; } || true )"

  if [ -n "$FRAMES" ]; then
    SIG_RAW="$TYPE :: $FRAMES"
  else
    # No frames (macOS 26 secondary CHECK) — key on error type + crashing PC.
    PC="$(grep -m1 -oE 'pc 0x[0-9a-f]+' "$LOG" | head -1 || true)"
    ADDR="$(grep -m1 -oE 'on address 0x[0-9a-f]+' "$LOG" | head -1 || true)"
    SIG_RAW="$TYPE :: nostack :: $PC :: $ADDR"
  fi
  SIG="$(printf '%s' "$SIG_RAW" | shasum | awk '{print substr($1,1,12)}')"
fi

if [ -n "$SIG" ]; then
  CRASH_DIR="$LAB_ROOT/findings/crashes/$SIG"
  mkdir -p "$CRASH_DIR/runs"
  cp "$LOG" "$CRASH_DIR/runs/$RUN_ID.log"
  if [ ! -f "$CRASH_DIR/repro.harness" ]; then
    cp "$HARNESS" "$CRASH_DIR/repro.harness" 2>/dev/null || true
    {
      echo "# Crash $SIG"
      echo
      echo "**First seen:** $RUN_ID"
      echo "**Harness:** $HARNESS"
      echo "**Bun:** $BIN"
      echo
      echo "## Signature"
      echo
      echo '```'
      echo "$TYPE"
      if [ -n "$FRAMES" ]; then
        echo "$FRAMES" | tr '|' '\n'
      else
        echo "(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)"
        [ -n "${PC:-}" ] && echo "$PC"
        [ -n "${ADDR:-}" ] && echo "$ADDR"
      fi
      echo '```'
      echo
      if [ -z "$FRAMES" ]; then
        echo "## Get a real stack"
        echo
        echo "ASan's post-detection stack walker is broken on macOS 26 (LLVM bug)."
        echo "To get function names, attach lldb and re-run the harness:"
        echo
        echo '```sh'
        echo "lab/scripts/triage-lldb.sh '$HARNESS'"
        echo '```'
        echo
      fi
      echo "See \`runs/\` for raw ASan reports."
    } > "$CRASH_DIR/README.md"
    echo "[triage] NEW CRASH: $SIG -> $CRASH_DIR" | tee -a "$LOG"
  else
    NCOUNT="$(ls -1 "$CRASH_DIR/runs/" | wc -l | tr -d ' ')"
    echo "[triage] DUP CRASH: $SIG (seen $NCOUNT times) -> $CRASH_DIR" | tee -a "$LOG"
  fi
  exit 1
fi

echo "[triage] no crash signature found (clean exit or non-sanitizer failure)" | tee -a "$LOG"
exit "$EXIT"
