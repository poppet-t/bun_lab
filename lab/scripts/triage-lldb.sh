#!/usr/bin/env bash
# Re-run a harness under lldb so we can get a real stack at the moment of the
# ASan crash, despite ASan's own stack walker being broken on macOS 26.
#
# How: set a breakpoint on __asan::ReportGenericError (the function ASan calls
# the moment it detects a memory bug, BEFORE the broken procmaps walk that
# normally wedges the process). When that breakpoint fires, lldb prints a
# proper backtrace using its own symbolizer, which doesn't share ASan's
# broken Mach VM code path.
#
# Usage:
#   lab/scripts/triage-lldb.sh path/to/harness.js [bun args...]
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./env.sh
. "$LAB_ROOT/scripts/env.sh"

if [ $# -lt 1 ]; then
  echo "usage: $0 <harness.js> [bun args...]" >&2
  exit 2
fi

HARNESS="$1"; shift
BIN="${BUN_ASAN_BIN}"

if ! command -v lldb >/dev/null 2>&1; then
  echo "error: lldb not found on PATH (install Xcode Command Line Tools)" >&2
  exit 127
fi

if [ ! -x "$BIN" ]; then
  echo "error: $BIN not found or not executable" >&2
  exit 127
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCRIPT="$TMP/lldb.cmd"

cat > "$SCRIPT" <<'LLDB'
# Don't load ASan's stack-walking code — we use lldb's instead.
settings set target.process.thread.step-avoid-regexp ^.*sanitizer_.*$

# Break on the function ASan calls *first* on detection, before the broken
# post-detection walk. Names per llvm-project/compiler-rt/lib/asan.
breakpoint set --name __asan::ReportGenericError
breakpoint set --name __asan_report_error
breakpoint set --name __asan::ReportError
breakpoint set --name __ubsan::Diag

# When any of those fires:
breakpoint command add 1 --script-type python << EOF
def hit(frame, bp_loc, dict):
    print("\n=== ASan/UBSan detection — backtrace ===")
    thread = frame.GetThread()
    for i, f in enumerate(thread.frames):
        print("  #%-2d %s" % (i, f))
    print("=== end ===\n")
    return False  # don't auto-continue; user gets an interactive prompt
EOF
breakpoint command add 2 --script-type python --command "thread backtrace all"
breakpoint command add 3 --script-type python --command "thread backtrace all"
breakpoint command add 4 --script-type python --command "thread backtrace all"

run
LLDB

echo "[triage-lldb] launching lldb on $BIN $HARNESS"
echo "[triage-lldb] breakpoints set on ASan/UBSan report functions"
echo "[triage-lldb] when the breakpoint fires, you'll get a backtrace + interactive prompt"
echo

exec lldb -s "$SCRIPT" -- "$BIN" "$HARNESS" "$@"
