#!/usr/bin/env bash
# Run a JS file (or any bun command) under the ASan-instrumented binary
# with the lab's standard sanitizer environment.
#
# Usage:
#   lab/scripts/run-asan.sh path/to/file.js [args...]
#   lab/scripts/run-asan.sh -- -e 'console.log(Bun.version)'
#   BUN_ASAN_BIN=/path/to/bun-asan lab/scripts/run-asan.sh ...
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./env.sh
. "$LAB_ROOT/scripts/env.sh"

if [ ! -x "$BUN_ASAN_BIN" ]; then
  if [ -x "$BUN_DEBUG_BIN" ]; then
    echo "[run-asan] release-asan binary missing, falling back to debug build" >&2
    BUN_ASAN_BIN="$BUN_DEBUG_BIN"
  else
    echo "error: no ASan-instrumented bun found." >&2
    echo "       expected: $BUN_ASAN_BIN" >&2
    echo "       run: $LAB_ROOT/scripts/build-asan.sh" >&2
    exit 127
  fi
fi

# `--` separates lab args from bun args. Anything after `--` is passed straight.
exec "$BUN_ASAN_BIN" "$@"
