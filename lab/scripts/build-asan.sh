#!/usr/bin/env bash
# Build bun with AddressSanitizer + UBSan + assertions.
# Profile: release-asan (Release codegen + ASAN + assertions). This matches
# what Bun's upstream CI uses for sanitizer runs.
#
# First run will fetch zig + prebuilt WebKit + BoringSSL etc. (~5-10 GB) and
# compile for ~30-60 minutes on an M-series Mac. Subsequent builds are
# incremental (~1-5 min for typical edits).
#
# Usage:
#   lab/scripts/build-asan.sh                # release-asan (recommended)
#   lab/scripts/build-asan.sh debug          # debug profile (ASan default-on, full debug symbols)
#   lab/scripts/build-asan.sh fuzzilli       # debug + Fuzzilli coverage instrumentation
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUN_REPO="$(cd "$LAB_ROOT/../bun" && pwd)"
PROFILE="${1:-release-asan}"

if ! command -v bun >/dev/null 2>&1; then
  echo "error: bun not found on PATH. Install with:" >&2
  echo "  curl -fsSL https://bun.sh/install | bash" >&2
  exit 127
fi

echo "[build-asan] profile=$PROFILE bun=$(command -v bun) repo=$BUN_REPO"

cd "$BUN_REPO"

# Make sure deps are up to date (idempotent, fast after first run).
bun install --frozen-lockfile

case "$PROFILE" in
  release-asan)
    bun run build:asan
    BIN="$BUN_REPO/build/release-asan/bun-asan"
    ;;
  debug)
    bun bd
    BIN="$BUN_REPO/build/debug/bun-debug"
    ;;
  debug-no-asan)
    bun run build:debug:noasan
    BIN="$BUN_REPO/build/debug/bun-debug"
    ;;
  fuzzilli)
    bun run build:debug:fuzzilli
    BIN="$BUN_REPO/build/debug-fuzz/bun-debug"
    ;;
  *)
    echo "error: unknown profile '$PROFILE'" >&2
    echo "       valid: release-asan | debug | debug-no-asan | fuzzilli" >&2
    exit 2
    ;;
esac

mkdir -p "$LAB_ROOT/build"
ln -sf "$BIN" "$LAB_ROOT/build/bun-current"

echo
echo "[build-asan] OK"
echo "[build-asan] binary: $BIN"
echo "[build-asan] symlink: $LAB_ROOT/build/bun-current -> $BIN"
echo
echo "Verify it's instrumented:"
echo "  nm '$BIN' | grep -c __asan        # >0 means ASan is linked"
echo "  '$BIN' --version"
echo
echo "Smoke-test against the canary harness:"
echo "  $LAB_ROOT/scripts/triage.sh $LAB_ROOT/harnesses/00-canary/heap-overflow.js"
