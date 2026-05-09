#!/usr/bin/env bash
# Quick-and-dirty static review: grep for native-code patterns that are
# historically associated with memory corruption in Bun-style projects.
#
# Output is grouped by category and intentionally noisy — the goal is to
# produce a curated review queue, not zero false positives.
#
# Usage:
#   lab/scripts/grep-risky.sh                    # whole src/
#   lab/scripts/grep-risky.sh src/install        # one subdir
#   lab/scripts/grep-risky.sh -c http_parser     # one category
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUN_REPO="${BUN_REPO:-$(cd "$LAB_ROOT/../bun" && pwd)}"

ROOT="${1:-$BUN_REPO/src}"

section() { printf '\n=== %s ===\n' "$1"; }

# Zig: unchecked pointer casts (drop bounds, lifetime, alignment info)
section "Zig @ptrCast / @intToPtr / @alignCast (lifetime/alignment risk)"
grep -RnE '@ptrCast|@intToPtr|@ptrFromInt|@alignCast' "$ROOT" --include='*.zig' 2>/dev/null | head -50 || true

# Zig: manual length math on slices (off-by-one country)
section "Zig slice length arithmetic (slice[..len], slice.ptr + N)"
grep -RnE '\.ptr *\+ *|\.\.\s*[a-zA-Z_]+\s*\+\s*1' "$ROOT" --include='*.zig' 2>/dev/null | head -40 || true

# Zig: explicit @memcpy / @memset with dynamic length
section "Zig @memcpy / @memset on dynamic length (verify bounds)"
grep -RnE '@memcpy\(|@memset\(' "$ROOT" --include='*.zig' 2>/dev/null | head -40 || true

# Zig: untagged unions / undefined values
section "Zig undefined / @as(*,undefined)"
grep -RnE 'undefined,?\s*$|@as\([^)]+,\s*undefined\)' "$ROOT" --include='*.zig' 2>/dev/null | head -30 || true

# C++: reinterpret_cast (type confusion)
section "C++ reinterpret_cast"
grep -RnE 'reinterpret_cast<' "$ROOT" --include='*.cpp' --include='*.cc' --include='*.h' 2>/dev/null | head -40 || true

# C++: hand-rolled memcpy/memmove
section "C++ memcpy / memmove with dynamic length"
grep -RnE 'memcpy\(|memmove\(' "$ROOT" --include='*.cpp' --include='*.cc' --include='*.h' 2>/dev/null | head -40 || true

# C++: alloca / VLA
section "C++ alloca / VLA"
grep -RnE 'alloca\(|alloca_size' "$ROOT" --include='*.cpp' --include='*.cc' --include='*.h' --include='*.zig' 2>/dev/null | head -20 || true

# C++/Zig: integer-to-pointer or unchecked length from JS
section "Length from JSValue / DataView / ArrayBuffer (untrusted)"
grep -RnE 'byteLength|byteOffset|toLength|toUint32|asUInt32|asInt32' "$ROOT" --include='*.cpp' --include='*.cc' --include='*.h' --include='*.zig' 2>/dev/null \
  | grep -vE 'test|spec|fixture' | head -40 || true

# Comments admitting fragility
section "Comments saying 'TODO', 'FIXME', 'unsafe', 'hack' near native code"
grep -RnE '(TODO|FIXME|XXX|HACK|UNSAFE|unsafe)' "$ROOT" \
  --include='*.zig' --include='*.cpp' --include='*.cc' --include='*.h' 2>/dev/null \
  | grep -vE 'test|spec|fixture' \
  | head -30 || true

# Manual ref-counting (UAF risk if a JS callback drops the last ref mid-call)
section "Manual ref counting (ref_count, deref, retain, release)"
grep -RnE '\bref_count\b|\bderef\b|\bretain\b|\brelease\b|incRef|decRef' "$ROOT" \
  --include='*.zig' --include='*.cpp' --include='*.cc' --include='*.h' 2>/dev/null \
  | grep -vE 'test|spec|fixture' \
  | head -40 || true

# Direct call into JS during native operation (re-entrancy → UAF)
section "Direct JSC calls / callbacks while holding native state (re-entrancy)"
grep -RnE 'callJSC|callFunction|JSC::call\(|asyncTask|->call\(|profiledCall' "$ROOT" \
  --include='*.cpp' --include='*.cc' --include='*.h' --include='*.zig' 2>/dev/null \
  | head -40 || true

echo
echo "(end. pipe through 'less', 'fzf', or save & curate)"
