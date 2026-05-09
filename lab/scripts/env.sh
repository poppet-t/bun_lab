# shellcheck shell=bash
# Common ASan / UBSan / leak settings sourced by other lab scripts.
# Tuned to maximise signal without drowning in noise from JSC's pre-existing
# leak suppressions (see ../../bun/test/leaksan.supp).

LAB_ROOT="${LAB_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BUN_REPO="${BUN_REPO:-$(cd "$LAB_ROOT/../bun" && pwd)}"

# ── ASAN ────────────────────────────────────────────────────────────────────
# abort_on_error=1     — SIGABRT on first hit so we get a real core/stack
# halt_on_error=1      — same but for non-fatal classes (UAF after delete)
# detect_leaks=0       — leaks dominate signal; flip to 1 only when hunting them
# detect_stack_use_after_return=1 — catches local-escape bugs
# strict_string_checks=1 — strncpy/strchr OOB
# check_initialization_order=1 — global init order UB
# detect_invalid_pointer_pairs=2 — cmp of pointers from different allocs
# fast_unwind_on_fatal=0 — slower but full backtrace (we want this for triage)
# malloc_context_size=64 — deep alloc backtrace for UAF root cause
# allocator_may_return_null=0 — abort on OOM rather than silently return NULL
# log_path=stderr — keep stderr; triage.sh redirects to per-run files
# abort_on_error=1 + the macOS 26 secondary CHECK in sanitizer_procmaps_mac.cpp
# wedge the process during ASan's post-detection report. Use exitcode=66
# (non-zero, distinguishable from the harness's own exit codes) so we get a
# fast process death after the bug is detected. The crash report still goes
# to stderr first; we lose the in-process stack walk to LLVM bug, not
# correctness. See lab/docs/SANITIZERS.md.
export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0}"

# ── UBSAN ───────────────────────────────────────────────────────────────────
# print_stacktrace=1 — UBSan default is no stack; we want it
# halt_on_error=1   — first hit aborts (matches -fno-sanitize-recover=all)
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1:report_error_type=1}"

# ── LSAN (only used when detect_leaks=1) ────────────────────────────────────
export LSAN_OPTIONS="${LSAN_OPTIONS:-malloc_context_size=100:print_suppressions=1:suppressions=$BUN_REPO/test/leaksan.supp}"

# ── Bun runtime hardening for testing ───────────────────────────────────────
# These environment variables increase signal:
export BUN_DESTRUCT_VM_ON_EXIT=1            # tear down JSC VM on exit (drives finalizers, exposes UAF)
export BUN_JSC_validateExceptionChecks=1    # catches missing exception scope checks (logic→memory bugs)
export BUN_JSC_dumpSimulatedThrows=1
export BUN_DEBUG_QUIET_LOGS=1               # silence routine debug logs

# Symbolizer (Apple clang ships its own; system 'atos' works as fallback)
if [ -z "${ASAN_SYMBOLIZER_PATH-}" ]; then
  if command -v llvm-symbolizer >/dev/null 2>&1; then
    export ASAN_SYMBOLIZER_PATH="$(command -v llvm-symbolizer)"
  fi
fi

# Build artifact paths
export BUN_ASAN_BIN="${BUN_ASAN_BIN:-$BUN_REPO/build/release-asan/bun-asan}"
export BUN_DEBUG_BIN="${BUN_DEBUG_BIN:-$BUN_REPO/build/debug/bun-debug}"
