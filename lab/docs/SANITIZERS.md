# Sanitizers — what catches what

Bun's `release-asan` and `debug` profiles enable a stack of compile-time
instrumentation. This doc is a quick reference for which class of bug each
sanitizer catches, what it misses, and how to tune the runtime options for
specific hunts.

## What each sanitizer catches

| Sanitizer | Bug class | Notes |
| --- | --- | --- |
| **AddressSanitizer (ASan)** | heap-buffer-overflow, stack-buffer-overflow, use-after-free, use-after-return, use-after-scope, double-free, invalid-free, alloc-dealloc-mismatch, container-overflow | Compile flag: `-fsanitize=address`. ~2× slowdown, 2-4× memory. The ASan build is `bun-asan` in `build/release-asan/`. |
| **UndefinedBehaviorSanitizer (UBSan)** | null deref, OOB array index, signed integer overflow, return without value, nullability violations, unreachable, function-type mismatch | Bun's build sets `-fno-sanitize-recover=all`, so first hit aborts. See `bun/scripts/build/flags.ts` for the exact UBSan checks enabled. |
| **LeakSanitizer (LSan)** | memory leaks at exit | Off by default in `lab/scripts/env.sh`; flip `detect_leaks=1` and source `bun/test/leaksan.supp` (already wired) to surface only new leaks. |
| **ThreadSanitizer (TSan)** | data races, deadlocks | **Not currently part of Bun's default profiles.** TSan and ASan are mutually exclusive. To use it, you'd need a custom profile; see Bun's `scripts/build/flags.ts`. |
| **MemorySanitizer (MSan)** | reads of uninitialized memory | Same exclusivity as TSan. Not part of standard Bun profiles. |

## What sanitizers do not catch

ASan/UBSan are about **memory safety** — they don't help with:

- **Logic bugs** — auth bypass, sandbox escape, prototype pollution, JIT
  type-confusion (the JIT might write valid memory to the wrong place)
- **Untriggered code paths** — sanitizers only trip on code that runs.
  Combine with **Fuzzilli** (see `FUZZILLI.md`) for coverage-guided
  exploration.
- **Cooperative misuse of safe APIs** — calling C with the wrong types via
  `bun:ffi` is not a bug; the binding layer mishandling a correctly-typed
  call is.
- **Side-channel leaks** — timing oracles, cache-side-channel.
- **Stack overflows** with unbounded recursion (UBSan's `unreachable` may
  catch some cases, but a deep recursion that runs the stack out is just a
  segfault).

## Tuning runtime options (set in `lab/scripts/env.sh`)

`ASAN_OPTIONS` (colon-separated key=value):

| Key | We set | Why |
| --- | --- | --- |
| `abort_on_error` | 1 | SIGABRT on error so debuggers / cores attach cleanly |
| `halt_on_error` | 1 | First hit aborts. Set to 0 only when you want to enumerate non-fatal classes |
| `detect_leaks` | 0 | Leaks dominate signal; flip to 1 for leak hunts |
| `detect_stack_use_after_return` | 1 | Catches local-escape bugs (closures over stack) |
| `strict_string_checks` | 1 | strncpy / strchr OOB |
| `check_initialization_order` | 1 | Global init UB |
| `detect_invalid_pointer_pairs` | 2 | `<` between pointers from different allocations |
| `fast_unwind_on_fatal` | 0 | Slow but full stack — we want this for triage |
| `malloc_context_size` | 64 | Deep alloc-stack history (helps UAF root cause) |
| `allocator_may_return_null` | 0 | Abort on OOM rather than silently NULL |

`UBSAN_OPTIONS`:

| Key | We set | Why |
| --- | --- | --- |
| `print_stacktrace` | 1 | UBSan default is no stack — useless for triage |
| `halt_on_error` | 1 | Match the build's `-fno-sanitize-recover=all` |
| `report_error_type` | 1 | Group dedupe by error type |

## Bun-specific runtime hardening

Set globally in `env.sh`:

- `BUN_DESTRUCT_VM_ON_EXIT=1` — tear down JSC at exit. Drives finalizers,
  exposes UAF that only surfaces during shutdown.
- `BUN_JSC_validateExceptionChecks=1` + `BUN_JSC_dumpSimulatedThrows=1` —
  catches missing exception scope in C++ glue. A missed scope is often the
  *cause* of a later UAF (an exception leaks past a code path that holds a
  raw pointer to GC memory).

## macOS 26 caveats (Darwin 25 / Tahoe)

Two LLVM-side bugs affect ASan on this OS. The lab works around both, but
the workflow has rough edges you should know about.

### 1. libc++ ABI mismatch (link-time)

WebKit's prebuilt `libJavaScriptCore.a` references `std::__1::__hash_memory`
as an exported symbol. Newer libc++ marks it `_LIBCPP_HIDE_FROM_ABI` and
drops the export, so `bun-asan` fails its smoke test with:

```
dyld: Symbol not found: __ZNSt3__113__hash_memoryEPKvm
```

**Fix:** a re-export shim is already in
`bun/src/jsc/bindings/workaround-missing-symbols.cpp` (search for
`__hash_memory`). Remove that block when WebKit prebuilt rebases against
modern libc++.

### 2. ASan runtime + macOS 26 Mach VM (run-time)

ASan's `task_info(TASK_DYLD_INFO)` calls return -1 on macOS 26, hitting
internal `CHECK_EQ(res, 0)` failures in
`compiler-rt/lib/sanitizer_common/sanitizer_procmaps_mac.cpp`. There are
two distinct sites:

| Line | When it fires | Effect |
| --- | --- | --- |
| 214 | ASan init (before any user code) | Process never starts |
| 272 | ASan post-detection report | Bug is detected, but stack walk wedges the process |

Bun's existing `asan-dyld-shim.dylib` (already linked into `bun-asan`)
fixes the deadlock at LLVM #182943, but **not** these two `task_info`
CHECKs. Apple Clang 21.x bundles an older sanitizer runtime that hits both;
**Homebrew `llvm@22` (22.1.4) has the init-time fix but not the
post-detection one.**

The lab uses Homebrew `llvm@22`'s ASan runtime — `install_name_tool` swaps
`bun-asan`'s linkage from clang 21 to clang 22 — so init works.
Post-detection the process wedges; `triage.sh` watches the log for the
secondary CHECK and SIGKILLs it within ~0.5 s of bug detection. You get:

- ✅ The error type (`heap-buffer-overflow`, `use-after-free`, etc.)
- ✅ The faulting program counter (`pc 0x...`)
- ✅ The faulting address (`on address 0x...`)
- ❌ No symbolic stack trace from ASan itself

For symbolic frames, use the lldb workflow:

```sh
lab/scripts/triage-lldb.sh path/to/repro.js
```

`triage-lldb.sh` sets a breakpoint on `__asan::ReportGenericError` —
ASan's first call on detection, *before* the broken procmaps walk. lldb's
own stack walker doesn't share that broken code, so you get full frames.

### When the upstream LLVM fix lands

The whole macOS 26 mess goes away when LLVM 22.1.x picks up Mach VM
compatibility for Tahoe. Watch:

- LLVM #182943 — deadlock fix (already in 22.1.4)
- The two `task_info` CHECKs — track via `git log` of
  `compiler-rt/lib/sanitizer_common/sanitizer_procmaps_mac.cpp`

Once Homebrew's `llvm@22` ships a build with both, undo the
`install_name_tool` swap (or just rebuild — `bun run build:asan` will pick
up the new toolchain naturally).

## Verifying your build is actually instrumented

```sh
nm "$BUN_ASAN_BIN" | grep -c __asan_init   # >0 → ASan linked
nm "$BUN_ASAN_BIN" | grep -c __ubsan_handle # >0 → UBSan linked
"$BUN_ASAN_BIN" --version                    # should print bun version
lab/scripts/triage.sh lab/harnesses/00-canary/heap-overflow.js
# expected: ASan reports heap-buffer-overflow → triage.sh prints NEW CRASH
```

If the canary doesn't trip, **stop hunting** — you'll get false negatives
on every harness until the build is fixed.
