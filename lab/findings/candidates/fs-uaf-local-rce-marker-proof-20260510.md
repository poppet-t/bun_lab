# fs UAF → controlled native code execution via marker callback (local RCE proof)

Scope: this note consolidates the end-to-end local-RCE-quality proof
already proven by commits `169e764`, `7a07d68`, `378039c`, and the
no-FFI primitive escalation in `212b652`. It explicitly documents the
chain that produces a marker file as a side-effect of the BufferSource
UAF, what is required to reproduce, what is end-to-end demonstrated, and
what is *not* claimed.

## The chain

1. **Local JS triggers async `fs.read` BufferSource UAF.** Standard
   `node:fs` API. Documented in
   `lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js` and the
   advisory.
2. **Controlled native heap write.** The detached BufferSource backing
   store is reclaimed and Bun's read worker writes attacker-chosen bytes
   into the reclaimed allocation. Documented in `e48034d` /
   `ADVISORY.md`. ASan flags this with SEGV addresses whose bytes match
   the JS-supplied payload byte (`0x4343434343434330`,
   `0x157575f57577756b`, `0x19b9ba39b9bbb9af`, …).
3. **Controlled native indirect-call target (with FFI to load the
   marker dylib).** The harness
   `lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js`
   shapes the reclaim into JSC's `PutByVal` JIT inline-cache stub at
   `UAF_SIZE=112 WRITE_OFFSET=16`. Writing an attacker-chosen 64-bit
   value into offset 16 of the reclaimed slot makes JSC's slow-path
   `BLR X16` call into that value when the IC misses. See `378039c` for
   the full disassembly of the IC stub.
4. **Native code executes.** When the planted address is the entry of a
   locally-loaded `bun_uaf_marker_callback` (compiled from
   `lab/harnesses/13-arb-rw-probes/native-marker-callback.c`), JSC's
   slow-path `BLR X16` calls the callback. The callback creates
   `/tmp/bun_uaf_marker_callback` and writes a record of the call.

This is a controlled local native code execution, end-to-end through the
memory-corruption path.

## Reproduction

```sh
clang -dynamiclib -fPIC -O0 -g \
  -o /tmp/libbun_uaf_marker_callback.dylib \
  lab/harnesses/13-arb-rw-probes/native-marker-callback.c

rm -f /tmp/bun_uaf_marker_callback

ASAN_OPTIONS="halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0" \
TIMEOUT=45 ITERATIONS=12 UAF_SIZE=112 VIEW_SIZE=128 SPRAY_COUNT=8192 \
WRITE_OFFSET=16 PAYLOAD_LAYOUT=single \
POINTER_LIBRARY=/tmp/libbun_uaf_marker_callback.dylib \
POINTER_SYMBOL=bun_uaf_marker_callback \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js
```

Expected effect: `/tmp/bun_uaf_marker_callback` is created and contains
records like

```
called data=0xfffe000000000000 ctx=0x62d0001f82a0 ra=0x… img=? base=0x0 off=0x0
ctx_prefix=…
ra_code=…
frame_dump=…
```

The call fires multiple times per run as the IC stub is exercised. The
marker file's existence and timestamp confirm that attacker-loaded native
code ran in-process as a result of the BufferSource UAF.

## Required prerequisites

| Requirement                            | Why                                                        |
|----------------------------------------|------------------------------------------------------------|
| local JS able to call `node:fs.read`   | trigger the UAF                                            |
| local JS able to call `bun:ffi.dlopen` | load the attacker's `bun_uaf_marker_callback` dylib        |
| ability to drop a `.dylib` in `/tmp`   | so dlopen has something to load                            |
| Bun on macOS arm64                     | the IC stub disassembly was identified for this build      |

The FFI dependency is what the disclosure-quality framing is most
careful about. We have proven non-FFI primitives up to and including
controlled native dereference (`fakeobj-from-arbitrary-bits` in
`212b652`), but turning the dereference into a successful call without
an attacker-supplied dylib still needs either arbitrary R/W or a useful
in-process callee tolerant of `(JSValue 0, JIT-baked-ctx)` (see
`fs-uaf-typedarray-callback-pc-control-20260510.md` and
`fs-uaf-fake-cell-layout-mapper-20260510.md`).

For deployments that *do* permit `bun:ffi`, this chain is end-to-end
local code execution from a single JS function that shouldn't be
allowed to do that.

## What this proof demonstrates

* **Memory-corruption-driven control transfer** — the planted byte
  pattern at offset 16 of the reclaimed slot becomes the program
  counter. `7a07d68` demonstrated `libc:exit` (clean process exit) and
  `bun_uaf_marker_callback` (creates `/tmp/bun_uaf_marker_callback`) as
  two distinct callees, proving the call target is fully attacker
  chosen.
* **Bypass of JS object boundary** — Bun's normal API surface does not
  allow user JS to invoke arbitrary native function pointers. This
  chain does, by exploiting the BufferSource UAF rather than going
  through any sanctioned JS-to-native interface.
* **Minimal scaffolding** — once the marker dylib is built (one `clang
  -dynamiclib` invocation), the JS side is a single ~50-line harness
  using only `node:fs`, `bun:ffi.dlopen`/`ptr`, and JS array primitives.

## What this proof does NOT demonstrate

* No `system(command)` chain. The IC stub's slow-path call has its
  first argument JIT-baked to `JSValue::encode(0)`, which is the poison
  sentinel `0xfffe000000000000`. `libc:system` reads that as a string
  pointer and crashes before executing anything (`378039c`).
* No arbitrary native read/write. The `fakeobj-from-arbitrary-bits`
  primitive (`212b652`) and the layout mapper (`f80a803`) show the
  fake-cell route is blocked by JSC's structureID `RELEASE_ASSERT`.
* No remote / request-reachable RCE. The hardened CTF service in this
  repo does not expose the local JS API path required to trigger the
  UAF.
* No ASLR / W^X / PAC bypass. The marker callback runs in pages JSC
  already considers executable; we did not write shellcode.

## Disclosure framing

`lab/findings/cve-disclosure/ADVISORY.md` is intentionally still
conservative; this finding is documented separately and not folded into
the advisory yet, because:

* The most damaging part of the chain (the marker callback running
  attacker C code) requires `bun:ffi` to load the dylib. Reasonable
  Bun deployments may already disable `bun:ffi`, in which case the
  user-facing impact is the no-FFI primitives instead — controlled
  native heap write, controlled native indirect call target, controlled
  native dereference at chosen address.
* If/when we find an in-process callee that is useful with the fixed
  IC ABI (or a way to leak a real `structureID` and complete the
  fake-cell construction), the marker proof becomes FFI-free and
  belongs in the advisory.

Until then this note is the single canonical "we have run attacker
native code through the memory-corruption path" reference for internal
use, and `ADVISORY.md` keeps its conservative scope for upstream
submission.
