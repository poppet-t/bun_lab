# fs UAF typed-array callback PC control - 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. This requires attacker-controlled local JS access to
`node:fs`; it is not request-reachable from the hardened CTF service.

## Harness

- `lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js`

The harness uses the async FIFO `fs.read` stale-write primitive against small
detached `ArrayBuffer` backing stores, then sprays typed-array-sized allocations.
`bun:ffi` is used only as a local diagnostic oracle for known pointer values
(`ptr()` / `dlsym()`), not as a service-reachable exploit primitive.

## New result

With `UAF_SIZE=112`, `VIEW_SIZE=128`, `SPRAY_COUNT=8192`, and
`WRITE_OFFSET=16`, writing a chosen 64-bit value into the reclaimed allocation
can become the crashing program counter during later cleanup.

Key logs:

- `lab/findings/runs/20260510T050027Z-67468/asan.log`
  - wrote the `ptr(source)` value
  - ASAN reported `pc 0x60c000048340`, matching the source backing pointer
- `lab/findings/runs/20260510T050246Z-72813/asan.log`
  - wrote `POINTER_OVERRIDE=0x4141414142424242`
  - ASAN reported `pc 0x4141414142424242`

This is a control-sensitive native corruption primitive, not just data-plane
ArrayBuffer length confusion.

## RCE attempt status

The harness can resolve real libc symbols with `dlopen`/`dlsym` and can keep a
NUL-terminated command buffer alive. A direct, non-UAF FFI finalizer control
check confirmed that `toArrayBuffer(ptr(command), 0, len, system)` invokes
`system(command)` on finalization in this local process. That proves the
resolved `system` pointer and command buffer are valid.

However, installing `system` through the UAF-controlled PC-shaped slot did not
execute the marker command:

- `lab/findings/runs/20260510T050734Z-80456/asan.log`
  - single-word `system` attempt
  - no `/private/tmp/bun_lab_uaf_system_proof`
- `lab/findings/runs/20260510T051047Z-85463/asan.log`
  - `PAYLOAD_LAYOUT=callback-command`
  - no marker file
- `lab/findings/runs/20260510T051106Z-86542/asan.log`
  - `PAYLOAD_LAYOUT=callback-zero-command`
  - no marker file
- `lab/findings/runs/20260510T051106Z-86548/asan.log`
  - `PAYLOAD_LAYOUT=callback-command-command`
  - no marker file
- `lab/findings/runs/20260510T052021Z-97841/asan.log`
  - custom offset-0 payload `command,commandLength,callback`
  - no marker file

The repeated failure mode is a `SEGV` reading `0xfffe000000000000`, with a PC
that is not the resolved `system` address. Current interpretation: the corrupted
slot is control-sensitive, but it is not a simple
`JSTypedArrayBytesDeallocator(data, ctx)` callback slot. The remaining blocker
is identifying the exact callsite/ABI, including any function-pointer
authentication or object-shape requirements on this macOS/arm64 build.

## Current boundary

Confirmed:

- fd-controlled bytes can corrupt a pointer-bearing typed-array/JSC allocation
- the corrupted value can reach native PC under the tested reclaim profile
- the harness supports fixed layouts and custom `PAYLOAD_WORDS` for follow-up
  field-layout probes
- offset `16` is an actual indirect call target, not only a crash artifact:
  resolving libc `exit` and writing that address at offset `16` cleanly exited
  before the harness final line (`20260510T053636Z-25899`)
- a locally loaded diagnostic callback can be invoked through the same offset:
  `bun_uaf_marker_callback` from `/tmp/libbun_uaf_marker_callback.dylib`
  created `/tmp/bun_uaf_marker_callback` (`20260510T053900Z-33110`);
  the later stderr-instrumented run records repeated callback invocation in
  the triage log itself (`20260510T054633Z-55057`)
- the diagnostic callback records the call ABI as
  `data=0xfffe000000000000` and a real heap-like `ctx` pointer
  (`20260510T053934Z-35049`, `20260510T054051Z-38483`,
  `20260510T054633Z-55057`)

Not confirmed:

- `system(command)` through the UAF-controlled slot
- arbitrary native read/write
- a stable no-FFI exploit chain
- request-path reachability from `lab/ctf/bun-rce/challenge-server.js`

Next useful work:

- recover a reliable stack/callsite for the controlled-PC crash
- map the reclaimed 112-byte allocation type and field layout
- avoid assuming the slot uses the `ArrayBuffer` finalizer ABI until proven
- find a way to control the first call argument (`x0`) or redirect through a
  real in-process gadget/wrapper that uses the controlled call target with the
  available arguments
- keep CTF verification separate: the current CTF solve is only the local
  static-asset symlink path, not remote RCE

## Follow-up: call-control proof and x0 blocker

Additional harness support was added after the initial controlled-PC result:

- `POINTER_LIBRARY` for resolving a symbol from a local diagnostic dylib
- `TARGET_MODE=ffi-arraybuffer` for testing whether sprayed FFI ArrayBuffer
  finalizers can become the corrupted callback target
- `DETACH_MODE` variants for checking whether the poison first argument depends
  on `ArrayBuffer.transfer(0)`
- `PAYLOAD_LAYOUT=prefix-callback` for testing whether the corrupted allocation
  pointer itself is passed as the first argument

The strongest new proof is local call control:

```sh
clang -dynamiclib -fPIC -O0 -g \
  -o /tmp/libbun_uaf_marker_callback.dylib \
  lab/harnesses/13-arb-rw-probes/native-marker-callback.c

ASAN_OPTIONS=...:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=8 UAF_SIZE=112 VIEW_SIZE=128 SPRAY_COUNT=8192 \
WRITE_OFFSET=16 \
POINTER_LIBRARY=/tmp/libbun_uaf_marker_callback.dylib \
POINTER_SYMBOL=bun_uaf_marker_callback \
PAYLOAD_LAYOUT=single \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js
```

Result: the marker callback was invoked and wrote the marker file. This proves
the corrupted offset can call an attacker-selected loaded native function.

The reason this is still not a clean `system(command)` chain is the call ABI.
The callback receives:

```text
data=0xfffe000000000000
ctx=0x62d0001f82a0
```

`system` uses the first argument, so it attempts to read the poisoned `data`
pointer and crashes before executing the command. Multi-word payload layouts,
prefix-command layouts, `DETACH_MODE=clone`, `DETACH_MODE=transfer-same`, and
`TARGET_MODE=ffi-arraybuffer` did not change `data` away from the poison
sentinel in the tested runs.

This means the current primitive is best described as local native call-control
with a fixed bad first argument. It is RCE-adjacent, but the remaining exploit
work is argument control or a suitable in-process call target/gadget.

## Follow-up: x0 source and JIT caller identification

The marker callback was extended to capture the return address, walk
`_dyld_image_count()` to find the owning image, and dump 96 bytes of caller
code at `ra-64` plus 128 bytes of frame state. Latest run:

- `lab/findings/runs/20260510T060147Z-84691/asan.log`
  - `data=0xfffe000000000000` (`JSC::JSValue::encode(int32_t 0)`,
    matching `NumberTag = 0xfffe000000000000` from
    `bun/src/runtime/ffi/FFI.h:97`)
  - `ctx=0x62d0001f82a0` (real heap pointer, stable across iterations)
  - `ra=0x11e3e885c` with `img=?` and `base=0x0` after iterating every
    `_dyld_get_image_header()` segment, so the caller does not live in any
    dyld-loaded image. It lives in JIT-mmap'd code.

Decoding the four 4-byte AArch64 instructions immediately preceding `ra`
(little-endian per the dump):

```text
ra-16: 49 80 43 f8 -> 0xf8438049 -> LDUR X9,  [X2, #56]
ra-12: 04 00 00 14 -> 0x14000004 -> B    +0x10
ra-8:  30 01 41 f8 -> 0xf8410130 -> LDUR X16, [X9, #16]
ra-4:  00 02 3f d6 -> 0xd63f0200 -> BLR  X16
```

Post-call, the JIT immediately materializes 48-bit pointers via
`MOV X16, #imm; MOVK X16, #imm, LSL #32` pairs, the canonical JSC JIT pattern
for baking heap-resident addresses into compiled code.

Conclusions:

- The corrupted slot is reached by a two-hop load: caller frame uses `X2` as
  a base pointer, loads `X9 = [X2 + 56]`, then loads `X16 = [X9 + 16]` and
  `BLR X16`. So the 112-byte allocation we reclaim is not a "free-form heap
  object"; it is the inner structure referenced from `[X2 + 56]` of a JSC
  inline-cache / JIT-baked container.
- `x0` is a literal `JSValue::encode(int32_t 0)` set by the JIT prologue
  before `BLR X16`. It is not loaded from the corrupted slot. A 56-byte
  `WRITE_OFFSET=0 PAYLOAD_WORDS=...,callback,...` sweep covering offsets
  0..55 confirmed that no offset in our payload alters `data` away from
  `0xfffe000000000000` (`lab/findings/runs/20260510T055613Z-71719/asan.log`,
  `lab/findings/runs/20260510T055920Z-78895/asan.log`).
- Writing past offset ~55 of the corrupted struct breaks an unrelated
  invariant. With a full 112-byte payload of `0xaaaa00000000000N` sentinels,
  Bun crashed at a real native PC (`pc 0x000107d34ad8`) reading
  `0x1555408000020004` before the marker call could fire
  (`lab/findings/runs/20260510T055746Z-74091/asan.log`,
  crash dir `lab/findings/crashes/f15b326e44ef`). So Bun does read fields
  beyond offset 24 of this allocation, but those reads happen in code we
  haven't isolated yet.
- `ctx = 0x62d0001f82a0` (i.e. `x1`) is also not field-controlled by the
  reclaim payload. Its first 64 bytes contain `0xbadbeef0` poison sentinels
  at offsets 32, 48, 56, indicating partial allocator poisoning of the region
  that holds it. Treat `x1` as fixed JIT/JSC-managed state for now.

What this changes about the threat model:

- The primitive is best classified as **PC control through a JIT inline-cache
  stub structure with hard-coded `JSValue::encode(0)` as `x0`**. Direct
  argument injection through the corrupted struct is not viable from this
  callsite.
- To turn this into stable RCE, the next useful work is one of:
  1. find a different IC / cached call shape whose first argument is loaded
     from a controlled field of the same reclaim slot,
  2. find a Bun- or JSC-internal callee whose `f(JSValue 0, JSGlobalObject*)`
     entry path performs an attacker-useful action (e.g. property lookup on
     `globalThis`, `unsafe-eval`, native `system`-like wrapper),
  3. or pivot away from this callsite and turn the existing object-array
     identity bridge / Float64Array overlap / `byteLength` corruption into a
     stronger JS-level primitive (addrof / fakeobj / stable arbitrary R/W).
- For Bun upstream reporting, the disclosure-relevant facts are unchanged:
  local JS with `node:fs` triggers a `BufferSource` lifetime UAF that lets
  attacker-chosen 64-bit values land in a JIT-cached function-pointer slot,
  giving controlled native call-target. Stable RCE is not currently proven.

Repro:

```sh
clang -dynamiclib -fPIC -O0 -g \
  -o /tmp/libbun_uaf_marker_callback.dylib \
  lab/harnesses/13-arb-rw-probes/native-marker-callback.c

ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=45 ITERATIONS=12 UAF_SIZE=112 VIEW_SIZE=128 SPRAY_COUNT=8192 \
WRITE_OFFSET=16 PAYLOAD_LAYOUT=single \
POINTER_LIBRARY=/tmp/libbun_uaf_marker_callback.dylib \
POINTER_SYMBOL=bun_uaf_marker_callback \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js
```

The marker file `/tmp/bun_uaf_marker_callback` will contain `data`, `ctx`,
`ra`, the dyld image lookup result, the 96-byte code dump around `ra`, and a
128-byte frame dump suitable for further reverse-engineering.
