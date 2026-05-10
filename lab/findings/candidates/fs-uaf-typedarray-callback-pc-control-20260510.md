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

## Follow-up: full IC stub disassembly identifies a JSC PutByVal cache

The marker dumps were widened to 320 bytes of code (`ra-64..ra+255`) plus
256 bytes of `ctx` heap state. Disassembling the captured JIT bytes (wrapped
into a Mach-O stub with `clang -arch arm64 -c` + `.incbin`, then disassembled
with `llvm-objdump --triple=aarch64-apple-darwin`) yields:

```text
ra-0x40: cmp  w3, w17                ; structure-id check
ra-0x3c: b.ne ra+0x00 (slow path)
ra-0x38: ldur w3, [x2, #0x8]         ; load capacity-or-shape field
ra-0x34: cmp  w3, #0x40
ra-0x30: b.lt ra-0x20
ra-0x2c: ldur x1, [x1, #0x8]         ; storage pointer load
ra-0x28: neg  w3, w3                 ; index normalisation
ra-0x24: sxtw x3, w3
ra-0x20: b    ra-0x18
ra-0x1c: sub  x1, x1, #0x1e0
ra-0x18: add  x17, x1, #0x1f0
ra-0x14: str  x0, [x17, x3, lsl #3]  ; FAST PATH WRITE (legitimate array)
ra-0x10: b    ra+0x00                ; skip slow path on success
ra-0x0c: ldur x9, [x2, #0x38]        ; SLOW PATH: load IC inner struct
ra-0x08: ldur x16, [x9, #0x10]       ; load slow-call function pointer
ra-0x04: blr  x16                    ; ** the indirect call we control **

ra+0x00: mov  x16, #0x668
ra+0x04: movk x16, #0x241, lsl #32   ; X16 = 0x0000_0241_0000_0668
ra+0x08: mov  x17, #0x218
ra+0x0c: movk x17, #0x3b1a, lsl #16  ; (slide-dependent)
ra+0x10: movk x17, #0x1, lsl #32     ; X17 = 0x0000_0001_3b1a_0218
ra+0x14: str  x16, [x17, xzr]        ; *X17 = X16
ra+0x18: mov  x0, #0x82a0
ra+0x1c: movk x0, #0x1f, lsl #16
ra+0x20: movk x0, #0x62d0, lsl #32   ; X0 = 0x0000_62d0_001f_82a0  == ctx
ra+0x24: ldurb w1, [x0, #0x7]        ; read JSCell indexing-type byte
ra+0x28: mov  x17, #0xb50
ra+0x2c: movk x17, #0x3b18, lsl #16
ra+0x30: movk x17, #0x1, lsl #32
ra+0x34: ldr  w16, [x17, xzr]
ra+0x38: cmp  w16, w1
ra+0x3c: b.hs ra+0xe6c                ; deopt branch on bound check
... (subsequent block at +0x9c-0xfc emits BRK #0 with W16=0x113 if the
     IC's invariants are violated, then re-materialises ctx and emits
     `orr x1, xzr, #0xfffe000000000000` followed by another call setup)
```

This identifies the corrupted slot as the **slow-path miss handler of a JSC
JIT'd `PutByVal` (indexed property store) inline cache**. Specifically:

- The IC's fast path (`str x0, [x17, x3, lsl #3]`) is the in-place array
  store. It reads from the legitimate JS array's storage pointer; our UAF
  does not reach that path.
- The IC's slow path is what we hijack. It calls a function pointer at
  `[X9 + 16]` where `X9 = [X2 + 56]` of an outer JSC structure (likely the
  `JITStubInfo` or `PolymorphicAccess` container).
- Post-call code in this same JIT region uses three baked 48-bit
  immediates that decode to JSC heap addresses. Two of them
  (`0x62d0_001f_82a0`, `0x62d0_001f_82b0`) sit in the same partially
  poisoned heap region as our `ctx` parameter, and the surrounding
  `ctx_prefix` shows `0xbadbeef0` poison patterns (`f0 ee db ba 00 00 00 00`
  little-endian) at offsets 32 and 48..255 of `ctx`, with only the first
  32 bytes still containing valid JSC pointers. This means the JIT compiled
  this IC against a JSC heap object that has since been freed/poisoned by
  the allocator — a separate JSC inline-cache freshness condition we do
  not need to chase for this finding.

Implications for `x0`/`x1` controllability:

- `x1 = 0x62d0_001f_82a0` is materialised after the call by the same
  baked constants the JIT used before the call. So `x1` is not field-loaded
  from the corrupted slot at all — it is JIT-baked. We cannot influence it.
- `x0 = 0xfffe_0000_0000_0000` is later re-emitted explicitly in this same
  block via `orr x1, xzr, #0xfffe000000000000` (and the `mov x0, x1` swap
  pattern), confirming the JIT bakes `JSValue::encode(int32_t 0)` directly
  into the IC stub. We cannot influence this either.

So this slow-path callsite has no field-controlled arguments by design.

## Follow-up: UAF_SIZE sweep

Reclaim-size sweep with the same `WRITE_OFFSET=16 PAYLOAD_LAYOUT=single`
setup (12 iterations, 8192 spray, marker callback as call target):

| `UAF_SIZE` | result                                                |
|-----------:|--------------------------------------------------------|
|         64 | clean exit, marker not called (slot uncalled)          |
|         96 | crash (`5879 SEGV pc 0x000106b13dfc`), marker not called |
|        112 | marker called repeatedly with `data=0xfffe000000000000` |
|        128 | crash (`6303 BUS  pc 0x0001123a6864`), marker not called |
|        144 | clean exit, marker not called                          |
|        160 | clean exit, marker not called                          |
|        192 | clean exit, marker not called                          |
|        240 | exit 133, marker not called                            |

Crash dirs added: `lab/findings/crashes/aadd7fc40d48` (UAF_SIZE=96) and
`lab/findings/crashes/5805dff9975b` (UAF_SIZE=128). Both crash inside Bun
native code at real PCs — they are corruption of a non-IC reclaim target,
not call-target control. So 112 is uniquely the `PutByVal`-slow-path slot;
no nearby reclaim size lands in a different IC type with a more useful
calling shape under this harness.

Net status: PC control through this `PutByVal` IC slow-path slot is real
but inert for stable RCE. The next productive directions are unchanged from
the previous section: target a different IC shape (likely needs harness
changes that warm distinct ICs), find a useful in-process callee tolerant
of `(JSValue 0, JIT-baked-ctx)`, or pivot to JS-level primitives building
on the existing object-array identity bridge / Float64Array overlap.
