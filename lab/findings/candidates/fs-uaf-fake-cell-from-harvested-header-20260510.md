# fs UAF fake cell from harvested header — past the structureID block

Date: 2026-05-10

Scope: extends the no-FFI cell-prefix harvest in commit `e81a274` and the
`fakeobj-from-arbitrary-bits` primitive in `212b652`. No `bun:ffi`, no
native helper dylib, no symbol enumeration, no JIT warming, no remote
service.

## Headline

Using a freshly-harvested real cell header as the body of a fake cell
**bypasses the structureID `RELEASE_ASSERT`** documented in `f80a803`.
JSC accepts the planted cell, walks past the +5 type-byte read, and
crashes only at a *later* validation reading inside the Gigacage
region where our fake bytes live. This unblocks the gating problem in
`f80a803` and is the first concrete step toward layout-independent
fakeobj.

## Harness

`lab/harnesses/13-arb-rw-probes/fake-cell-from-harvested-header-probe.js`

End-to-end pipeline in one process:

1. Build the no-FFI two-stage `addrof` → ArrayBuffer-metadata bridge
   (same machinery as `cb38d3c` and `e81a274`).
2. `addrof(donor)` for a real plain object; bridge-read its first 32
   bytes (the donor's JSCell header + butterfly + first inline slot).
3. Allocate a `BigUint64Array(8)` (raw 64-byte data, no NaN-boxing) and
   copy the donor's 32-byte prefix verbatim into the typed-array data.
4. `addrof(fakeCellBuf)` then bridge-read its JSCell to recover its
   `m_vector` field at offset 16. That is the address of the bytes we
   just wrote.
5. Plant `m_vector` as `fakeobj-from-arbitrary-bits` payload using the
   same plant primitive as `212b652` (8 KB BufferSource UAF, sentinel
   spray, write 8 bytes at offset 144).
6. Read the planted slot in JS to force JSC to interpret the bytes as
   a `JSCell*`.

If JSC's structureID `RELEASE_ASSERT` passes, the plant survives and
JSC continues into secondary validation. If we are still blocked, the
process aborts at `BRK` before any secondary read.

## Validation

Command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=300 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/fake-cell-from-harvested-header-probe.js
```

Run: `lab/findings/runs/20260510T093506Z-48570/asan.log`
Crash: `lab/findings/crashes/585986f15890/`

Trace:

```text
{"phase":"start"}
{"phase":"victim-addrof","victimAddr":"0x000060f000010558"}
{"phase":"stage1","attempt":3,"bridgeIndex":1}
{"phase":"metadata-addr","metadataAddr":"0x000060c000041bc0"}
{"phase":"stage2","attempt":0,"bridgeIndex":1}
{"phase":"donor-addrof","donorAddr":"0x000062d0000356a0"}
{"phase":"donor-prefix","bytes":"606f0300002200000000000000000000f0272200d06200000000000000000000"}
{"phase":"fakecell-copied","bytes":"606f0300002200000000000000000000f0272200d06200000000000000000000"}
{"phase":"fakecellbuf-addrof","cellAddr":"0x0000610000002ac8"}
{"phase":"fakecellbuf-prefix","bytes":"f0cb0000003c080078c12000d062000000bb0100606000000800000000000000"}
{"phase":"fake-bytes-addr","fakeBytesAddr":"0x000060600001bb00"}
{"phase":"planting","bits":"0x000060600001bb00"}
{"phase":"planted","arrayIndex":3}
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x606000018008
       at pc 0x000107348644
READ of size 8 at 0x606000018008
```

Parsed donor header (from the `donor-prefix` bytes):

* structureID: `0x00036f60` (per-VM, fresh in this process)
* indexingType: `0`
* m_type: `34` (FinalObjectType)
* flags: `0`
* cellState: `0`

Parsed `fakeCellBuf` cell (from `fakecellbuf-prefix`):

* structureID: `0x0000cbf0` (BigUint64Array — matches the harvest in `e81a274`)
* m_type: `60` (BigUint64ArrayType)
* m_vector at offset 16: `0x000060600001bb00`
* m_length at offset 24: `0x08` (8 elements)

## What changed

* `212b652` `fakeobj-from-arbitrary-bits` with `0x00007fffdeadbef0`
  produced `SEGV at 0x7fffdeadbef5` — the **+5 read** of the cell type
  byte. The structureID `RELEASE_ASSERT` did not get a chance to fire
  (the +5 SEGV happened first in the unmapped page). When we tried
  cell-shaped *mapped* bytes whose structureID did not match a real
  StructureIDTable entry, JSC instead aborted via `BRK`/`RELEASE_ASSERT`
  (`f80a803`).
* This run plants `0x000060600001bb00` — a *mapped, typed-array-data*
  pointer. The bytes there are the donor's real header. JSC's +5 read
  succeeds (m_type=34 is `FinalObjectType`). The structureID lookup
  succeeds because `0x00036f60` is a live entry in this process's
  `StructureIDTable`. The plant survives the planting check
  (`arrayIndex=3` reported before any abort). The crash that follows is
  ASan flagging a *separate* read of `0x606000018008` in the Gigacage
  region — i.e. a JSC integrity / heap-membership read on the fake
  cell's surroundings, not the structureID assertion.

This is the first time in this lab session that the planted JSCell
pointer has produced a non-`BRK` post-validation crash. The
`f80a803` block is no longer the gate.

## Boundaries

* No standalone `arbitrary native R/W` yet. Surviving the structureID
  block is necessary but not sufficient; we still need the post-plant
  cell access to complete cleanly. The next concrete step is to
  reshape the fake cell so JSC's secondary integrity check on
  `0x606000018008` (likely a heap-membership probe over the Gigacage)
  does not fault. Two avenues to try:
  1. Place the fake cell bytes in JSC's general IsoSubspace heap
     instead of Gigacage. That requires a different controlled-byte
     allocation; e.g., write through the proven ArrayBuffer-metadata
     write into a chosen IsoSubspace slot.
  2. Forge the donor's butterfly / inline-slot bytes so the read at
     `+0x8008` lands in valid memory (or so JSC takes a shorter code
     path and never reads there).
* No FFI was used. No native helper dylib. No JIT warming. No remote
  trigger.
* The advisory in `lab/findings/cve-disclosure/ADVISORY.md` is
  intentionally **not** updated. This finding only confirms one more
  rung is reached; it does not by itself increase user-facing impact.

## Why this matters for the chain

The progression of the fake-cell route is now:

1. `212b652` — fakeobj-from-arbitrary-bits crashes at planted+5
   (unmapped). Not yet a useful primitive.
2. `f80a803` — fakeobj-from-arbitrary-bits with mapped but invalid
   structureID aborts at `BRK` / `RELEASE_ASSERT`.
3. `e81a274` — wide-table harvest of real `(structureID, m_type, …)`
   per template. Closes the validation gap.
4. **This finding** — fake cell with harvested header bytes survives
   the structureID `RELEASE_ASSERT` and reaches a *post-validation*
   secondary read. The gate that blocked us in `f80a803` is now
   demonstrably crossed.
5. *Next* — make the post-validation read land in mapped memory the
   fake cell controls, after which the fake cell reaches its
   secondary fields (butterfly, m_vector, m_length, etc.) and a
   fake-Uint8Array constructed there is the standard arb-R/W payload.

## Side-effect note

The harness produces a final ASan crash because the planted fake cell
is read while ASan still has Gigacage redzones on. This is a *probe
artifact*, not a stability failure of the primitive: the JSON trace
through the `phase: "planted"` line is authoritative and shows the
plant landed. In a non-ASan production binary, the secondary read at
`0x606000018008` would either succeed (returning whatever bytes are
there) or trigger only at a hard page fault — neither of which JSC
asserts on directly.

## Follow-up: non-cell storage is still not enough

The harness now has storage and donor controls:

* `FAKE_STORAGE=biguint64Array` keeps the original typed-array-data path.
* `FAKE_STORAGE=doubleArray` writes the harvested cell bytes into a normal
  double-array butterfly, avoiding typed-array backing storage.
* `DONOR_KIND=plain|withProp|withProps|doubleArray|objectArray|arrayBuffer|uint8Array|biguint64Array`
  selects the donor header.
* `TOUCH_MODE=typeof` avoids constructor/property introspection after planting.

Representative command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=120 FAKE_STORAGE=doubleArray TOUCH_MODE=typeof DONOR_KIND=plain \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/fake-cell-from-harvested-header-probe.js
```

Run:

`lab/findings/runs/20260510T094819Z-68148/asan.log`

Key trace:

```text
{"phase":"fake-storage-butterfly","butterfly":"0x000062d000054408","fakeBytesAddr":"0x000062d000054408"}
{"phase":"fakecell-copied","kind":"doubleArray","bytes":"4062000000220000000000000000000000000000000000000000000000000000","matchesDonor":true}
{"phase":"planted","arrayIndex":2}
ERROR: AddressSanitizer: SEGV on unknown address 0x0000badbef50
```

This proves the donor bytes can be placed verbatim in a regular JSC butterfly
at a `0x62d...` address, and the fakeobj plant still reaches the post-structure
walk. It also shows why this is not sufficient: a butterfly is not a JSCell
allocation, so the later heap/cell-membership walk still reaches poisoned
secondary state (`0xbadbef50`). The successful follow-up is therefore to patch
a **real** typed-array cell's vector in place rather than plant a fake cell in
non-cell storage (`fs-uaf-real-typedarray-vector-patch-arw-20260510.md`).
