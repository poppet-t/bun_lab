# fs UAF fake-cell layout mapper — addrof-only addrof+fakeobj is bounded

Scope: extends the addrof + fakeobj-from-arbitrary-bits primitives proven
in `lab/findings/candidates/fs-uaf-object-bridge-rce-pivot-20260510.md`
(commit `212b652`). This note records what survives JSC's per-cell
validation when we plant `addrof(template) + DELTA` as a fake JSCell, what
JSC reads at each delta, and which deltas are dead-ends.

The headline negative result: **the fakeobj-from-arbitrary-bits primitive
proven in `212b652` is currently bounded by JSC's structureID
`RELEASE_ASSERT`**. The next layer of progress requires either (a) a way
to leak / observe a real `structureID`, or (b) a way to corrupt an
existing cell's metadata in place rather than craft a new one.

## Harness

`lab/harnesses/13-arb-rw-probes/fake-cell-layout-mapper.js`. Single
experiment per process invocation. Env: `TEMPLATE` selects the JS object
type (`plain | withProps | doubleArray | objectArray | arrayBuffer |
uint8Array | float64Array | biguint64Array | dataView | regexp |
function`). `DELTA` is a signed integer added to the leaked `addrof()`.
Reads back via `arr[i]` after planting and reports `readBack` /
`identityProbe` if it survived, otherwise the process dies and ASan logs
the crash signature.

## addrof leak survey

Confirmed addrof works for every template tested, with each landing in a
distinct JSC IsoSubspace heap region:

| Template          | addrof(template) example         | Heap region     |
|-------------------|-----------------------------------|------------------|
| `plain`           | `0x000062d0000a66c0`             | `0x62d0…`       |
| `withProps`       | `0x000062d0000a66c0`             | `0x62d0…`       |
| `doubleArray`     | `0x000062d0001ec290`             | `0x62d0…`       |
| `objectArray`     | `0x000062d0001ec290`             | `0x62d0…`       |
| `arrayBuffer`     | `0x000060f000010388`             | `0x60f0…`       |
| `uint8Array`      | `0x00006100000035c8`             | `0x6100…`       |
| `float64Array`    | `0x00006100000035c8`             | `0x6100…`       |
| `biguint64Array`  | `0x00006100000035c8`             | `0x6100…`       |
| `dataView`        | `0x000061100000fd48`             | `0x6110…`       |

Distinct templates of the same kind allocated in sequence are typically
0x20 apart (JSObject IsoSubspace stride), as predicted by the addrof
probe in `212b652`.

## Delta sweep — `TEMPLATE=plain`

| `DELTA` | Outcome                                                  |
|--------:|----------------------------------------------------------|
| `-32`   | ASan BUS error (unaligned read inside JSC)               |
| `-16`   | SEGV at `0x10` (JSC followed a near-zero pointer)        |
| `-8`    | exit 133 — JSC `BRK` / `RELEASE_ASSERT`                  |
| `0`     | identity (real cell) — `readBack` matches template       |
| `+8`    | exit 133 — `RELEASE_ASSERT`                              |
| `+16`   | exit 133 — `RELEASE_ASSERT`                              |
| `+24`   | exit 133 — `RELEASE_ASSERT`                              |
| `+32`   | exit 133 — `RELEASE_ASSERT`                              |
| `+48`   | exit 133 — `RELEASE_ASSERT`                              |
| `+64`   | exit 133 — `RELEASE_ASSERT`                              |

Only `DELTA=0` survives. Run dirs:
`20260510T071202..071206Z-*` (sweep), `20260510T071202Z-88884` (the
DELTA=0 baseline). The exit-133 cases die after the
`{"phase":"planted",…}` line and before the `{"phase":"result",…}` line,
i.e. JSC aborted while reading the planted slot. macOS reports this as
`Trace/BPT trap: 5`, consistent with `BRK #c471` /
`JSC::handleAssertion` patterns.

## Delta sweep — `TEMPLATE=biguint64Array`

| `DELTA` | Outcome                                                       |
|--------:|---------------------------------------------------------------|
| `0`     | identity — `readBack` is the BigUint64Array                   |
| `+8`    | heap-buffer-overflow at `0x610000000008` (followed pointer)   |
| `+16`   | exit 133 — `RELEASE_ASSERT`                                   |
| `+24`   | heap-buffer-overflow at `0x610000000008`                      |
| `+32`   | exit 133 — `RELEASE_ASSERT`                                   |
| `+40`   | heap-buffer-overflow at `0x610000000008`                      |
| `+48`   | heap-buffer-overflow at `targetAddr + 48 + 5` = `targetAddr+53` |
| `+56`   | heap-buffer-overflow at `targetAddr + 56 + 5`                  |
| `+64`   | heap-buffer-overflow at `targetAddr + 64 + 5`                  |
| `+72..+96` | same `targetAddr + DELTA + 5` pattern                        |
| `-8`    | heap-buffer-overflow at `0x610000000008`                       |
| `-16`   | exit 133 — `RELEASE_ASSERT`                                   |
| `-24`   | heap-buffer-overflow at `0x610000000008`                       |

Two crash modes are visible:

* **`exit=133` / RELEASE_ASSERT** — JSC reads the fake cell but fails a
  structureID-based invariant. The crash is internal to JSC; we never get
  to the +5 read.
* **heap-buffer-overflow at `planted_bits + 5`** — JSC reads the type
  byte at offset +5 but is past the cell's allocation; ASan flags it.
  This is the same fingerprint as the original `212b652`
  `0x00007fffdeadbef0 → 0x7fffdeadbef5` crash, here scaled to
  `targetAddr + DELTA + 5`.

Mixed in (DELTAs 8, 24, 40, -8, -24) is a third mode where JSC follows
some pointer field in our fake cell and dereferences it at
`0x610000000008` (the IsoSubspace base). This is JSC chasing what it
thinks is `m_vector` or the butterfly through a partially-zero region.

The takeaway: planting `addrof(typedArray) + DELTA` for any small
non-zero DELTA either trips `RELEASE_ASSERT` or runs JSC into a chained
deref that crashes immediately. **There is no DELTA on this template
for which JSC's read at +5 lands in attacker-controlled bytes inside
a known mapped region.**

## Wide leak attempt

Harness: `lab/harnesses/13-arb-rw-probes/wide-leak-structureid-recover.js`.
Run: `lab/findings/runs/20260510T072053Z-4737/asan.log`.

The leak side of the BufferSource UAF reads 8192 bytes — far more than
the 8 we were consuming for addrof. A focused dump of the first 320
bytes of a single leak attempt:

```
   0  bebebebebebebebebebebebebebebebe
  16  bebebebebebebebe1811090050620000   <- ptr 0x000062500009_1118
  32  18a1320050620000e200000000000000   <- ptr 0x000062500032_a118
  48  1020000000000000e2010002ff000000
  64  2022034701000000 0000000000000000   <- ptr 0x0000000147032220 (StructurePool-ish)
  ...
 128  00000000000000000008034701000000
 136  f0eedbba000000000004000000040000   <- butterfly header: vectorLength=publicLength=0x400=1024
 144  c05c0300d0620000e05c0300d0620000   <- anchor[0..N] cell pointers begin
```

Key observations:

* The butterfly header at offset 136..143 contains
  `vectorLength = publicLength = 0x400 = 1024`. That matches `SLOTS=1024`
  in the spray. Confirms the 8KB freed slot was reclaimed *exactly* as
  the indexed-array butterfly we expect, and explains why the canonical
  `ELEMENT_OFFSET=144` lands element[0].
* Offsets 16, 32, 64 carry residual pointers from whatever last lived in
  the slot before the spray (some JSC StructurePool / JIT-cache record).
  The poison `0xbadbeef0` at offset 128..131 is an allocator free-fill
  pattern, just below the butterfly header.
* **None of the leaked u64s in the entire 8KB transcript are recognisable
  as a JSCell header.** The cell pointers we see all point *to* anchor
  cells; we do not get the cells themselves in the leaked bytes. So
  this leak — large as it is — does not directly expose a real
  `structureID` value we could reuse in a fake cell.

## Why the fake-cell build is currently blocked

To turn `fakeobj-from-arbitrary-bits` into a non-crashing primitive we
need to plant a 64-bit value `bits` such that:

1. The address `bits` is mapped (so the +5 read does not SEGV).
2. The byte at `bits + 5` decodes to a plausible `JSType`
   (`m_type ∈ {ObjectType, ArrayType, FinalObjectType, …}`).
3. The 32-bit value at `bits + 0..3` is a real, currently-allocated
   `StructureID` from JSC's per-VM `StructureIDTable`. JSC's `BRK` /
   `RELEASE_ASSERT` fires on the next layer of validation if it isn't.

We have (1) trivially when we plant `addrof(real_cell) + 0` — the price
is that the fake cell *is* the real cell, so we cannot bend its
`m_vector` away from the real backing store. We do not yet have (3).
Without (3), planting `addrof(real_cell) + N` for N != 0 always trips
the `RELEASE_ASSERT`.

The wide-leak transcript above confirms that the controlled-write
primitive's leak side, on its own, cannot recover a `StructureID`: the
8KB transcript is the spray-array butterfly, which contains anchor
*pointers*, not anchor *cell contents*. We cannot dereference those
pointers from JS without the same fake-cell construction we are trying
to build.

## Routes that remain open

The next concrete experiments worth running, ordered by expected
information-per-effort:

1. **Reuse-content StructureID grooming.** The 8KB transcript already
   contains residual JSC StructurePool-shaped pointers. If those
   addresses can be steered into the freed slot's offset 0..3 (so we
   leak a `Structure*` rather than a butterfly), we could either:
   (a) infer a `StructureID` index from the pool layout, or
   (b) plant the leaked `Structure*` as the structureID-bearing field
   of a fake cell that can be loaded by JIT code (analogous to the
   `PutByVal` IC flow in `378039c`).
   Requires a new leak-shaping harness, not just dump tuning.

2. **Corrupt an existing cell's metadata.** Bypass fake-cell
   construction entirely. Use the controlled-write side of the
   BufferSource UAF to overwrite, say, the `m_vector` of a real
   `Uint8Array` whose JSCell happens to land in the freed slot. This
   requires picking a reclaim profile (BUF_SIZE / SPRAY_COUNT / spray
   shape) where the freed slot is *the typed-array view cell*, not a
   *butterfly*. Adjacent reclaim sizes 96 and 128 already produced
   crashes inside Bun native code (`378039c` crash dirs `aadd7fc40d48`,
   `5805dff9975b`); one of those reclaims is plausibly hitting a
   typed-array cell.

3. **Corrupt JIT IC state and re-use the proven `BLR X16` callsite.**
   `378039c` proved we can drive the program counter via the JSC
   `PutByVal` IC slow-path at offset 16 of a 112-byte reclaim. With
   addrof + the wide-leak transcript, we may now be able to either
   shape the IC's `[X2 + 56]` indirection ourselves, or fold the IC
   slot into the addrof+fakeobj chain.

For now, do not over-claim. The advisory bundle in
`lab/findings/cve-disclosure/` continues to describe only the
end-to-end demonstrated effects: controlled native heap write,
controlled native indirect call target through the JIT IC stub, and
controlled native dereference via fakeobj. Stable arbitrary R/W and
RCE remain unproven.

## Reproduction snippets

```sh
# baseline identity sweep over templates (DELTA=0)
for tpl in plain withProps doubleArray objectArray arrayBuffer \
           uint8Array float64Array biguint64Array dataView; do
  ASAN_OPTIONS=…:quarantine_size_mb=0 \
    TIMEOUT=20 TEMPLATE=$tpl DELTA=0 \
    lab/scripts/triage.sh \
      lab/harnesses/13-arb-rw-probes/fake-cell-layout-mapper.js
done
# expect: identityProbe=true, readBack matches template

# delta sweep on a typed array
for delta in 0 8 16 24 32 40 48 56 64 -8 -16 -24; do
  ASAN_OPTIONS=…:quarantine_size_mb=0 \
    TIMEOUT=15 TEMPLATE=biguint64Array DELTA=$delta \
    lab/scripts/triage.sh \
      lab/harnesses/13-arb-rw-probes/fake-cell-layout-mapper.js
done

# wide-leak transcript dump
ASAN_OPTIONS=…:quarantine_size_mb=0 \
  TIMEOUT=30 DUMP_START=0 DUMP_LEN=320 \
  lab/scripts/triage.sh \
    lab/harnesses/13-arb-rw-probes/wide-leak-structureid-recover.js
```
