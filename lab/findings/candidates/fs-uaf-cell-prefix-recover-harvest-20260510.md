# fs UAF cell-prefix recovery — closes the structureID block

Date: 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. No `bun:ffi`, no native helper dylib, no symbol
enumeration, no JIT warming, no remote service.

## Headline

The no-FFI ArrayBuffer-metadata bridge (`addrof-arraybuffer-metadata-arw-bridge.js`,
commit `cb38d3c`) already had a `CELL_READ` path that reads 32 bytes from an
attacker-chosen `JSCell*`. Until now we used it once. This finding turns it
into a wide-table primitive: read JSCell prefixes for many distinct object
kinds in a single process, parse out the JSCell header fields, and confirm
the result that **closes the `f80a803` structureID `RELEASE_ASSERT` block**:
real `structureID` and `m_type` bytes are recoverable from JS, with no FFI,
in the same process where they will be used.

New harness:

* `lab/harnesses/13-arb-rw-probes/cell-prefix-recover-harvest.js`

It builds the two-stage metadata bridge once (`addrof(victimBuffer)` →
wrapper → metadata object) and then loops through templates, retargeting
the metadata's data-pointer field to each template's `addrof()` and reading
32 bytes through a fresh `Uint8Array(victimBuffer)` view. The metadata
data-pointer is restored between templates so the victim survives the next
loop iteration.

## Validation

Command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/cell-prefix-recover-harvest.js
```

Run: `lab/findings/runs/20260510T092821Z-38174/asan.log`

The harness produces one `phase: summary` JSON line at the end; the
`results[]` array contains an entry per template with `targetAddr`,
`cellPrefixHex` (32 bytes), and a parsed `header` (structureID,
indexingType, m_type, flags, cellState).

## Recovered table

For one representative process (structureIDs are per-VM and will rotate
between runs; m_type / indexingType / flags / cellState are stable):

| Template          | Target address           | structureID   | indexingType | m_type | flags | cellState |
|-------------------|--------------------------|---------------|--------------|-------:|------:|----------:|
| `plain`           | `0x000062d0000a42c0`     | `0x00006240`  | 0            | 34     | 0     | 0         |
| `withProps`       | `0x000062d0000a4440`     | `0x0000f900`  | 0            | 34     | 0     | 0         |
| `doubleArray`     | `0x000062d0017246b0`     | `0x000069b0`  | 23           | 46     | 8     | 0         |
| `objectArray`     | `0x000062d00118c6c0`     | `0x00006710`  | 9            | 46     | 8     | 0         |
| `arrayBuffer`     | `0x000062d000f1ba00`     | `0x0000a630`  | 0            | 48     | 0     | 0         |
| `uint8Array`      | `0x000062d0016c2560`     | `0x0000b040`  | 0            | 50     | 8     | 0         |
| `float64Array`    | `0x00006100000089c8`     | `0x0000c9c0`  | 0            | 58     | 8     | 0         |
| `biguint64Array`  | `0x00006100000099c8`     | `0x0000cbf0`  | 0            | 60     | 8     | 0         |
| `dataView`        | `0x000061100001e348`     | `0x0000f120`  | 0            | 61     | 0     | 0         |
| `regexp`          | `0x000060f000016a98`     | `0x00006c50`  | 0            | 72     | 8     | 0         |
| `function`        | `0x000062d0002a1c20`     | `0x00005c20`  | 0            | 36     | 14    | 0         |

The `m_type` values match standard JSC `JSType` conventions:

* 34 — `FinalObjectType`
* 36 — `JSFunctionType`
* 46 — `ArrayType`
* 48 — `ArrayBufferType`
* 50 — `Uint8ArrayType`
* 58 — `Float64ArrayType`
* 60 — `BigUint64ArrayType`
* 61 — `DataViewType`
* 72 — `RegExpObjectType`

`indexingType` for `doubleArray` is 23 (`CopyOnWriteArrayWithDouble`); for
`objectArray` it is 9 (`ArrayWithContiguous`). Typed arrays carry
indexingType 0.

`cellState=0` across the board (a freshly allocated, "marked black" cell).

## Why this matters

The fakeobj-from-arbitrary-bits primitive in `212b652` was bounded by
JSC's structureID `RELEASE_ASSERT`: planting any 64-bit value whose
`structureID` field at offset 0..3 is not a real entry in the per-VM
`StructureIDTable` aborts via `BRK` (`f80a803`). With the harvest
primitive above, real per-VM `structureID` and `m_type` bytes are now
attacker-readable from JS, in the same process where the fakeobj plant
will happen. That removes the gating block on the FFI-free arb-R/W
chain.

A follow-up harness will use a harvested `(structureID, m_type)` pair
to construct a fake cell that survives the `RELEASE_ASSERT`. The
structural sketch:

1. Harvest `plain` → `(real_structureID, 34, 0, 0, 0)` in-process.
2. Allocate a JS object `obj` with a `Float64`-typed property whose
   stored NaN-boxed bytes encode the harvested header at `addrof(obj)+16`.
3. Plant `addrof(obj)+16` as the fakeobj-from-arbitrary-bits target.
4. JSC's `RELEASE_ASSERT` should now pass because the structureID maps
   to a real `Structure*` and `m_type` is a known cell type.

If step 4 holds, layout-independent fakeobj is reached, and from there
the well-known JSC fake-Uint8Array path gives arbitrary native R/W.

## Boundaries

This finding does **not** by itself demonstrate fake-cell construction
or arbitrary R/W. It only proves the harvest works and that the
structureIDs / type bytes are recoverable. The advisory in
`lab/findings/cve-disclosure/ADVISORY.md` is intentionally not changed.
A future commit using these harvested values to build a working
fake-cell will be the right place to extend the advisory.

## Side-effect note

The teardown of the harness produces an ASan
`attempting free on address which was not malloc()-ed` because the
victim ArrayBuffer's metadata data-pointer was once swapped through the
bridge and the runtime later attempts to free the original allocation.
This is post-result noise — the JSON summary is emitted **before** the
teardown crash. We treat the JSON as authoritative; the teardown
abort does not invalidate the harvested data.
