# fs UAF real-cell vector corruption — typed-array data is in Gigacage

Scope: extends the addrof + fakeobj primitives in `212b652` and the
fake-cell-layout-mapper negative result in `f80a803`. We test whether
the existing controlled-write primitive can corrupt an existing typed
array's `m_vector`, `m_length`, or backing-store contents (without
constructing a fake JSCell), so that a real, validly-structured typed
array view from JS reads or writes attacker-chosen native memory.
Headline result: **the canonical reclaim profile of the BufferSource
UAF does not land in typed-array data or typed-array view metadata**,
so this direct route is closed. Documented for completeness; the
fake-cell route in `f80a803` remains the open structural blocker.

## Harness

`lab/harnesses/13-arb-rw-probes/real-cell-vector-corruption-probe.js`.
Same detach + spray + write cycle as
`fs-uaf-object-ref-roundtrip.js`, but replaces the spray with typed
arrays / `ArrayBuffer`s and looks for the planted magic u64 bits inside
any sprayed view's first 32 elements. If the magic is found, we know
the freed BufferSource slot was reclaimed inside that allocation kind
at the corresponding offset.

```text
SPRAY_KIND ∈ {uint8Array, biguint64Array, float64Array, arrayBuffer}
VIEW_SIZE ∈ {1024, 4096}    # bytes per spray view's data
BUF_SIZE = 8192             # freed BufferSource backing store
WRITE_OFFSET = 144          # canonical landing offset
WRITE_LENGTH = 8
SPRAY_COUNT = 4096
ITERATIONS = 8
MAGIC_HEX = 0xcafef00ddeadbeef
```

## Sweep results

| `SPRAY_KIND`     | `VIEW_SIZE` | `foundOnIteration` | Outcome                                                        |
|------------------|------------:|-------------------:|----------------------------------------------------------------|
| `uint8Array`     | 1024        | `null`             | magic never appears in any sprayed view                        |
| `uint8Array`     | 4096        | `null`             | same                                                           |
| `biguint64Array` | 1024        | `null`             | same                                                           |
| `biguint64Array` | 4096        | `null`             | same                                                           |
| `float64Array`   | 1024        | `null`             | same                                                           |
| `float64Array`   | 4096        | `null`             | same                                                           |
| `arrayBuffer`    | 1024        | `null`             | same (read back as a `BigUint64Array` over the AB)             |
| `arrayBuffer`    | 4096        | `null`             | same                                                           |

Eight runs × eight iterations each = 64 spray-and-write attempts. The
magic landed in zero typed-array data buffers. Compare to the regular
`Array(1024)` butterfly spray in
`fs-uaf-object-ref-roundtrip.js`, which lands the magic at element[0]
of one specific sprayed array on **iteration 1, every run**. The
difference is structural: typed-array data is allocated by JSC's
Gigacage allocator, not by the same general-heap allocator that
backs `ArrayBuffer.transfer`'s freed backing store. The reclaim
size class therefore does not overlap.

## What this rules out

* Direct reclaim of the freed BufferSource backing store as a
  typed-array data buffer at the canonical write offset 144.
  Consequently, we cannot use the controlled-write primitive to plant
  bytes that a sprayed typed array view will read back through normal
  JS access.
* Direct corruption of a typed-array view's `m_vector` /
  `m_length` / `m_mode` fields via the same primitive at the same
  offset. The JSCell of a typed-array view lives in `0x6100…` /
  `0x6110…` IsoSubspace heap regions (per `f80a803`), in size classes
  much smaller than 8 KB; even if we shrank `BUF_SIZE` to a typed-array
  cell size class (≈32–48 bytes), it would not coincide with any of
  the larger BufferSource sizes we have empirical reclaim recipes for.

## What this does not rule out

* **Butterfly-length corruption of the regular-array spray.** The
  existing harness `lab/harnesses/13-arb-rw-probes/fs-read-array-oob-object-copy.js`
  *already* uses a write at offset 136 (the butterfly length header)
  to advertise a larger `vectorLength=publicLength=0x400` than the
  butterfly actually has. Under ASan that crosses into a redzone and
  is caught as `heap-buffer-overflow`. Under a non-ASan build the OOB
  read would silently return adjacent allocation bytes.
* **Targeting JSC structures that share the 8 KB size class.** The
  `7a07d68` IC-stub reclaim used `UAF_SIZE=112` to land in a JSC IC
  stub. There may be 8 KB-sized JSC objects (large polymorphic IC
  caches, Wasm tables, JIT data) that would be corruptible by the
  same offset-144 write at `BUF_SIZE=8192`. Identifying which ones is
  beyond what this bounded probe attempted.
* **Custom-shaped reclaim with a different `BUF_SIZE`.** Other
  `BUF_SIZE` values produce other reclaims:
  `BUF_SIZE ∈ {96, 128}` already crash inside Bun native code with
  attacker-byte-influenced SEGV addresses (`378039c` crash dirs
  `aadd7fc40d48`, `5805dff9975b`). One of those reclaims is a real
  in-process structure being mishandled; if it is a typed-array view
  cell, we have a candidate `m_vector` corruption path that this
  probe didn't directly attempt.

## Why the typed-array Gigacage matters

JSC partitions its heap into the regular `IsoSubspace` (used for
JSCells) and the **Gigacage** — a separate large mmap region whose
purpose is to make typed-array out-of-bounds writes unable to corrupt
pointers in the rest of the JSC heap. Bun inherits this layout. The
controlled-write primitive lands in the regular ASan general heap,
which contains JSCells and butterflies but **not** typed-array data
buffers. Hence the 64-iteration zero-hit result is structural, not a
timing or spray-tuning failure.

This is consistent with the addrof leak survey in `f80a803`: typed
arrays leak from `0x6100…` heap regions, while spray-array butterflies
that we successfully reclaim leak from `0x62d0…`. Different heap
regions, different size classes; the canonical reclaim path does not
cross.

## Conclusion

The fakeobj-from-arbitrary-bits primitive proven in `212b652` remains
bounded by the structureID `RELEASE_ASSERT` (`f80a803`). The proposed
"corrupt a real typed-array's `m_vector` and use it as a fake R/W
view" workaround does not work with the canonical reclaim profile,
because the freed BufferSource backing store does not land in
typed-array data nor in typed-array view metadata. To advance toward
FFI-free arbitrary R/W from here, the next concrete experiments are:

1. **Identify other 8 KB-class JSC structures.** The general
   IsoSubspace's 8 KB size class is shared with regular butterflies;
   any other JSC object of that size is a candidate reclaim target.
   Requires source-level enumeration of Bun/JSC heap classes, which
   was out of scope for this lab session.
2. **Re-investigate the 96-byte and 128-byte reclaims.** They produce
   crashes inside real Bun code with attacker-byte-influenced SEGV
   addresses; one of them is plausibly hitting a typed-array view
   cell (the `m_vector` corruption path), but we have not isolated
   which.
3. **Pursue arbitrary R/W via JIT-side state.** The proven
   `PutByVal` IC slow-path callsite in `378039c` still gives us
   controlled native call-target. Its post-call code does
   `STUR X16, [X17, …]` against a JIT-baked `X17`. If we could shape
   X17 to point at our chosen address, we would have an arbitrary
   write. This requires deeper IC-state corruption than the simple
   offset-16 function-pointer overwrite we have used so far.

## Disclosure framing

This finding does **not** strengthen the existing advisory in
`lab/findings/cve-disclosure/ADVISORY.md`. It is a structured
negative — recording that the most obvious "skip the fake cell, just
corrupt a real typed array" workaround does not apply under the
canonical reclaim shape. The advisory remains conservative.
