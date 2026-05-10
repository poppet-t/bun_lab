# UAF to JSC Array Storage Primitives - 2026-05-10

Scope: local defensive validation of whether the async fs BufferSource UAF can
cross from ordinary byte-storage corruption into JSC array storage. This note
records exploitability primitives and current limits; it does not provide a
native arbitrary read/write or RCE chain.

## Summary

The async fs UAF can be groomed beyond `Buffer`/`ArrayBuffer` byte storage in
the ASan build with quarantine disabled. Fresh harnesses show:

- stale `fs.write` can disclose JSC array storage containing pointer-like object
  references and array metadata
- stale `fs.read` can perform a controlled write into a sprayed double array
  element
- a leaked valid object reference representation can be written into another
  object array and observed through JS identity

This is stronger than the earlier byte-storage-only status. It is still not a
complete arbitrary native read/write primitive because the destination/source is
selected through allocator reuse and grooming, not by supplying an arbitrary
native address.

## Harnesses

- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/fs-write-overlap-scan.js`
- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/fs-read-array-double-write.js`
- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/fs-uaf-object-ref-roundtrip.js`

All fresh runs used:

```text
ASAN_OPTIONS=...:quarantine_size_mb=0
```

This is necessary because ASan quarantine otherwise intentionally delays reuse
of freed allocations. Production/non-ASan allocator behavior still needs a
separate reliability pass.

## Fresh Evidence

### Baseline byte-storage overlap

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025456Z-90671/asan.log`

Result:

```text
SPRAY=byte-canary
markerOffset=0
sourceFillRatio=0
```

Interpretation: the overlap harness can still reproduce the original stale
read into reclaimed byte storage.

### Stale read leaks array storage

Logs:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025518Z-91349/asan.log`
- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025618Z-94539/asan.log`
- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025518Z-91360/asan.log`
- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025518Z-91366/asan.log`

Representative `array-refs` result:

```text
pointerSamples:
  offset=24  value=0x00006250003cf118
  offset=32  value=0x0000625000345918
  offset=144 value=0x000062d0000347a0
  offset=152 value=0x000062d0000347c0
  offset=160 value=0x000062d0000347e0
```

Representative `array-doubles` result:

```text
pointerSamples:
  offset=24  value=0x0000625000091118
  offset=32  value=0x0000625000348118

doubleSamples:
  offset=144 value=387.37
  offset=152 value=387.370977
  offset=160 value=387.371953
```

Interpretation: after detaching the stale `fs.write` source, spraying JS arrays
can reuse the freed backing allocation. The stale native read discloses metadata
and element storage, including object-reference-shaped values and double
elements. Offset `144` is the first observed element slot for the tested
8192-byte/1024-slot array shape.

### Controlled write into a double array

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025653Z-96462/asan.log`

Result:

```text
writeOffset=144
magic=6.02214076e+23
found={"arrayIndex":368,"elementIndex":0,"value":6.02214076e+23}
```

Interpretation: stale `fs.read` with API-level offset control can write a chosen
IEEE-754 value into the first element slot of a reclaimed double array. This is
a controlled non-byte-storage write, not just a redirected write into another
`ArrayBuffer`.

### Object reference leak and valid reference write

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T025816Z-99060/asan.log`

Result:

```text
leakedRef=0x000062d000035c00
leakPrefixAtElementOffset=[
  0,92,3,0,208,98,0,0,
  32,92,3,0,208,98,0,0,
  64,92,3,0,208,98,0,0,
  96,92,3,0,208,98,0,0
]
found={"arrayIndex":5,"elementIndex":0,"anchorIndex":45}
```

Interpretation: the stale read leaked a valid object-reference representation
from an anchor object array. A second stale write placed that exact value into a
sentinel-filled object array. JS then observed `arr[0]` become one of the anchor
objects by identity. This is a safe valid-reference roundtrip, not an attempt to
install an invalid or attacker-invented pointer.

## Current Primitive Status

Confirmed:

- controlled stale write into reclaimed byte storage
- stale read from reclaimed byte storage
- stale read from JSC array storage with pointer-like object references
- controlled write into JSC double-array element storage
- valid object-reference write into JSC object-array element storage

Still not confirmed:

- arbitrary native address read
- arbitrary native address write
- typed-array backing pointer corruption
- fake object construction
- JIT/code-pointer corruption
- ASLR/W^X/PAC bypass
- request-reachable trigger in `lab/ctf/bun-rce/challenge-server.js`

## Exploitability Boundary

The new result is best described as an addrof/write-what-through-reuse style
primitive over groomed JSC array storage:

- read side: leak object-reference-shaped values and array storage bytes from a
  reclaimed allocation
- write side: write chosen bytes into a groomed reclaimed allocation at a chosen
  offset

It is not yet arbitrary native read/write because the primitive does not accept
an arbitrary address. A stronger claim would require a separate, reliable way
to turn the object-reference leak and array-element write into corruption of a
typed array/DataView backing pointer or another native pointer-bearing object
that gives address-indexed memory access.

## Fix Direction

The root fix direction is unchanged:

- pin or copy all BufferSource backing stores used by async `fs.read`/`fs.write`
  and `readv`/`writev`
- for vector APIs, pin each backing store, not just the outer JS array
- reject or copy detachable/resizable buffers when a stable native pointer
  cannot be guaranteed
