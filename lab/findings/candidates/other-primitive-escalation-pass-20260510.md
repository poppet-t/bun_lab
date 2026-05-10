# Other Primitive Escalation Pass - 2026-05-10

Scope: local defensive follow-up after the async fs UAF was pushed into JSC
array storage. This pass checks whether other confirmed primitives also cross
into pointer-bearing JSC storage or controlled element writes. It does not
include a native arbitrary read/write or RCE chain.

## Summary

Confirmed stronger result:

- `Blob` and `File` BufferSource re-entry stale reads can disclose groomed JSC
  array storage, including pointer-like object references and double elements.

Still crash/corruption only in this pass:

- async zlib input stale read did not produce a clean decompressed leak in the
  tested ASan build
- async zlib output stale write hit ASan before a JS-visible array-element
  mutation could be observed
- async `crypto.randomFill` random stale write hit ASan before a JS-visible
  array-element mutation could be observed

Still not arbitrary native read/write:

- none of these primitives accepts an arbitrary native address
- no typed-array/DataView backing pointer corruption was confirmed
- no fake object or JIT/code-pointer corruption was attempted or confirmed

## Harnesses

- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/blob-array-leak.js`
- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/zlib-input-array-leak.js`
- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/zlib-output-array-write.js`
- `/Users/CJ/Documents/bun_lab/lab/harnesses/13-arb-rw-probes/crypto-randomfill-array-write.js`

Fresh runs used:

```text
ASAN_OPTIONS=...:quarantine_size_mb=0
```

## Blob/File stale read to JSC array storage

### Byte-storage baseline

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030421Z-8653/asan.log`

Result:

```text
CONSTRUCTOR=blob SPRAY=byte-canary
prefix="BUN_BLOB_LEAK_BYTE-CANARY..."
oldFillRatio=0.0004
```

Interpretation: with ASan quarantine disabled, the detached BufferSource backing
store can be reclaimed before `Blob` materializes the earlier part.

### Blob leaks object-array storage

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030452Z-10251/asan.log`

Representative result:

```text
CONSTRUCTOR=blob SPRAY=array-refs
pointerSamples:
  offset=24  value=0x00006250003c5118
  offset=32  value=0x0000625000203118
  offset=144 value=0x000062d000034280
  offset=152 value=0x000062d0000342a0
```

Interpretation: `Blob` output contains bytes from sprayed JSC object-array
storage. This is an information-disclosure primitive over groomed array storage.

### Blob leaks double-array storage

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030452Z-10252/asan.log`

Representative result:

```text
CONSTRUCTOR=blob SPRAY=array-doubles
doubleSamples:
  offset=144 value=3007.5
  offset=152 value=3007.500977
  offset=160 value=3007.501953
```

Interpretation: the same stale read can disclose double-array element storage.

### File shares the Blob leak

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030639Z-16094/asan.log`

Representative result:

```text
CONSTRUCTOR=file SPRAY=array-refs
pointerLikeCount=16
pointerSamples:
  offset=144 value=0x000062d000034280
  offset=152 value=0x000062d0000342a0
```

Interpretation: `new File([...])` shares the vulnerable Blob part processing
path and can disclose the same groomed JSC array storage.

## zlib input stale read

### Small input did not race into reclaimed storage

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030421Z-8652/asan.log`

Result:

```text
CODEC=deflate INPUT_SIZE=8192 SPRAY=byte-canary
oldFillRatio=1
markerOffset=-1
```

Interpretation: for this small input, the async worker consumed the original
bytes before the detached allocation was reclaimed.

### Larger input produced sanitizer crash, not clean leak

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030438Z-9318/asan.log`

Result:

```text
AddressSanitizer: SEGV ... READ memory access ... thread T6
```

Interpretation: zlib input is still a confirmed stale native read, but this pass
did not produce a decompressed JSC-array disclosure comparable to Blob/File.

## zlib output stale write

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030616Z-14337/asan.log`

Probe details:

- set `engine._outOffset = 144` to aim output at the first observed double-array
  element slot
- detached `engine._outBuffer`
- sprayed double arrays before worker output

Result:

```text
AddressSanitizer: heap-buffer-overflow ... WRITE of size 2 ... thread T6
```

Interpretation: zlib output remains a stale native write/corruption primitive,
but this pass did not observe a clean JS-visible element mutation. The write
bytes are codec-generated, not attacker-chosen in the same way as `fs.read`.

## crypto.randomFill stale write

Log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T030519Z-11705/asan.log`

Probe details:

- scheduled async `randomFill(target, 144, 8)`
- detached target backing store
- sprayed double arrays

Result:

```text
AddressSanitizer: heap-buffer-overflow ... WRITE of size 8 ... thread T6
```

Interpretation: this remains a non-fs stale write, but the bytes are random and
this pass did not turn it into a clean JS-visible array-element write.

## Other primitive boundaries

- `Buffer.write` encoding coercion still appears to become a null/detached
  vector write after detach rather than an attacker-chosen stale destination.
- `Buffer.from(resizable ArrayBuffer, offset, length)` remains a JS-visible
  length-tracking/bounds-confusion issue inside the same resizable backing
  store, not a native address primitive.
- `Bun.mmap` offset confusion is a local file wrong-region disclosure. It does
  not disclose process memory or native pointers.

## Current Status

Confirmed from this pass:

- Blob/File addrof-like disclosure of groomed JSC array storage
- zlib and crypto stale-write/read crashes remain valid memory-safety evidence

Not confirmed from this pass:

- arbitrary native address read
- arbitrary native address write
- controlled zlib output write into a JS-visible element
- controlled crypto write into a JS-visible element
- typed-array backing pointer corruption
- fake object construction
- RCE reachability
