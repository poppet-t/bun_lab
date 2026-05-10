# Post-push primitive escalation - 2026-05-10

Scope: local CTF/lab validation after pushing the initial primitive findings to
`codex/uaf-array-primitives`. These results still require local JS access to
the affected APIs and are not yet reachable from the hardened HTTP challenge
request path.

## New confirmed primitives

### JSC double-array length corruption to linear OOB RW

Harness:

- `lab/harnesses/13-arb-rw-probes/fs-read-array-metadata-write.js`

Controlled async `fs.read` stale writes can modify the adjacent JSC array
metadata words at reclaimed offset `136`. Setting both words to a larger value
changes a retained double array's JS-visible length.

Key logs:

- `lab/findings/runs/20260510T031755Z-35162/asan.log`: length changed from
  `1024` to `2048`.
- `lab/findings/runs/20260510T032011Z-39605/asan.log`: OOB reads from the
  corrupted array disclose a neighboring double-array sequence starting at
  relative OOB index `256`.
- `lab/findings/runs/20260510T032023Z-40425/asan.log`: writing
  `corrupted[1024 + 256] = 1.23456789012345e+123` changes
  `retained[45][0]` to that exact double.

Impact: this is a JS-visible linear OOB read/write across JSC butterfly storage
under the current reclaim profile. It is stronger than the earlier single
element stale write because the corrupted array remains usable as the write
gadget.

Current boundary: object-array victim mixes changed the allocator layout and
hit ASAN redzones before a stable object-pointer OOB copy was obtained. See
`lab/harnesses/13-arb-rw-probes/fs-read-array-oob-object-copy.js` and crash
logs `20260510T032236Z-44323`, `20260510T032252Z-45855`, and
`20260510T032311Z-47615`.

### ArrayBuffer metadata corruption to expanded backing length

Harness:

- `lab/harnesses/13-arb-rw-probes/fs-read-typedarray-metadata-write.js`

Small `UAF_SIZE=128` stale reads showed freed BufferSource storage can be
reclaimed by pointer-bearing ArrayBuffer/typed-array metadata objects, not only
raw byte stores.

Key logs:

- `lab/findings/runs/20260510T032622Z-58803/asan.log`: stale read of a
  byte-canary spray leaks pointer-bearing metadata with `0x80` length fields at
  offsets `48` and `56`.
- `lab/findings/runs/20260510T032714Z-60561/asan.log`: controlled stale write
  at offset `48` changes a retained view's `buffer.byteLength` from `128` to
  `256` while the view length remains `128`.
- `lab/findings/runs/20260510T032742Z-62008/asan.log`: constructing a fresh
  `Uint8Array(view.buffer)` after the length corruption and reading index `128`
  triggers an ASAN heap-buffer-overflow, confirming that the expanded buffer
  length reaches beyond the original allocation.

Impact: local JS can corrupt ArrayBuffer metadata into a fresh-view OOB byte
access. Under ASAN the first byte past the original allocation is a redzone and
crashes on read; a non-ASAN build would need adjacency grooming to turn this
into a practical read/write primitive.

### Backing-pointer alias attempt

Harness:

- `lab/harnesses/13-arb-rw-probes/fs-arraybuffer-backing-alias.js`

The metadata leak exposes pointer-like fields at offsets including `8`, `16`,
and `24`. Offset `16` often points into the 128-byte ASAN allocation class and
is the best current backing-store candidate.

Key logs:

- `lab/findings/runs/20260510T032940Z-66462/asan.log`: filtered retry obtains
  pointer-like offset-16 metadata (`0x000060c00049e280`) but a single write
  attempt did not create an observable alias.
- `lab/findings/runs/20260510T033039Z-69496/asan.log` and
  `lab/findings/runs/20260510T033039Z-69508/asan.log`: alternate write/leak
  offsets did not produce an alias.
- `lab/findings/runs/20260510T033002Z-68164/asan.log` and
  `lab/findings/runs/20260510T033039Z-69495/asan.log`: repeated or offset-8
  pointer-field attempts caused sanitizer crashes during metadata use/teardown.

Current boundary: no stable arbitrary backing-pointer alias was obtained.

## CTF request-path status

The challenge route still exposes only bounded request streaming,
`TextDecoder("utf-8", { fatal: true })`, `JSON.parse`, and strict package-name
validation. The local primitives above require direct local JS access to
`node:fs` or constructors that are not invoked by the request handler.

Request-path fuzzing/audit remains clean:

- `lab/harnesses/14-ctf-request-surface/ctf-http-mutator.js`:
  `lab/findings/runs/20260510T031544Z-29484/asan.log`
- `lab/harnesses/14-ctf-request-surface/body-chunk-stability.js`:
  `lab/findings/runs/20260510T031653Z-32331/asan.log`

Current implication: the new local primitives are useful for exploit
development, but they do not yet produce a local HTTP solve for
`lab/ctf/bun-rce/challenge-server.js`.
