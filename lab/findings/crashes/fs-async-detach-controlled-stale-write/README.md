# Async `fs.read` / `fs.readv` detached ArrayBuffer controlled stale write

Status: confirmed canary corruption under ASan with quarantine disabled.

Harnesses:

- `lab/harnesses/10-async-buffer-lifetime/async-fs-read-canary.js`
- `lab/harnesses/10-async-buffer-lifetime/async-fs-readv-canary.js`

Command:

```sh
ASAN_OPTIONS="$ASAN_OPTIONS:quarantine_size_mb=0:thread_local_quarantine_size_kb=0" \
  ITERATIONS=8 SPRAY_COUNT=2048 \
  lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-read-canary.js

ASAN_OPTIONS="$ASAN_OPTIONS:quarantine_size_mb=0:thread_local_quarantine_size_kb=0" \
  ITERATIONS=8 SPRAY_COUNT=2048 VIEW_SIZE=2048 \
  lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-readv-canary.js
```

Saved logs:

- `lab/findings/runs/20260509T-fs-controlled-stale-writes/fs-read-canary.log`
- `lab/findings/runs/20260509T-fs-controlled-stale-writes/fs-readv-canary.log`

Observed signal:

```text
[fs.read:canary] controlled stale write observed iteration=1 canary=2 bytesRead=8192
[fs.readv:canary] controlled stale write observed iteration=1 canary=42 bytesRead=8192
```

Root cause:

- Async FS tasks capture `MarkedArrayBuffer` / iovec pointers before scheduling work on the `WorkPool`.
- `toThreadSafe()` roots JS values but does not pin the underlying backing stores or reject detachable/resizable buffers.
- User JS can detach the original ArrayBuffers and allocate same-size canary buffers before the worker read completes.
- The native `read(2)` / `readv(2)` call writes attacker-controlled fd bytes through stale pointers into the reclaimed allocations.

Relevant source:

- `bun/src/runtime/node/node_fs.zig:356`
- `bun/src/runtime/node/node_fs.zig:1430`
- `bun/src/runtime/node/node_fs.zig:2560`
- `bun/src/runtime/node/node_fs.zig:4341`
- `bun/src/runtime/node/node_fs.zig:4490`
- `bun/src/runtime/node/types.zig:840`

Exploitability note:

This confirms controlled same-process stale writes, not RCE by itself. The next exploitability question is whether an attacker can reliably reclaim the freed backing store with security-sensitive object metadata or another object that yields arbitrary read/write.
