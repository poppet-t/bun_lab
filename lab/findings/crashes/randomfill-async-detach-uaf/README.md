# Async `crypto.randomFill` detached ArrayBuffer UAF

Status: confirmed under ASan.

Harness:

- `lab/harnesses/10-async-buffer-lifetime/async-randomfill-detach.js`

Command:

```sh
ITERATIONS=64 BATCH_SIZE=16 lab/scripts/run-asan.sh \
  lab/harnesses/10-async-buffer-lifetime/async-randomfill-detach.js
```

Saved log:

- `lab/findings/runs/20260509T-randomfill-uaf/asan-randomfill.log`

ASan signal:

```text
ERROR: AddressSanitizer: heap-use-after-free
WRITE of size 8192
```

Root cause:

- `randomFill()` stores `buf.slice().ptr` in `JobCtx.bytes`.
- `JobCtx.init()` only protects the JS value.
- User JS can detach the ArrayBuffer after scheduling.
- `JobCtx.runTask()` later writes through the stale pointer on a worker thread.

Relevant source:

- `bun/src/runtime/node/node_crypto_binding.zig:198`
- `bun/src/runtime/node/node_crypto_binding.zig:202`
- `bun/src/runtime/node/node_crypto_binding.zig:418`

Exploitability note:

This is a native write-after-free primitive, but the bytes are CSPRNG output, not attacker-selected data. Treat it as confirmed memory corruption and as a strong indicator that related async writable-buffer APIs need pin/copy/reject hardening.
