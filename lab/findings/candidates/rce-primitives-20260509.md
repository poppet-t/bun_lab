# RCE primitive scan - 2026-05-09

Scope: local static triage of Bun native code paths for memory-corruption primitives that could plausibly matter for RCE research. This note intentionally records root causes and validation direction, not weaponized exploit steps.

## Highest-signal candidates

### 1. Async native writes into stale JS ArrayBuffer backing stores

Status: confirmed. `crypto.randomFill` is dynamically confirmed under ASan as a write-after-free. `fs.read`/`readv` are dynamically confirmed as controlled stale writes into reclaimed same-size canary ArrayBuffers when sanitizer quarantine is disabled.

Surfaces:

- `fs.read` / `fs.readSync` async binding path: `src/runtime/node/node_fs.zig`
- `fs.readv` / `fs.writev`: `src/runtime/node/node_fs.zig`
- `crypto.randomFill`: `src/runtime/node/node_crypto_binding.zig`

Key code:

- `NewAsyncFSTask.create()` stores arguments, calls `args.toThreadSafe()`, then schedules work on `jsc.WorkPool`: `bun/src/runtime/node/node_fs.zig:356`.
- `Arguments.Read.toThreadSafe()` only roots the JS value with `this.buffer.buffer.value.protect()`: `bun/src/runtime/node/node_fs.zig:2560`.
- Worker-side `readInner()`/`preadInner()` calls `args.buffer.slice()` and passes that slice to `Syscall.read`/`Syscall.pread`: `bun/src/runtime/node/node_fs.zig:4341`.
- `Arguments.Readv.toThreadSafe()` roots only `this.buffers.value` and clones the iovec list: `bun/src/runtime/node/node_fs.zig:1430`.
- `VectorArrayBuffer.fromJS()` snapshots raw `byteSlice()` pointers into `bun.PlatformIOVec`: `bun/src/runtime/node/types.zig:840`.
- `ArrayBuffer.byteSlice()` trusts the captured `ptr`/`byte_len` in the copied `ArrayBuffer` struct: `bun/src/jsc/array_buffer.zig:324`.
- `crypto.randomFill()` stores `buf.slice().ptr`, roots only `buf_value`, and later fills `this.bytes[this.offset..][0..this.length]` on a worker: `bun/src/runtime/node/node_crypto_binding.zig:198` and `bun/src/runtime/node/node_crypto_binding.zig:418`.

Primitive shape:

- Single-buffer async APIs appear to root the JS object but not pin or revalidate the backing store. If the backing store is detached, transferred, resized, or reallocated after scheduling, the worker can write through a stale native pointer.
- `readv` is stronger: it snapshots raw iovec pointers and later protects only the outer array. User JS can mutate the array after scheduling, potentially dropping the only rooted references to the original views/backing stores while the worker still owns their raw pointers.
- `writev` is the read-side counterpart: stale iovec pointers can become an out-of-lifetime native read into an fd.

RCE relevance:

- `fs.read`/`readv` are attacker-controlled native writes if the fd source is controlled. This is the most plausible RCE-class primitive found in this pass.
- `crypto.randomFill` is a native write but with random bytes, so it is more useful as memory corruption confirmation than as a directly controlled write.
- This is a local JS-to-native runtime memory safety issue. It is not, by itself, a network-only remote RCE unless a separate path runs attacker-controlled JS or exposes these APIs across a trust boundary.

Validation direction:

- `lab/harnesses/10-async-buffer-lifetime/async-randomfill-detach.js` confirms a heap-use-after-free write after `ArrayBuffer.prototype.transfer(0)`.
- Saved ASan log: `lab/findings/runs/20260509T-randomfill-uaf/asan-randomfill.log`.
- Crash note: `lab/findings/crashes/randomfill-async-detach-uaf/README.md`.
- `fs.read` and `fs.readv` regular-file harnesses completed 2,000 iterations without an ASan crash.
- FIFO-backed `fs.read` and `fs.readv` variants force the read to occur after detach. With default ASan quarantine, they did not crash, which is expected because kernel writes through `read(2)`/`readv(2)` are not necessarily checked by ASan instrumentation.
- `async-fs-read-canary.js` and `async-fs-readv-canary.js` confirm controlled stale writes when ASan quarantine is disabled: `fs.read` overwrote canary allocation 2 and `fs.readv` overwrote canary allocation 42 on the saved run.
- Saved controlled-write logs: `lab/findings/runs/20260509T-fs-controlled-stale-writes/fs-read-canary.log` and `lab/findings/runs/20260509T-fs-controlled-stale-writes/fs-readv-canary.log`.
- Crash/primitive note: `lab/findings/crashes/fs-async-detach-controlled-stale-write/README.md`.
- Hardening direction is to mirror the existing off-thread borrow/pin pattern (`JSC__JSValue__borrowBytesForOffThread` / `JSC__JSValue__unpinArrayBuffer`, documented at `bun/src/jsc/bindings/bindings.cpp:3336`) or copy buffers for worker-owned lifetime. Write-target APIs may need a mutable variant of that helper. Reject shared/resizable/growable buffers where pinning cannot make the pointer stable.

### 2. MySQL length-encoded fields can escape packet bounds

Status: medium-high confidence memory-safety candidate, remote-from-malicious-DB-server threat model.

Key code:

- `decodeLengthInt()` accepts 8-byte length-encoded integers into `u64`: `bun/src/sql/mysql/protocol/EncodeInt.zig:33`.
- `NewReader.encodeLenString()` decodes a length, skips the length prefix, then calls `read(@intCast(result.value))` without checking against remaining packet bytes: `bun/src/sql/mysql/protocol/NewReader.zig:69`.
- `StackReader.ensureCapacity()` checks `buffer.len >= offset + length` with unchecked addition: `bun/src/sql/mysql/protocol/StackReader.zig:13`.
- `StackReader.read()` then advances by `@intCast(count)` and returns `buffer[offset..this.offset.*]`: `bun/src/sql/mysql/protocol/StackReader.zig:51`.
- The fast socket path uses `StackReader` when there is no buffered partial packet: `bun/src/sql_jsc/mysql/MySQLConnection.zig:274`.
- The outer packet length is checked before command handling, but inner length-encoded field lengths are not bounded to that packet: `bun/src/sql_jsc/mysql/MySQLConnection.zig:346`.
- Text and binary result decoders consume these fields: `bun/src/sql_jsc/mysql/protocol/ResultSet.zig:167`, `bun/src/sql_jsc/mysql/protocol/DecodeBinaryValue.zig:151`.
- Raw cells later copy through `SQLClient.cpp`: `bun/src/jsc/bindings/SQLClient.cpp:140`.

Z3 arithmetic check:

- Model: `offset = 4`, `buffer_len = 32`, `count = 2^64 - 3`.
- Constraint: `(offset + count) mod 2^64 <= buffer_len`, while `count > buffer_len - offset`.
- Result: satisfiable. This confirms `StackReader.ensureCapacity()` can be bypassed by wraparound for attacker-chosen 64-bit length values.

Primitive shape:

- Likely first manifestation is a crash, bogus slice, huge allocation/copy, or OOB read as a malicious MySQL server feeds oversized length-encoded fields inside an otherwise complete packet.
- The raw-result path can move a bogus `ptr,len` into a C++ `createUninitialized(... length)` plus `memcpy`, so this should be treated as memory-safety relevant even if the first practical proof is a DoS.

RCE relevance:

- This is more remotely reachable than the JS-native buffer issue because the peer can be a compromised or malicious MySQL server.
- I did not find a controlled native write here. Current RCE relevance is OOB read/crash/huge copy across Zig/C++ boundaries, not a confirmed code-execution chain.

Hardening direction:

- Bound every length-encoded field to the current packet's remaining payload before `read()`.
- Change `ensureCapacity()` to use overflow-safe arithmetic, e.g. `length <= buffer.len - offset`, after checking `offset <= buffer.len`.
- Avoid `usize -> isize` skip casts for protocol-controlled lengths.

## Lower RCE relevance / hardening candidates

### WebSocket terminate during message callback leaves stale extension use

Status: medium confidence UB, low observed RCE relevance.

Key code:

- `WebSocketContext::onData()` captures `WebSocketData *`, calls `WebSocketProtocol::consume()`, then uses `asyncSocket` and `webSocketData` afterward: `bun/packages/bun-uws/src/WebSocketContext.h:311`.
- `WebSocketContext::onClose()` destructs the in-place `WebSocketData`: `bun/packages/bun-uws/src/WebSocketContext.h:277`.
- JS `ws.terminate()` calls `this.websocket().close()`: `bun/src/runtime/server/ServerWebSocket.zig:1095`.
- uSockets marks the socket closed and links it to a closed list for later free: `bun/packages/bun-usockets/src/socket.c:261`.

Primitive shape:

- If a server `message` callback calls `ws.terminate()` while `onData()` is inside `consume()`, `onClose()` can destruct the `WebSocketData`, then execution returns to `onData()` and reads stale extension state.
- The socket memory itself is not immediately freed in the observed code, so this is use-after-destructor/stale-object UB rather than a clear freed-chunk UAF.

Hardening direction:

- After `consume()`, short-circuit if `us_socket_is_closed(s)` before `uncork()`, `getBufferedAmount()`, or reading `webSocketData`.

### WebSocket overreads/overwrites rely on recv padding

Status: real logical overrun, currently protected by local allocation contract.

Key code:

- permessage-deflate temporarily reads/writes 4 or 9 bytes past `compressed.length()`: `bun/packages/bun-uws/src/PerMessageDeflate.h:240`.
- masked-frame unmask writes past logical frame chunks in imprecise fast paths: `bun/packages/bun-uws/src/WebSocketProtocol.h:246`.
- uSockets receive buffers include 32 bytes of post padding: `bun/packages/bun-usockets/src/libusockets.h:65`.

RCE relevance:

- Low in this tree because the callers appear to satisfy the padding contract.
- High fragility if the protocol code is reused with unpadded buffers.

### Postgres unknown-message skip desync

Status: protocol bug, not a memory-corruption primitive in this pass.

Key code:

- Unknown message handler skips `length - 1` after the 4-byte length was already read: `bun/src/sql_jsc/postgres/PostgresRequest.zig:382`.

RCE relevance:

- Low. This looks like parser desynchronization/DoS rather than OOB memory access.

## Triage summary

Best RCE primitive lead: async `fs.read`/`readv` stale backing-store writes, especially `readv` post-schedule array mutation and missing per-view pinning.

Best remote-from-peer memory-safety lead: MySQL length-encoded field overflow in `StackReader` fast path.

Worth hardening but unlikely to be standalone RCE: WebSocket post-close stale extension reads and padded-buffer logical overruns.
