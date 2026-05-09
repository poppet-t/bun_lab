# UAF Pattern Audit: 2026-05-09

**Status:** no confirmed UAF yet
**Scope:** local Bun checkout, memory-lifetime audit
**Z3:** `/usr/local/bin/z3` is broken (`ModuleNotFoundError: z3.snap`); `/usr/local/opt/z3/bin/z3` works

## Summary

This pass looked for borrowed byte slices crossing user callbacks, GC/finalizer paths that close or free native storage, and APIs that transfer raw pointer ownership into JS buffers.

The current result is mostly mitigated UAF-shaped patterns:

- WebSocket server receive data is borrowed from uWS, but Bun copies it before exposing it to JS.
- SQL raw result cells borrow packet bytes, but `SQLClient.cpp` copies raw cells into JS buffers during row construction before the row is deinitialized.
- uSockets group/listener teardown has explicit guards around listener ownership and semi-open socket detachment.
- UDP `sendMany()` and MySQL bind parameters have comments and code that root/pin payloads across re-entrant user JS.

No disclosure-ready UAF was confirmed in this pass.

## WebSocket Receive Borrow

uWS calls Bun with `std::string_view(data, length)` from its receive/decompression buffer:

- `bun/packages/bun-uws/src/WebSocketContext.h:131`
- `bun/packages/bun-uws/src/WebSocketContext.h:192`
- `bun/src/uws_sys/libuwsockets.cpp:731`
- `bun/src/uws_sys/libuwsockets.cpp:789`
- `bun/src/uws_sys/WebSocket.zig:236`

The server binding converts before invoking JS:

- text: `bun.String.createUTF8ForJS(globalObject, message)`
- binary: `this.binaryToJS(globalObject, message)`

`binaryToJS()` uses `jsc.ArrayBuffer.createBuffer()` / `jsc.ArrayBuffer.create()`, which call `Bun__createUint8ArrayForCopy` / `Bun__createArrayBufferForCopy`.

Relevant lines:

- `bun/src/runtime/server/ServerWebSocket.zig:119`
- `bun/src/runtime/server/ServerWebSocket.zig:147`
- `bun/src/runtime/server/ServerWebSocket.zig:215`
- `bun/src/jsc/array_buffer.zig:168`
- `bun/src/jsc/bindings/JSBuffer.cpp:432`

Assessment: not a retained borrowed-buffer UAF as written, because the JS-visible object is a copy.

## WebSocket Decompression Tail Write

The permessage-deflate path temporarily writes past `compressed.data() + compressed.length()`:

- `bun/packages/bun-uws/src/PerMessageDeflate.h:240`
- `bun/packages/bun-uws/src/PerMessageDeflate.h:242`
- `bun/packages/bun-uws/src/PerMessageDeflate.h:243`
- `bun/packages/bun-uws/src/PerMessageDeflate.h:254`
- `bun/packages/bun-uws/src/PerMessageDeflate.h:260`

Complete-frame server parsing passes `src + MESSAGE_HEADER - 4` into the fragment handler:

- `bun/packages/bun-uws/src/WebSocketProtocol.h:296`
- `bun/packages/bun-uws/src/WebSocketProtocol.h:299`

The receive buffer is allocated with 32 bytes of padding on each side:

- `bun/packages/bun-usockets/src/libusockets.h:65`
- `bun/packages/bun-usockets/src/loop.c:74`
- `bun/packages/bun-usockets/src/loop.c:581`

Z3 model:

```smt2
(set-logic QF_LIA)
(declare-const H Int)
(declare-const L Int)
(declare-const P Int)
(assert (>= H 6))
(assert (>= P 0))
(assert (>= L 0))
(assert (<= (+ P H) L))
(assert (> (+ (- H 4) P 9) (+ L 32)))
(check-sat)
```

Result: `unsat`. Under the complete-frame precondition `P + H <= L`, the 9-byte libdeflate tail write cannot exceed the 32-byte post-padding.

A second model showed that an exact-fit frame needs 5 bytes of post-padding because the server path starts 4 bytes before the payload. With padding `< 5`, Z3 returns `sat`.

Assessment: not a current overflow/UAF with the present libusockets padding. This is a brittle invariant worth regression-testing if receive-buffer allocation changes.

## SQL Raw Cells

Raw MySQL result decoding stores borrowed packet bytes:

- `bun/src/sql_jsc/shared/SQLDataCell.zig:122`
- `bun/src/sql_jsc/mysql/protocol/DecodeBinaryValue.zig:10`
- `bun/src/sql_jsc/mysql/protocol/ResultSet.zig:176`

Readers return `Data.temporary` pointing into the packet/read buffer:

- `bun/src/sql_jsc/mysql/MySQLConnection.zig:812`
- `bun/src/sql/mysql/protocol/StackReader.zig:51`
- `bun/src/sql/shared/Data.zig:41`

But row conversion copies raw cells into new JS buffers before `row.deinit()`:

- `bun/src/sql_jsc/mysql/JSMySQLConnection.zig:687`
- `bun/src/sql_jsc/mysql/JSMySQLConnection.zig:694`
- `bun/src/sql_jsc/mysql/protocol/ResultSet.zig:21`
- `bun/src/jsc/bindings/SQLClient.cpp:139`
- `bun/src/jsc/bindings/SQLClient.cpp:144`

Assessment: not an immediate UAF as written. Remaining risk would require proving a path where raw cells outlive the packet buffer before `SQLClient.cpp` copies them; I did not find one in this pass.

## Native Buffer Ownership API

`jsc.JSValue.createBuffer()` transfers ownership of the passed slice to JSC and frees it with `MarkedArrayBuffer_deallocator`:

- `bun/src/jsc/JSValue.zig:585`
- `bun/src/jsc/bindings/JSBuffer.cpp:351`

This API is dangerous if called with borrowed memory or if the caller frees the slice after transfer. Audited call sites found expected ownership handoffs:

- PBKDF2 async clears `this.output` after transfer before `deinit()`.
- Zstd/archive paths use default-allocator output or duplicate borrowed stores.
- Image encode paths use codec-specific finalizers via `createBufferWithCtx()`.
- FFI exposes raw pointer wrapping by design; this is unsafe API surface, not a Bun memory-safety bug by itself.

Worth continuing: grep new call sites to `JSValue.createBuffer` and require an ownership proof at each call.

## Existing UAF Guardrails

The codebase contains explicit fixes/guards around prior UAF hazards:

- uSockets group teardown avoids freeing listener sockets owned by Zig/JS wrappers:
  - `bun/packages/bun-usockets/src/context.c:79`
  - `bun/packages/bun-usockets/src/libusockets.h:300`
- TLS socket ALPN avoids listener-level callback data for per-connection state:
  - `bun/src/runtime/socket/socket.zig:14`
- Socket flush avoids re-entering `markInactive()` after detach:
  - `bun/src/runtime/socket/socket.zig:1318`
- Duplex upgrade nulls `tls` before paths that consume refs:
  - `bun/src/runtime/socket/socket.zig:1926`
- UDP `sendMany()` roots payloads and delays raw pointer borrowing until after re-entrant JS:
  - `bun/src/runtime/socket/udp_socket.zig:607`
  - `bun/src/runtime/socket/udp_socket.zig:682`
- MySQL bind values pin/root array buffers across parameter coercion:
  - `bun/src/sql_jsc/mysql/MySQLValue.zig:116`
  - `bun/src/sql_jsc/mysql/MySQLValue.zig:212`

These are useful fuzz/review targets because they document exact bug classes that were previously plausible.

## Next Leads

- Build a focused harness for socket finalization/re-entrancy: user callbacks that close/detach/GC while a native callback is still unwinding.
- Continue auditing `JSValue.createBuffer()` call sites. Any borrowed slice passed there is potentially a UAF/double-free.
- Variant-check SQL raw row paths under exception/OOM during `SQLClient.cpp` conversion. The normal path copies before deinit; exceptional paths are the area most worth stress-testing.
- Add a regression/model test for the WebSocket tail-write padding invariant so future changes to `LIBUS_RECV_BUFFER_PADDING` or the `src + MESSAGE_HEADER - 4` convention fail loudly.
