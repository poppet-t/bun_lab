# 08 — TypedArray / DataView / SAB / detach race

JS↔native length checks at the ArrayBuffer / TypedArray boundary are a
historical bug source for every JS engine. Bun has its own boundary
shims (`bun/src/jsc/array_buffer.zig`, `bun/src/jsc/JSValue.zig`) on top of
JSC. Concurrent detach (transfer to Worker) while another thread reads the
view is a classic TOCTOU.

## Files

- `boundary.js` — TypedArray slicing edges, detached buffers, DataView
  alignment, SharedArrayBuffer + Atomics with hostile sizes.
- `detach-race.js` — opens N workers, transfers ArrayBuffers around while
  another worker is mid-`set()`. Looks for use-after-detach.
