# 05 — bun:ffi binding layer

`bun:ffi` lets JS call native code. Calling C with a wrong pointer is unsafe
**by design** — that's not a Bun bug. We're hunting bugs in the *binding
layer*: how Bun marshals JS values to C calls, how it dispatches return
values, how it converts struct-by-value layouts.

## Risk model

`bun:ffi` is exposed to any JS that imports `bun:ffi`. If the binding layer
mishandles, e.g., a struct-by-value with packed alignment, you get
deterministic stack/heap corruption from JS that obeys all the FFI type
rules. That's a real bug.

## Files

- `args-edge.js` — exercises argument-marshaling edges: extreme integers,
  NaN/Infinity floats, function-pointer round-trips, struct-by-value
  variants, detached ArrayBuffer pointers, ptr() of zero-length / huge
  TypedArrays.
- `callback-lifetime.js` — registers a JS callback as a C function pointer,
  drops the JS reference, then triggers GC and calls back. Probes
  ref-keeping in the callback-table.

## Caveat

It's easy to write an FFI test that *looks* like a bug but is just wrong
usage. When you hit a crash here, before filing a finding, prove the
binding-layer is at fault by re-running with the same C side and a
*correctly-typed* call — if that crashes too, it's a binding bug; otherwise
it's user error.
