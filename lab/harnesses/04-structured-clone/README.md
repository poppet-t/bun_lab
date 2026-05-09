# 04 — Worker / structured-clone deserializer

Targets `worker.postMessage()` (and parent←→child IPC). Bun's IPC layer
length-prefixes serialized values; the deserializer walks the byte stream
into JS objects. Bugs here are reachable from any code that hosts a Worker.

## Risk model

In-process: a buggy worker library could pass attacker-influenced data to
another worker via `postMessage`. The deserializer walks a tree of
JS-object types; type-confusion bugs there can yield read primitives. Bun's
`SerializedScriptValue` derives from JSC's serializer — JSC has had
structured-clone bugs historically (see WebKit security advisories).

## Files

- `worker-roundtrip.js` — spawns a Worker and trades hostile structured-clone
  payloads back and forth. Checks for cycles, transferable abuse, mixed
  TypedArray views, deep recursion, and ArrayBuffer detach during clone.
