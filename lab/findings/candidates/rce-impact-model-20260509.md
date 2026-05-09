# RCE impact model - 2026-05-09

This note explains the exploitability implications of the currently confirmed primitives without recording a weaponized exploit chain.

## Confirmed primitives

### Controlled stale write: async `fs.read` / `fs.readv`

Confirmed behavior:

- The destination ArrayBuffer is captured for async FS work.
- User JS detaches the backing store before the worker read completes.
- Same-size ArrayBuffer allocations can reclaim that freed storage.
- Bytes read from an fd are written through the stale native pointer into the reclaimed allocation.

Why this matters:

- This is stronger than a crash. It proves attacker-controlled bytes can be redirected into a fresh same-process allocation.
- `readv` is especially interesting because it can snapshot multiple raw destination pointers and because the rooted outer array can be mutated after scheduling.

What is still missing for RCE:

- A reliable reclaim target whose corrupted contents can produce arbitrary read/write or control-sensitive state.
- A way to make the stale write land at a useful offset in that target.
- A layout or information-leak primitive if the final target requires absolute addresses.
- A mitigation story for allocator behavior, ASLR, W^X/JIT protections, and platform pointer-authentication where applicable.

High-level attacker model:

- If attacker-controlled JS runs inside a Bun process with access to `node:fs`, it can schedule async reads into buffers it later detaches.
- If the attacker can influence the fd contents, the stale write is byte-controlled.
- If heap grooming can place a sensitive object or a typed-array backing store where the freed buffer was, the stale write may become a stronger memory primitive.

### Random stale write: async `crypto.randomFill`

Confirmed behavior:

- Async `randomFill` stores a raw ArrayBuffer pointer.
- User JS detaches the backing store before worker execution.
- The worker writes CSPRNG bytes through the stale pointer.

Why this matters:

- It confirms the same lifetime bug class independently in another async native API.
- It is less directly useful for RCE because the bytes are random, not attacker-selected.

## Candidate remote peer issue

### MySQL length-encoded field overflow

Current state:

- Z3 confirms the `offset + length` capacity check can wrap.
- Static source review shows length-encoded fields can reach string/raw-buffer copy paths.
- No full fake-server dynamic proof was built in this pass.

RCE relevance:

- This is more interesting for remote reachability because a malicious or compromised MySQL server controls the protocol bytes.
- The observed primitive is currently OOB read / bogus slice / huge copy class, not controlled write.

## Practical severity framing

The strongest CVE-quality memory-corruption issue is the async writable-buffer lifetime bug class:

- `crypto.randomFill`: confirmed UAF write, random bytes.
- `fs.read`: confirmed controlled stale write.
- `fs.readv`: confirmed controlled stale write.

The strongest RCE candidate is `fs.readv`, because it offers controlled bytes and multiple captured destination pointers. It still needs a non-weaponized arbitrary read/write proof or a clear corrupted-object impact proof before claiming practical RCE.
