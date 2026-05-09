# 00 — Canary

A planted bug used to verify that the lab actually triggers ASan. If
`triage.sh harnesses/00-canary/heap-overflow.js` does **not** produce an ASan
report, the build is broken and any "no crash" result from a real harness is
meaningless.

## Why this exists

Empty corpus + no crashes = "I'm finding zero bugs" or "my pipeline is
silently broken." A canary distinguishes the two. Run it after every build.

## Running

```sh
lab/scripts/triage.sh lab/harnesses/00-canary/heap-overflow.js
```

Expected: ASan reports `heap-buffer-overflow` and `triage.sh` prints
`NEW CRASH: <hash>`.

## How the bug is reached

`heap-overflow.js` uses `bun:ffi` to call libc `malloc(8)`, then libc
`memcpy` writes 32 bytes into it. ASan's malloc interceptor places redzones
around the allocation; the OOB write trips
`heap-buffer-overflow ... WRITE of size 32`.

### Why malloc, not Uint8Array?

An earlier version of this canary used `new Uint8Array(8)` as the
destination. **That doesn't work** — JSC allocates ArrayBuffer storage in
the **Gigacage**, a pre-allocated arena outside libc's malloc. ASan's
malloc interceptor never sees those allocations and can't enforce
redzones around them.

For the canary to be a valid sanity check, we have to route through libc
so the chunk lives in the ASan-instrumented heap. (This is also a useful
fact when writing real harnesses — bugs in code that *only* touches
Gigacage memory may not be ASan-visible, even if they're real.)

If `bun:ffi` ever stops being the canary mechanism (API removed, etc.),
swap to a different attack surface that's known to crash under ASan, e.g.
direct calls into a vendored library that uses libc heap.
