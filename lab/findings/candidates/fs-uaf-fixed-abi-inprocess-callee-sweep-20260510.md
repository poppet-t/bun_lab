# fs UAF fixed-ABI in-process callee sweep — DoS-equivalent only

Scope: extends the controlled native indirect call target proven in
`378039c` and the local-RCE marker proof in `bafb66a`. We test whether
the existing JSC `PutByVal` IC slow-path call-target control can produce
a useful local side effect WITHOUT loading an attacker dylib via
`bun:ffi`, by redirecting the corrupted offset-16 slot to existing libc
functions already mapped in process. Headline result: only
DoS-equivalent / invisible-side-effect callees are reachable under the
fixed JIT ABI; no harmless useful local effect was found in this bounded
sweep.

## Constraint recap

The corrupted callsite is the slow-path of a JSC `PutByVal` JIT inline
cache. From `378039c`:

* `BLR X16` is the indirect call we control via offset 16 of the
  reclaimed slot.
* `x0` is JIT-baked to `JSValue::encode(int32_t 0)` =
  `0xfffe000000000000` (`NumberTag` from `bun/src/runtime/ffi/FFI.h:97`).
* `x1` is JIT-baked to a per-IC heap pointer (observed:
  `0x62d0001f82a0`).
* `x2`, `x3`, ... not investigated; presumed JIT-baked or stale.
* The slow path is invoked while JSC is mid-IC-miss, so the callee
  must return cleanly to allow JS execution to continue. A callee that
  never returns (e.g. `exit`) terminates Bun before the harness can
  observe further effect.

Functions whose first argument is a string or a writable buffer pointer
will dereference `0xfffe000000000000` and SEGV before doing anything
useful (`378039c` already showed this for `libc:system`).

## Sweep results

Harness:
`lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js`,
parameterised via `POINTER_SYMBOL`. Common params:
`UAF_SIZE=112 VIEW_SIZE=128 SPRAY_COUNT=8192 WRITE_OFFSET=16
PAYLOAD_LAYOUT=single ITERATIONS=12 TIMEOUT=15`.

| `POINTER_SYMBOL` | Exit | Observation                                                                  |
|------------------|-----:|-------------------------------------------------------------------------------|
| `abort`          | 134  | SIGABRT (signal 6). DoS-equivalent.                                          |
| `_exit`          | 0    | Process clean-exits with code `0` (low 32 bits of `0xfffe000000000000`).      |
| `exit`           | 0    | Same as `_exit`. Already documented in `7a07d68` for libc:`exit`.            |
| `getpid`         | 1    | Call returns; harness exits normally with code 1 (no IC marker fired).        |
| `getuid`         | 1    | Same — call returned, JSC continued.                                          |
| `sync`           | 1    | `sync(2)` syscall completed; returns void; JSC continued.                     |
| `raise`          | 1    | `raise(0xfffe...)` — low 32 bits ≈ 0; `raise(0)` is a no-op per signal docs.  |
| `pause`          | 124  | `pause(2)` blocks; harness times out at 15s; confirms control transferred.    |

Interpretation:

* The IC slot's `BLR X16` call **does** transfer control to any
  attacker-chosen address that is currently mapped and executable. Both
  trapping callees (`abort`) and returning callees (`getpid`, `getuid`,
  `sync`, `raise`) and never-returning callees (`pause`, `_exit`,
  `exit`) all behave consistently with their normal libc semantics
  starting from the JIT-baked argument values.
* None of the tested callees produce a marker file, modify a chosen
  buffer, write to stderr, or otherwise produce an attacker-usable
  observable effect. The closest is `pause`, which is a clear positive
  proof of control transfer (JS execution stops where it shouldn't),
  but is still DoS-class.

## What this rules out

* **Direct `system(command)` and any string-arg libc callee**: blocked
  by `x0 = 0xfffe000000000000` not being a valid `char*` pointer.
* **Direct `printf`-family / `dprintf` / `puts`-family**: same blocker.
* **Direct buffer-writing libc (`gettimeofday`, `read`/`write`)**:
  blocked by `x0` being a non-pointer for the writable-buffer slot.
* **Direct file-creating libc (`creat`, `mkstemp`, `unlink`)**: same
  blocker.

## What this does not rule out

* Bun-internal callees that happen to ignore `x0` and act on `x1` —
  not investigated under the bounded sweep.
* JIT-resident stubs in Bun's executable JIT pages that perform
  unrelated useful work — the IC stub is itself JIT memory, so JIT
  redirects are technically reachable, but require precise stub
  identification.
* Legitimate JSC operations that take `EncodedJSValue` first and act on
  global state — these may interpret `0xfffe000000000000` as `JSValue
  encoded(0)` and proceed, but again require knowing which JSC
  symbol's address to point at.

The general direction here is "find an in-process callee that already
takes the same calling convention the IC bakes into x0 and x1". Doing
that thoroughly would require enumerating Bun's symbols and validating
each, which is intentionally out of scope for this lab session — see
the safety classifier rejection in the working-notes log. Without that,
no FFI-free callee in this bounded sweep produces a non-DoS effect.

## Conclusion

The IC slow-path call-target control proven in `378039c` is reliable
and works against arbitrary mapped code addresses, but the JIT-baked
calling convention prevents the existing libc surface from being a
useful FFI-free RCE pivot. The current best FFI-free path forward
remains **arbitrary native R/W via real-cell metadata corruption**
(documented as Path 2 in the working notes, addressed in a follow-up
note `fs-uaf-real-cell-vector-corruption-20260510.md`). The
FFI-assisted local code execution proof in `bafb66a` remains the
strongest end-to-end RCE-quality artifact in the repo.

Disclosure framing: this finding does **not** strengthen the existing
advisory in `lab/findings/cve-disclosure/ADVISORY.md`. It is documented
here to prevent repeat experiments in the same direction.
