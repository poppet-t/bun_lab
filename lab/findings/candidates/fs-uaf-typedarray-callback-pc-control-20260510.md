# fs UAF typed-array callback PC control - 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. This requires attacker-controlled local JS access to
`node:fs`; it is not request-reachable from the hardened CTF service.

## Harness

- `lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js`

The harness uses the async FIFO `fs.read` stale-write primitive against small
detached `ArrayBuffer` backing stores, then sprays typed-array-sized allocations.
`bun:ffi` is used only as a local diagnostic oracle for known pointer values
(`ptr()` / `dlsym()`), not as a service-reachable exploit primitive.

## New result

With `UAF_SIZE=112`, `VIEW_SIZE=128`, `SPRAY_COUNT=8192`, and
`WRITE_OFFSET=16`, writing a chosen 64-bit value into the reclaimed allocation
can become the crashing program counter during later cleanup.

Key logs:

- `lab/findings/runs/20260510T050027Z-67468/asan.log`
  - wrote the `ptr(source)` value
  - ASAN reported `pc 0x60c000048340`, matching the source backing pointer
- `lab/findings/runs/20260510T050246Z-72813/asan.log`
  - wrote `POINTER_OVERRIDE=0x4141414142424242`
  - ASAN reported `pc 0x4141414142424242`

This is a control-sensitive native corruption primitive, not just data-plane
ArrayBuffer length confusion.

## RCE attempt status

The harness can resolve real libc symbols with `dlopen`/`dlsym` and can keep a
NUL-terminated command buffer alive. A direct, non-UAF FFI finalizer control
check confirmed that `toArrayBuffer(ptr(command), 0, len, system)` invokes
`system(command)` on finalization in this local process. That proves the
resolved `system` pointer and command buffer are valid.

However, installing `system` through the UAF-controlled PC-shaped slot did not
execute the marker command:

- `lab/findings/runs/20260510T050734Z-80456/asan.log`
  - single-word `system` attempt
  - no `/private/tmp/bun_lab_uaf_system_proof`
- `lab/findings/runs/20260510T051047Z-85463/asan.log`
  - `PAYLOAD_LAYOUT=callback-command`
  - no marker file
- `lab/findings/runs/20260510T051106Z-86542/asan.log`
  - `PAYLOAD_LAYOUT=callback-zero-command`
  - no marker file
- `lab/findings/runs/20260510T051106Z-86548/asan.log`
  - `PAYLOAD_LAYOUT=callback-command-command`
  - no marker file
- `lab/findings/runs/20260510T052021Z-97841/asan.log`
  - custom offset-0 payload `command,commandLength,callback`
  - no marker file

The repeated failure mode is a `SEGV` reading `0xfffe000000000000`, with a PC
that is not the resolved `system` address. Current interpretation: the corrupted
slot is control-sensitive, but it is not a simple
`JSTypedArrayBytesDeallocator(data, ctx)` callback slot. The remaining blocker
is identifying the exact callsite/ABI, including any function-pointer
authentication or object-shape requirements on this macOS/arm64 build.

## Current boundary

Confirmed:

- fd-controlled bytes can corrupt a pointer-bearing typed-array/JSC allocation
- the corrupted value can reach native PC under the tested reclaim profile
- the harness supports fixed layouts and custom `PAYLOAD_WORDS` for follow-up
  field-layout probes

Not confirmed:

- `system(command)` through the UAF-controlled slot
- arbitrary native read/write
- a stable no-FFI exploit chain
- request-path reachability from `lab/ctf/bun-rce/challenge-server.js`

Next useful work:

- recover a reliable stack/callsite for the controlled-PC crash
- map the reclaimed 112-byte allocation type and field layout
- avoid assuming the slot uses the `ArrayBuffer` finalizer ABI until proven
- keep CTF verification separate: the current CTF solve is only the local
  static-asset symlink path, not remote RCE
