# wasm descriptor system ABI probe

Date: 2026-05-10

Scope: targeted attempt to upgrade the WebAssembly dispatch primitive into
standalone native `system(command)` execution. This is local lab-only and uses
`bun:ffi` strictly as an address oracle for `dlsym("system")` and
`ptr(commandBytes)`. It is not no-FFI exploit evidence.

## Harness

New harness:

- `lab/harnesses/13-arb-rw-probes/wasm-descriptor-system-i64-probe.js`

Shape:

1. build the existing UAF -> addrof -> ArrayBuffer metadata bridge;
2. create same-signature wasm exports with type `(i64) -> i32`;
3. resolve libc `system` with `dlsym`;
4. keep a NUL-terminated command string alive and refresh its native pointer
   immediately before the forged call;
5. forge the wasm descriptor's first qword to the resolved `system` address;
6. call `a(commandPointerBigInt)`.

Goal: if the forged descriptor target receives the wasm `i64` argument in `x0`,
`system(commandPointer)` should create `/tmp/bun_uaf_descriptor_system_probe`.

## Result 1: system is reached, but the command pointer is stale

Run:

- `lab/findings/runs/20260510T123704Z-97471/asan.log`

Command:

```sh
FAKE_DESCRIPTOR=1 FAKE_DESCRIPTOR_MODE=system EXTRA_CELL_FIELDS=40 \
SYSTEM_PROBE_PATH=/tmp/bun_uaf_descriptor_system_probe \
SYSTEM_COMMAND="printf 'descriptor-system-success:%s\n' \"$$\" > /tmp/bun_uaf_descriptor_system_probe" \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/wasm-descriptor-system-i64-probe.js
```

Observed:

```text
sh: @...: command not found
```

Key facts:

```json
{
  "systemPointer": "0x000000018a3f6368",
  "systemCommandPointer": "0x000062d000338250",
  "fakeDescriptorWord": "0x000000018a3f6368",
  "patchedA": 32512,
  "restoredA": 42,
  "systemProbeAfter": false,
  "ok": false
}
```

Initial interpretation, later corrected by Result 3:

- The forged descriptor can call an arbitrary native executable address;
  `system` returned a shell-style `127` (`32512 == 127 << 8`).
- The shell tried to execute a short garbage string from the pointer supplied
  in `x0`.
- Result 3 shows this was a stale command-buffer pointer, not lack of native
  `x0` control.

## Result 2: forcing cell offset 40 to the command pointer hangs

Follow-up change:

- for `FAKE_DESCRIPTOR_MODE=system`, the harness temporarily forces extra cell
  field offset `40` to the command pointer rather than module B's context-like
  field.

Run:

- started as `lab/findings/runs/20260510T123746Z-99430/asan.log`
- the ASan Bun child wedged for more than five minutes with no proof file
- the wrapper was terminated manually; the child remained in an uninterruptible
  state briefly after `SIGKILL`

Interpretation:

- Offset `40` is not a safe direct substitute for `x0`.
- The raw descriptor call path depends on JSC/wasm context state beyond the
  descriptor qword. Replacing that context with a command string pointer breaks
  the call path before a useful `system(command)` result.

## Result 3: late pointer refresh gets standalone native system(command)

Runs:

- `lab/findings/runs/20260510T133916Z-77172/asan.log` — `JSCallback`
  descriptor target receives the wasm argument and returns `31337`.
- `lab/findings/runs/20260510T134225Z-85934/asan.log` — native helper
  `record_args(a0..a7)` confirms raw `a0 == wasmArgValue`.
- `lab/findings/runs/20260510T134439Z-89310/asan.log` — after refreshing
  `ptr(commandBuffer)` immediately before the forged call, native helper
  shows `a0_bytes` is `descriptor-arg-ok\0`.
- `lab/findings/runs/20260510T134457Z-90384/asan.log` — direct libc
  `system(command)` succeeds.

Key final facts:

```json
{
  "systemPointer": "0x000000018a3f6368",
  "systemCommandPointer": "0x000062d000340250",
  "systemCommandPointerBytes": "7072696e7466202764657363726970746f722d73797374656d2d737563636573",
  "fakeDescriptorWord": "0x000000018a3f6368",
  "patchedA": 0,
  "restoredA": 42,
  "systemProbeAfter": true,
  "systemProbeText": "descriptor-system-success:90384\n",
  "ok": true
}
```

The earlier `sh: @...: command not found` result was caused by a stale
native pointer captured before the GC-heavy bridge setup. The stale pointer
still numerically propagated through `x0`, but it no longer pointed at the
command bytes by the time `system` ran. Refreshing `ptr(commandBuffer)` after
all bridge construction and descriptor reads fixes that.

## Current conclusion

This branch now gets standalone native `system(command)` in the local lab
under address-oracle assumptions.

What it did prove:

- forged wasm descriptor qword -> arbitrary native callee reaches libc
  `system`;
- the wasm `i64` argument is passed as raw native `x0`;
- a stale pre-GC `ptr()` value is not reliable for command storage, but a
  late-refreshed command pointer is reliable enough for this proof;
- the final command side effect is direct native libc `system(command)`, not
  an attacker-provided wasm host import.

Caveat: the proof still uses `bun:ffi` as a local address/pointer oracle
(`dlsym("system")`, `ptr(commandBuffer)`) and does not demonstrate a no-FFI
ASLR/PAC bypass or remote request reachability.
