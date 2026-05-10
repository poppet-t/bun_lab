# fs UAF no-FFI WebAssembly export marker control

Date: 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. This is local-JS-only. It does not use `bun:ffi`, a native
helper dylib, `dlsym`, broad symbol enumeration, or a remote service path.

## Summary

The no-FFI `addrof` -> ArrayBuffer metadata bridge can now be used for a
control-flow-relevant write into WebAssembly export metadata.

New harness:

`lab/harnesses/13-arb-rw-probes/wasm-export-code-pointer-redirect-probe.js`

The harness builds on the earlier native-view primitive:

1. Use the 8KB object-array reclaim leak to get `addrof(ArrayBuffer)`.
2. Use the 128-byte ArrayBuffer metadata reclaim at offset `16` to create a
   restorable native memory view over known valid in-process addresses.
3. Read two same-signature WebAssembly export function cells.
4. Patch export `a`'s function cell offset `48` with export `b`'s value at the
   same offset.
5. Call export `a`.
6. Restore export `a`'s original offset-48 value.

With two pure-return exports, this changes `a()` from `42` to `7`, then restores
`a()` to `42`.

In marker mode, export `b` is a same-signature WebAssembly function that calls a
JS import `env.mark`. The import is warmed while disarmed, the marker file is
removed, then export `a` is corrupted and called. The marker file is created
only after the offset-48 metadata patch, and `a()` restores to `42` afterward.

This is the strongest FFI-free control-flow artifact so far. It demonstrates a
memory-corruption-driven redirect from one WebAssembly export body to another
same-signature export body with a marker side effect.

## Validation

Command:

```sh
rm -f /tmp/bun_uaf_noffi_wasm_marker
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 MARKER_IMPORT=1 MARKER_PATH=/tmp/bun_uaf_noffi_wasm_marker \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/wasm-export-code-pointer-redirect-probe.js
```

Environment:

* Bun binary: `bun/build/release-asan/bun-asan`
* Bun version: `1.3.14`
* ASAN: enabled
* FFI: no
* Native helper dylib: no
* WebAssembly: yes
* JIT / wasm warming: yes, `WARM_ITERATIONS=10000`
* UAF sizes:
  * `8192` for object-array `addrof`
  * `128` for ArrayBuffer metadata bridge
* Reclaim carrier: sprayed `Uint8Array(new ArrayBuffer(128))`
* Stale write offset: `16` in the 128-byte metadata bridge carrier
* Corrupted final target: WebAssembly export `a` function cell offset `48`
* Marker path: `/tmp/bun_uaf_noffi_wasm_marker`

Representative run:

`lab/findings/runs/20260510T085231Z-63521/asan.log`

Result:

```text
[triage] exit=86
[triage] no crash signature found
```

Key redacted facts:

```json
{
  "markerImport": true,
  "markerPath": "/tmp/bun_uaf_noffi_wasm_marker",
  "markerBefore": false,
  "markerAfter": true,
  "patchScope": "cell",
  "patchField": 48,
  "originalPatchValue": "0x0000603000036558",
  "replacementPatchValue": "0x0000603000036560",
  "beforeA": 42,
  "beforeB": 7,
  "patchedA": 7,
  "restoredA": 42,
  "ok": true
}
```

Earlier confirming run:

`lab/findings/runs/20260510T085207Z-62446/asan.log`

This run also produced:

```text
/tmp/bun_uaf_noffi_wasm_marker
wasm-marker:<pid>
```

## Interpretation

The offset-48 field in the WebAssembly export function cell is per-export and
dispatch-relevant under this build. Swapping export `a`'s field with export
`b`'s field does not merely change a JS-visible property; it changes which wasm
export body runs when `a()` is called.

The low image-range pointers observed in the nested executable metadata at
offsets `24` and `32` are not sufficient by themselves for this redirect. In
the tested module, those pointers were shared between exports and behaved like
common wrapper/trampoline pointers. Patching the shared low-code pointer did not
change `a()`'s return value.

The useful field found here is a heap pointer in the function cell:

* export `a` cell offset `48`: original per-export target metadata
* export `b` cell offset `48`: replacement per-export target metadata

After the write:

* `a()` returns `7` instead of `42`
* marker mode creates `/tmp/bun_uaf_noffi_wasm_marker`
* restoring the original qword makes `a()` return `42` again

## Current impact

Confirmed:

* no-FFI native memory view over known valid in-process addresses
* no-FFI write to a WebAssembly export function cell
* no-FFI redirect from one same-signature wasm export body to another
* marker file creation through the redirected wasm export path
* clean restoration of the corrupted export metadata after the call

Not demonstrated:

* arbitrary native shellcode execution
* writing executable/JIT code memory
* ASLR / W^X / PAC bypass
* a layout-independent arbitrary native read/write primitive
* remote/request-path reachability

## Disclosure framing

This should be framed conservatively as **FFI-free WebAssembly export
control-flow redirection with a marker side effect**, not as a generic native
shellcode RCE chain.

The marker side effect is reached through attacker-supplied WebAssembly code and
a JS import that the local attacker provided. That is still valuable because the
call to export `a` reaches export `b`'s body only after native metadata is
corrupted by the `fs.read` UAF chain, and no FFI or native helper module is used.
It does not prove a standalone ASLR/W^X/PAC bypass or remote exploitability.
