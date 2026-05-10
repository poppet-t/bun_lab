# fs UAF addrof -> ArrayBuffer metadata native R/W bridge

Date: 2026-05-10

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF. This is still local-JS-only. It does not use `bun:ffi`, a
native helper dylib, broad symbol enumeration, or a remote service path.

## Summary

The 128-byte ArrayBuffer/view metadata reclaim class can now be combined with
the existing 8KB object-array `addrof` primitive to build a no-FFI native memory
view over known in-process addresses.

New harness:

`lab/harnesses/13-arb-rw-probes/addrof-arraybuffer-metadata-arw-bridge.js`

Two-step model:

1. Use the existing object-array leak to obtain `addrof(victimBuffer)`.
2. Use `UAF_SIZE=128 WRITE_OFFSET=16` to point a fresh bridge view at the
   victim `ArrayBuffer` wrapper.
3. Read wrapper offset `16`, which points to the actual 128-byte ArrayBuffer
   metadata object.
4. Use a second `UAF_SIZE=128 WRITE_OFFSET=16` bridge to point at that metadata
   object.
5. The second-stage metadata object has the direct layout seen in the earlier
   128-byte reclaim triage:
   * offset `16`: backing data pointer
   * offset `48`: current byteLength
   * offset `56`: max byteLength
6. Rewriting offset `16` to `data + 16` makes a fresh
   `new Uint8Array(victimBuffer)` alias the shifted native backing address.
7. Restoring offset `16` returns the victim buffer to its original data pointer.

This is stronger than the previous crash-only 128-byte result. It demonstrates
that the pointer field can be used as a controlled native memory view when
the target address is valid and known.

## Validation

Command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=240 BRIDGE_ATTEMPTS=64 SPRAY_COUNT=16384 REQUIRE_LENGTH_FIELDS=0 \
SECOND_STAGE=1 SECOND_STAGE_MUTATE=1 CELL_READ=1 SCAN_BYTES=64 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/addrof-arraybuffer-metadata-arw-bridge.js
```

Run:

`lab/findings/runs/20260510T083155Z-22979/asan.log`

Result:

```text
[triage] exit=86
[triage] no crash signature found
```

Key redacted facts from the run:

```json
{
  "victimAddress": "0x000060f000010648",
  "wrapperOffset16": "0x000060c000047b00",
  "metadata": {
    "dataPtr": "0x000060c0000481c0",
    "byteLength": "0x80",
    "maxByteLength": "0x80"
  },
  "mutation": {
    "shiftedPtr": "0x000060c0000481d0",
    "shiftedFirstBefore": 176,
    "shiftedFirstAfter": 90,
    "originalAtShiftAfter": 90,
    "restoredFirst": 160,
    "ok": true
  },
  "cellRead": {
    "cellAddress": "0x000062d000181270",
    "cellPrefixLength": 32,
    "ok": true
  }
}
```

Interpretation:

* `addrof(victimBuffer)` disclosed the JS wrapper address.
* Wrapper offset `16` disclosed the address of a 128-byte ArrayBuffer metadata
  object.
* The second-stage bridge read that metadata object and recovered the backing
  pointer plus length fields.
* Rewriting metadata offset `16` to `data + 16` caused a fresh victim view to
  read the byte originally at backing offset `16`.
* Writing through that shifted fresh view changed the original backing byte at
  offset `16`.
* Restoring the metadata pointer made a fresh victim view read the original
  first byte again.
* Retargeting the metadata pointer to `addrof(cellTarget)` allowed a 32-byte
  JSCell prefix read, then the pointer was restored.

## Earlier one-stage alias proof

The simpler fresh-view alias harness also confirms the 128-byte offset-16
field can redirect a target ArrayBuffer/view to another leaked backing pointer.

Harness:

`lab/harnesses/13-arb-rw-probes/arraybuffer-metadata-fresh-view-alias-probe.js`

Run:

`lab/findings/runs/20260510T082013Z-96032/asan.log`

Result before expected teardown crash:

```json
{
  "result": "alias-confirmed",
  "leakOffset": 16,
  "leakedPointer": "0x000060c000048dc0",
  "targetIndex": 3,
  "freshFirstBeforeWrite": 49,
  "freshFirstAfterWrite": 90,
  "sourceHitsAfterWrite": [{ "sourceIndex": 32, "value": 90 }]
}
```

That run later crashed during finalization because the corrupted target tried
to free a borrowed pointer. The two-stage bridge restores the victim metadata
before exit and avoids that teardown crash in the representative run above.

## Current impact

Confirmed:

* no-FFI bridge from `addrof(ArrayBuffer)` to its native metadata object
* no-FFI read of ArrayBuffer metadata fields
* no-FFI write to ArrayBuffer metadata offset `16`
* fresh JS view retargeted to a chosen valid native address (`data + 16`)
* write through the retargeted fresh view changes the chosen native address
* fresh JS view retargeted to `addrof(plainObject)` can read a JSCell prefix
* metadata pointer can be restored cleanly after the operation

Not yet confirmed in this bridge-only harness:

* standalone native marker execution without FFI or an attacker-supplied
  WebAssembly/import path
* a stable call target with useful arguments
* writing executable/JIT code memory
* ASLR/W^X/PAC bypass
* remote/request-path reachability

## RCE relevance

This is the strongest FFI-free primitive so far. It closes the previous gap
between `addrof` and a useful native memory view: known in-process addresses can
now be read, and valid writable native addresses can be written through normal
JS typed-array operations after metadata retargeting.

It still should not be described as layout-independent arbitrary native R/W or
standalone native shellcode execution. The follow-up
`fs-uaf-noffi-wasm-export-marker-control-20260510.md` shows one no-FFI
control-flow use of this bridge: WebAssembly export metadata redirection with a
marker side effect. The remaining harder problem is a generic native-code chain,
such as a JIT-code patch, a JSC call-target patch with useful arguments, or
another native object corruption path that does not rely on attacker-supplied
wasm/import scaffolding.
