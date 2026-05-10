# OOB Array Bridge - 2026-05-10

Scope: local CTF primitive escalation from the confirmed async `fs.read`
double-array length corruption. New files are limited to
`lab/harnesses/15-oob-array-bridge/`.

All runs below used `/Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan`
through `lab/scripts/triage.sh` with ASan quarantine disabled.

## Harnesses

- `lab/harnesses/15-oob-array-bridge/double-oob-object-transition-copy.js`
- `lab/harnesses/15-oob-array-bridge/double-oob-float64array-bridge.js`

## Object-array bridge confirmed

Command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 TIMEOUT=90 ITERATIONS=24 lab/scripts/triage.sh lab/harnesses/15-oob-array-bridge/double-oob-object-transition-copy.js
```

Log:

- `lab/findings/runs/20260510T033935Z-97244/asan.log`

Result:

- clean triage exit `86`; no sanitizer crash
- corrupted source double array: `arrayIndex=368`, `length=2048`
- OOB overlap: relative index `256` maps to victim double array
  `arrayIndex=45`, element `0`
- after transitioning the overlapped victim slots to objects, the corrupted
  double array read object-reference bits at relative index `256`:
  `0x000062d00040aa10`
- writing those bits through relative index `257` changed the victim's next
  object slot from the sentinel to the anchor object by JS identity:
  `afterIsAnchor=true`

Assessment: this is a stable one-shot bridge from the fs UAF double-array
length corruption to object-array element storage. It provides an addrof-like
valid object-reference leak/copy primitive for groomed adjacent object arrays.
It is not a fabricated fake object from an attacker-invented pointer.

Repeat-mode boundary:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 TIMEOUT=90 ITERATIONS=5 STOP_ON_SUCCESS=0 lab/scripts/triage.sh lab/harnesses/15-oob-array-bridge/double-oob-object-transition-copy.js
```

Log:

- `lab/findings/runs/20260510T034008Z-2126/asan.log`
- crash bucket: `lab/findings/crashes/494aafec7161/`

Result: the first two iterations both copied a valid object reference through
the OOB bridge, then a later ASan heap-buffer-overflow fired while continuing in
the same VM. The default harness stops after the first successful bridge.

## Float64Array backing bridge confirmed

Command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 TIMEOUT=90 ITERATIONS=24 lab/scripts/triage.sh lab/harnesses/15-oob-array-bridge/double-oob-float64array-bridge.js
```

Log:

- `lab/findings/runs/20260510T033917Z-95695/asan.log`

Result:

- clean triage exit `86`; no sanitizer crash
- corrupted source double array: `arrayIndex=368`, `length=2048`
- OOB overlap: relative index `238` maps to a `Float64Array` backing store,
  `arrayIndex=51`, element `0`
- OOB write through relative index `239` changed `Float64Array[1]` from
  `1051840.5002441406` to `1.23456789012345e+123`

Repeat command:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 TIMEOUT=90 ITERATIONS=5 STOP_ON_SUCCESS=0 lab/scripts/triage.sh lab/harnesses/15-oob-array-bridge/double-oob-float64array-bridge.js
```

Log:

- `lab/findings/runs/20260510T034032Z-3792/asan.log`

Result: clean triage exit `86`; `successes=2` across 5 iterations in one VM.
The misses had no corrupted source array in that iteration.

Assessment: this confirms a bridge into typed-array/ArrayBuffer backing storage
data via the corrupted double array OOB write. It does not corrupt typed-array
or ArrayBuffer metadata.

## Current status

Confirmed:

- double-array length corruption remains reproducible with
  `WRITE_OFFSET=136`, `NEW_LENGTH=2048`, `SLOTS=1024`
- object-array bridge through post-corruption victim transition
- valid object-reference bits copied from one object slot to another by OOB
  double-array read/write
- `Float64Array` backing store write through the same OOB primitive

Not confirmed:

- attacker-invented fake object
- typed-array or ArrayBuffer metadata corruption through the OOB double array
- arbitrary native address read/write
