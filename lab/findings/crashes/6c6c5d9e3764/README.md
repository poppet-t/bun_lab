# Crash 6c6c5d9e3764

**First seen:** 20260510T032311Z-47615
**Harness:** lab/harnesses/13-arb-rw-probes/fs-read-array-oob-object-copy.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x00010b3789a0
on address 0x62500001b198
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/fs-read-array-oob-object-copy.js'
```

See `runs/` for raw ASan reports.
