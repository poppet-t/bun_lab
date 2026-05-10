# Crash 2ede9a5ea432

**First seen:** 20260510T030519Z-11705
**Harness:** lab/harnesses/13-arb-rw-probes/crypto-randomfill-array-write.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000117241bbc
on address 0x6250003c0190
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/crypto-randomfill-array-write.js'
```

See `runs/` for raw ASan reports.
