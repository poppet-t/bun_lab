# Crash 2f2c145931eb

**First seen:** 20260510T032236Z-44323
**Harness:** lab/harnesses/13-arb-rw-probes/fs-read-array-oob-object-copy.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001072009a0
on address 0x62500001b198
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/fs-read-array-oob-object-copy.js'
```

See `runs/` for raw ASan reports.
