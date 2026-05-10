# Crash 494aafec7161

**First seen:** 20260510T034008Z-2126
**Harness:** lab/harnesses/15-oob-array-bridge/double-oob-object-transition-copy.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001074acd50
on address 0x625002840998
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/15-oob-array-bridge/double-oob-object-transition-copy.js'
```

See `runs/` for raw ASan reports.
