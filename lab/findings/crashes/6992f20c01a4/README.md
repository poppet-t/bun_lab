# Crash 6992f20c01a4

**First seen:** 20260510T032742Z-62008
**Harness:** lab/harnesses/13-arb-rw-probes/fs-read-typedarray-metadata-write.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001063c192c
on address 0x60c0004a2ec0
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/fs-read-typedarray-metadata-write.js'
```

See `runs/` for raw ASan reports.
