# Crash 8fcf4cc8a530

**First seen:** 20260510T033002Z-68164
**Harness:** lab/harnesses/13-arb-rw-probes/fs-arraybuffer-backing-alias.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001085bc2e8
on address 0x60c00002a100
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/fs-arraybuffer-backing-alias.js'
```

See `runs/` for raw ASan reports.
