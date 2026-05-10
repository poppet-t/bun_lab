# Crash 585986f15890

**First seen:** 20260510T093506Z-48570
**Harness:** lab/harnesses/13-arb-rw-probes/fake-cell-from-harvested-header-probe.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000107348644
on address 0x606000018008
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/fake-cell-from-harvested-header-probe.js'
```

See `runs/` for raw ASan reports.
