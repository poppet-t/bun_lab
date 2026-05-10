# Crash f15b326e44ef

**First seen:** 20260510T055746Z-74091
**Harness:** lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x1555408000020004 (pc 0x000107d34ad8 bp 0x00016d1de330 
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000107d34ad8
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js'
```

See `runs/` for raw ASan reports.
