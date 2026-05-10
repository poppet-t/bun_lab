# Crash e1c150de3f9c

**First seen:** 20260510T030438Z-9318
**Harness:** lab/harnesses/13-arb-rw-probes/zlib-input-array-leak.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x00012eef8800 (pc 0x0001040889f8 bp 0x00016d56ea80 sp 0
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001040889f8
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/zlib-input-array-leak.js'
```

See `runs/` for raw ASan reports.
