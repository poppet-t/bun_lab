# Crash a94317124221

**First seen:** 20260510T034255Z-15309
**Harness:** lab/harnesses/15-arraybuffer-metadata/fs-read-metadata-field-matrix.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x000000000040 (pc 0x000100f81e34 bp 0x00016f2eb6a0 sp 0
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000100f81e34
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/15-arraybuffer-metadata/fs-read-metadata-field-matrix.js'
```

See `runs/` for raw ASan reports.
