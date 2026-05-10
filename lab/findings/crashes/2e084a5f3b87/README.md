# Crash 2e084a5f3b87

**First seen:** 20260510T063836Z-40158
**Harness:** lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x157575f57577757a (pc 0x00010ae9b0e8 bp 0x00016b25e410 
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x00010ae9b0e8
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js'
```

See `runs/` for raw ASan reports.
