# Crash 35ad6c0c66f7

**First seen:** 20260510T063834Z-39307
**Harness:** lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x157575f57577756b (pc 0x000108a5e638 bp 0x00016d5ddda0 
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000108a5e638
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js'
```

See `runs/` for raw ASan reports.
