# Crash 5425989d9a80

**First seen:** 20260510T063837Z-40509
**Harness:** lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x19b9ba39b9bbb9be (pc 0x000106fd30e8 bp 0x00016f1267f0 
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000106fd30e8
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js'
```

See `runs/` for raw ASan reports.
