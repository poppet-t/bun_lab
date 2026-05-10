# Crash a83c75e93eb6

**First seen:** 20260510T063542Z-31047
**Harness:** lab/harnesses/10-async-buffer-lifetime/async-fs-read-fifo-detach.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x4343434343434330 (pc 0x000112b7a864 bp 0x00016f65ddf0 
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000112b7a864
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/10-async-buffer-lifetime/async-fs-read-fifo-detach.js'
```

See `runs/` for raw ASan reports.
