# Crash 7751f1f7d0b1

**First seen:** 20260510T063614Z-32561
**Harness:** lab/harnesses/10-async-buffer-lifetime/async-fs-read-fifo-detach.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x86868e8686a6804 (pc 0x000107766820 bp 0x00016f5bdd60 s
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000107766820
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/10-async-buffer-lifetime/async-fs-read-fifo-detach.js'
```

See `runs/` for raw ASan reports.
