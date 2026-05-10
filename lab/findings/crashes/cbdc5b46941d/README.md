# Crash cbdc5b46941d

**First seen:** 20260510T033039Z-69495
**Harness:** lab/harnesses/13-arb-rw-probes/fs-arraybuffer-backing-alias.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x6a6a726a6a8a6a6 (pc 0x00010a5d79d8 bp 0x00016baee770 s
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x00010a5d79d8
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/fs-arraybuffer-backing-alias.js'
```

See `runs/` for raw ASan reports.
