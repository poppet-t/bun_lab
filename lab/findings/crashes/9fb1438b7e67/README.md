# Crash 9fb1438b7e67

**First seen:** 20260510T065909Z-72122
**Harness:** lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x7fffdeadbef5 (pc 0x0001088d16fc bp 0x00016ce8ae10 sp 0
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001088d16fc
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js'
```

See `runs/` for raw ASan reports.
