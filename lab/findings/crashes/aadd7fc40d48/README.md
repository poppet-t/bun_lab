# Crash aadd7fc40d48

**First seen:** 20260510T061707Z-5859
**Harness:** lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
SEGV on unknown address 0x15216fffba226082 (pc 0x000106b13dfc bp 0x00016f60e810 
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x000106b13dfc
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js'
```

See `runs/` for raw ASan reports.
