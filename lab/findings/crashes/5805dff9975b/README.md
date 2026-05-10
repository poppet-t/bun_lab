# Crash 5805dff9975b

**First seen:** 20260510T061708Z-6283
**Harness:** lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```

(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001123a6864
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/13-arb-rw-probes/typedarray-vector-alias-ffi-oracle.js'
```

See `runs/` for raw ASan reports.
