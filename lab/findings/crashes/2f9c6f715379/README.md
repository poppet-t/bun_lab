# Crash 2f9c6f715379

**First seen:** 20260509T132719Z-78356
**Harness:** lab/harnesses/09-css/calc-depth.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: stack-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x0001064a9fa8
on address 0x00016ecbf660
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh 'lab/harnesses/09-css/calc-depth.js'
```

See `runs/` for raw ASan reports.
