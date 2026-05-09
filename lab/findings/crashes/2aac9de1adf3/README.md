# Crash 2aac9de1adf3

**First seen:** 20260509T130812Z-62628
**Harness:** /Users/CJ/Documents/bun_lab/lab/harnesses/00-canary/heap-overflow.js
**Bun:** /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan

## Signature

```
ERROR: AddressSanitizer: heap-buffer-overflow
(no stack — macOS 26 ASan post-detection wedge; see lldb workflow in lab/docs/SANITIZERS.md)
pc 0x00011742dbbc
on address 0x602000046938
```

## Get a real stack

ASan's post-detection stack walker is broken on macOS 26 (LLVM bug).
To get function names, attach lldb and re-run the harness:

```sh
lab/scripts/triage-lldb.sh '/Users/CJ/Documents/bun_lab/lab/harnesses/00-canary/heap-overflow.js'
```

See `runs/` for raw ASan reports.
