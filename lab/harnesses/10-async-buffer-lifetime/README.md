# Async Buffer Lifetime Harnesses

These harnesses exercise async native APIs that keep raw pointers to JS
ArrayBuffer-backed memory while work runs off-thread.

Run with the ASan wrapper:

```sh
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-read-detach.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-readv-mutate.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-read-fifo-detach.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-readv-fifo-mutate.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-read-canary.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-fs-readv-canary.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-randomfill-detach.js
lab/scripts/run-asan.sh lab/harnesses/10-async-buffer-lifetime/async-randomfill-canary.js
```

The expected safe outcome is either successful completion or a clean JS-level
error. An ASan report, segfault, or process abort is a validation signal for the
lifetime issue described in `lab/findings/candidates/rce-primitives-20260509.md`.
