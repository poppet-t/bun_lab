# Bun Security Research Lab

A CTF-style lab for hunting memory corruption (UAF, heap overflow, OOB,
double-free, type confusion) and other vulnerability classes in the Bun
runtime. Built on top of Bun's existing AddressSanitizer + UBSan + Fuzzilli
infrastructure.

> ⚠️ **Scope:** defensive security research on this local checkout. Any real
> findings should be reported to `security@bun.com` per
> `bun/SECURITY.md` — do not publish exploits before coordinated disclosure.

## Layout

```
lab/
├── README.md                # this file
├── build/                   # local build artifacts, asan binary symlinks
├── tools/                   # local-only tools (no PATH pollution)
├── scripts/
│   ├── build-asan.sh        # build bun with ASan + assertions + UBSan
│   ├── run-asan.sh          # run bun under ASan with sane env
│   ├── triage.sh            # run a harness, capture & dedupe ASan reports
│   ├── triage-lldb.sh       # re-run under lldb to recover stack frames lost
│   │                        # to the macOS 26 ASan post-detection wedge
│   ├── env.sh               # ASAN_OPTIONS / UBSAN_OPTIONS we use everywhere
│   └── grep-risky.sh        # static-analysis grep for risky native patterns
├── harnesses/               # CTF-style "challenges" — one per attack surface
│   ├── 00-canary/           # planted bug to verify the lab works
│   ├── 01-http-parser/
│   ├── 02-tarball-install/
│   ├── 03-ffi/
│   ├── 04-napi/
│   ├── 05-tls-x509/
│   ├── 06-postgres/
│   ├── 07-shell-parser/
│   ├── 08-html-parser/
│   ├── 09-path-canon/
│   ├── 10-structured-clone/
│   └── ...
├── corpus/                  # seed inputs per harness (corpus/<harness>/)
├── findings/
│   ├── TEMPLATE.md          # use this for each finding
│   └── crashes/             # one dir per dedup'd crash
└── docs/
    ├── ATTACK-SURFACE.md    # ranked attack surface map
    ├── SANITIZERS.md        # what each sanitizer catches + tuning
    ├── FUZZILLI.md          # using Fuzzilli against bun-debug
    └── METHODOLOGY.md       # workflow: pick target → harness → fuzz → triage
```

## Quick start

```sh
# 1. Build bun with ASan + UBSan + assertions (one-time, ~30-60 min)
lab/scripts/build-asan.sh

# 2. Verify the lab works against the planted-bug canary
lab/scripts/triage.sh harnesses/00-canary/heap-overflow.js

# 3. Pick a target, fuzz it
lab/scripts/triage.sh harnesses/01-http-parser/serve-malformed.js
```

## Why this lab works

Bun already ships sanitizer-aware build profiles:

| Profile              | Build flags                                             |
| -------------------- | ------------------------------------------------------- |
| `debug`              | ASan on (arm64 macOS / linux), UBSan, assertions, logs  |
| `debug-no-asan`      | Faster compile, no memory checking                      |
| `release-asan`       | Release + ASan + assertions (closer to prod codegen)    |
| `release-assertions` | RelWithDebInfo + assertions + logs (no ASan)            |
| `debug:fuzzilli`     | Debug + Fuzzilli coverage instrumentation (requires ASan) |

The `release-asan` profile is the **right default for this lab**: it catches
memory bugs the same way the upstream Bun maintainers' CI does, but with
optimized codegen so a bug only reachable in release mode (UB-around-NRVO,
optimizer-induced races, etc.) still triggers.

## Sanitizer coverage

ASan finds heap-buffer-overflow, stack-buffer-overflow, use-after-free,
use-after-return, use-after-scope, double-free, invalid-free, alloc-dealloc
mismatch, container-overflow, leaks (with LSan).

UBSan in the bun build catches: null deref, OOB array index, signed overflow,
return-without-value, nullability violations, unreachable, function-type
mismatch (`-fno-sanitize-recover=all` means first hit aborts).

What ASan / UBSan **don't** catch and you have to look for separately:
- **Logic bugs** (auth bypass, sandbox escape from the JIT, prototype pollution
  reaching native APIs)
- **Data races** (use `-fsanitize=thread` separately if you suspect)
- **Untriggered code paths** (need fuzzing or coverage-guided exploration)
- **Cooperative misuse of safe APIs** (e.g., `bun:ffi` with attacker-controlled
  pointer args is unsafe by design)

See [docs/SANITIZERS.md](docs/SANITIZERS.md).

## Methodology

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the loop:

1. **Pick a target** from [docs/ATTACK-SURFACE.md](docs/ATTACK-SURFACE.md)
2. **Read the parser** — focus on length/offset arithmetic, `@ptrCast` /
   `reinterpret_cast`, anywhere lifetime crosses a JS callback
3. **Write a harness** — minimal JS that drives the target with attacker-shaped
   input from `corpus/<harness>/`
4. **Run under ASan** — `lab/scripts/triage.sh harnesses/<n>/...`
5. **Mutate the corpus** — radamsa, AFL++, or hand-craft based on what
   ASan says about the crash site
6. **Triage** — dedupe by ASan stack frame, write up in `findings/crashes/`
7. **Disclose responsibly** — `security@bun.com` for real bugs

## On responsible disclosure

This lab is for finding bugs in **your own** local checkout of Bun, where
you have authorization (it's an open-source project you've cloned). Do not
attack hosted services, public deployments, or any system you don't own. If
you find a real vulnerability, follow `bun/SECURITY.md`.
