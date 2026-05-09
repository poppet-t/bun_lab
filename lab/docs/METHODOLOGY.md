# Methodology

The loop you should run, end-to-end, for every target.

## 1. Pick a target

Open [ATTACK-SURFACE.md](ATTACK-SURFACE.md). Pick one of the top-15 areas.
Don't try to cover all of them — go deep on one, then variant-analyse.

For your first target, pick HTTP/1.1 parser, decompression, or the IPC
deserializer. They're network-reachable, well-defined byte protocols, and
crashes there are unambiguously high-impact.

## 2. Read the parser before you fuzz it

Before writing any input mutator, spend 30-60 minutes reading the parser
end-to-end. You're looking for:

- Length math involving operands from the wire
- `@ptrCast` / `reinterpret_cast` that drops alignment / lifetime info
- Anywhere lifetime crosses a JS callback (re-entrancy can free what
  native still holds a pointer to)
- Hand-rolled `memcpy` / `@memcpy` with computed lengths
- State machines that can be entered from an unexpected state via partial
  input (the parser's own buffering layer)

Run `lab/scripts/grep-risky.sh src/<target>` to seed your reading list.

## 3. Write a minimal harness

Drop a file in `lab/harnesses/<n>-<name>/`. The harness should:

- Be a single JS file with no external state
- Boot a small server / open a fixture / call the API directly
- Drive the target with one or many adversarial inputs
- Log per-variant identifiers to stderr so triage can map crash → input

If the input space is structured (HTTP frames, postgres messages, tar
records), prefer hand-built variants for the *first* pass — they hit
specific code paths your reading flagged.

For the second pass, add a mutation loop. Either roll a dumb byte-level
mutator (see `harnesses/01-http-parser/mutate-loop.js`) or use Fuzzilli
(see [FUZZILLI.md](FUZZILLI.md)) when the target is JS-driven.

## 4. Run under ASan

```sh
lab/scripts/triage.sh lab/harnesses/<n>/<file>.js
```

Default timeout is 60 s. For mutation loops set `TIMEOUT=300` or longer.
The script writes a per-run log under `findings/runs/`, and on crash
moves it to `findings/crashes/<sig>/runs/`.

## 5. Read the ASan report

Three things matter:

1. **Error type** (`heap-buffer-overflow` / `use-after-free` / etc.)
2. **Top frame** — where the bad access happened
3. **Allocation site** (only printed for heap bugs) — where the buffer was
   allocated. For UAF, also the **free site**.

Crash-grouping in `triage.sh` keys on (error type, top-4 frames). If two
inputs produce the same hash, they're the same bug.

## 6. Minimize the reproducer

Once you have a crash, shrink the input. Goal: minimum bytes / minimum
JS that still trips the bug. Why it matters:

- Smaller repro = clearer root cause analysis
- Smaller repro = easier disclosure
- Smaller repro = useful regression test

Use bisection on the input — halve until the crash disappears, then
backtrack.

## 7. Root-cause it

Once minimized, attach a debugger:

```sh
lldb -- "$BUN_ASAN_BIN" lab/findings/crashes/<sig>/repro.harness
(lldb) run
# crash
(lldb) bt all
```

Set a breakpoint at the allocation site (ASan reports it), then re-run
with logging to see the lifecycle of the offending object. For UAF, the
question is always: *what code path is keeping a pointer to the freed
object?* For OOB, it's: *what attacker-influenced operand made the
length math wrong?*

## 8. Variant analysis

Before disclosing, ask: where else does this pattern exist? If you find a
length-math bug in `H2FrameParser.zig`, the same shape probably lives in
`H3Client.zig`, `picohttp_sys`, postgres, etc. Find every variant in the
same disclosure window.

## 9. Write up the finding

Copy `lab/findings/TEMPLATE.md` to `lab/findings/crashes/<sig>/finding.md`
and fill it in. Be specific about:

- Reachability (network / local / requires-already-RCE)
- Primitive (read / write / what alignment / what attacker control)
- Exploit ceiling (don't claim RCE without a PoC)

## 10. Disclose

`security@bun.com`. Do not publish before a fix lands. Don't post repros
to GitHub issues — even private ones. Bun's security policy is in
`bun/SECURITY.md`.
