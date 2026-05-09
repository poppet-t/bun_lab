# Finding: <one-line title — "OOB read in <subsystem> via <input>">

**Severity:** unknown / low / medium / high / critical
**Exploitability:** unknown / hard / plausible / easy
**ASan signature:** `<error type> :: <top frame>`
**Crash hash:** `<12-hex from triage.sh>`
**First seen:** `<run-id>`
**Bun rev:** `<git rev-parse HEAD of bun/ at the time>`
**Build profile:** `release-asan` | `debug` | `fuzzilli`

## TL;DR

One-paragraph plain-language summary: what API takes what input and produces
what kind of corruption. Include the security impact in one sentence (e.g.,
"network-reachable", "requires local privileged input", "internal-only").

## Reproducer

Minimal harness that triggers the crash with no external state:

```js
// repro.js — drop this in lab/harnesses/<n>-<name>/
```

Run:

```sh
lab/scripts/triage.sh path/to/repro.js
```

## ASan output

```
==<pid>==ERROR: AddressSanitizer: <type> on address ...
WRITE of size N at 0x... thread T0
    #0 ...
    #1 ...
```

(Full log lives in `findings/crashes/<hash>/runs/<run-id>.log`.)

## Root cause analysis

Trace the corruption back to a specific source location. Format:

- **Bug class:** heap-buffer-overflow / UAF / double-free / OOB read / type-confusion / leak
- **Source location:** `bun/src/<file>:<line>` — function name
- **Trigger:** what attacker-controlled value reached this code path
- **Why the existing checks miss it:** brief

Include relevant code snippets with line numbers (use markdown link format
`[file.zig:42](../../bun/src/file.zig#L42)` for clickability).

## Impact analysis

- **Reachability:** how does an attacker get input to this code path?
  - Network (HTTP request, TLS handshake, DNS response, …)
  - Filesystem (npm tarball, local config file, …)
  - Same-origin JS (one tenant attacking another via shared runtime)
  - JIT-only (requires JS to run in a privileged context)
- **Primitive granted:**
  - Read N bytes past buffer end
  - Write N controlled bytes at controlled offset
  - Free arbitrary heap chunk
  - Use freed object as type T
- **Exploit ceiling:** crash / info-leak / RCE plausible / RCE confirmed.
  Don't claim RCE without a working PoC.

## Patch hypothesis

Smallest plausible fix. Don't write a patch unless you've already disclosed —
this template is for note-taking, not premature PRs.

## Disclosure

- [ ] Confirmed reproducer is minimal (single file, no external network)
- [ ] Verified against latest `main` of upstream Bun (not just this checkout)
- [ ] Prepared report for `security@bun.com` per `bun/SECURITY.md`
- [ ] Sent — date: ____
- [ ] Acknowledged — date: ____
- [ ] Fix landed — commit: ____
- [ ] CVE assigned: ____

## Related crashes

If `triage.sh` has dedup-grouped this with other harness runs, list the run
ids here. If similar bugs exist elsewhere in the codebase (same primitive in
a different parser), note them — that's variant analysis.
