# CTF real service HTTP lifecycle and misc parser probes

Date: 2026-05-10

Target: `lab/ctf/bun-rce/challenge-server.js`

## Summary

No local RCE, arbitrary read/write, or information leak was reached through the remaining updated CTF service surfaces.

Two additional request-reachable sweeps were added:

- `lab/harnesses/16-ctf-real-service/http-lifecycle-body-stress.js`
- `lab/harnesses/16-ctf-real-service/misc-surface-parser-stress.js`

Both ran cleanly under the ASAN Bun build with no sanitizer crash signature.

## HTTP lifecycle/body run

Run log:

- `lab/findings/runs/20260510T042540Z-99310/asan.log`

Command shape:

```sh
ITERATIONS=260 TIMEOUT=180 lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/http-lifecycle-body-stress.js
```

Result:

```json
{
  "harness": "http-lifecycle-body-stress",
  "iterations": 260,
  "internalErrors": 0,
  "socketErrors": 0,
  "timeouts": 12,
  "statuses": {
    "100": 11,
    "200": 148,
    "400": 89,
    "401": 14,
    "404": 6,
    "413": 21,
    "415": 7,
    "429": 169,
    "no-status": 12
  }
}
```

This targets request-state transitions that looked highest value in source review:

- early route rejection before the declared body is fully drained
- chunked/no-`Content-Length` oversize bodies
- `ReadableStream` cancellation after byte-limit checks
- mismatched short/long `Content-Length`
- duplicate `Content-Length`
- `Transfer-Encoding: chunked` plus `Content-Length`
- keep-alive pipelining after rejected JSON/NDJSON bodies
- aborts during streaming body reads

No stale `RequestContext`, uWS callback reuse, parser/body-boundary desync, or response buffer leak was observed.

## Misc surface parser run

Run log:

- `lab/findings/runs/20260510T042945Z-8185/asan.log`

Command shape:

```sh
ITERATIONS=220 TIMEOUT=120 lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/misc-surface-parser-stress.js
```

Result:

```json
{
  "harness": "misc-surface-parser-stress",
  "iterations": 220,
  "internalErrors": 0,
  "socketErrors": 0,
  "timeouts": 0,
  "wsUpgrades": 9,
  "statuses": {
    "101": 9,
    "200": 73,
    "206": 27,
    "400": 66,
    "401": 18,
    "404": 9,
    "405": 9,
    "415": 9,
    "no-status": 9
  }
}
```

This covers the remaining broad service surfaces:

- absolute-form request targets and mismatched host forms
- invalid, double-encoded, and overlong percent-encoded package paths
- duplicate query parameters and unusual numeric limits
- duplicate and large `Cookie` headers
- header continuation/obs-fold attempts
- static `Bun.file()` assets with HEAD/POST/PUT plus Range and conditional headers
- SSE early disconnect and keep-alive pipeline after `/api/events`
- JSON duplicate keys, `__proto__`, lone surrogate escapes, and CR-only NDJSON
- WebSocket UTF-8/JSON edge cases not covered by the burst-close harness

No request-controlled filesystem access appeared. Static assets remain allowlisted to `/assets/app.css` and `/assets/app.js`; the fact that static handling happens before route method checks lets non-GET methods receive allowlisted assets, but it does not expose `flag.txt`.

## Current solve status

No local CTF solve yet.

The source and harness work now point to the same blocker: the confirmed local UAF/OOB primitives need attacker-controlled local JS API use, while the updated service only exposes copied, bounded network data through common request surfaces. No service-reachable primitive for RCE or flag read has been found in these sweeps.
