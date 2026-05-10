# CTF real-service reachability pass - 2026-05-10

Scope: the updated `lab/ctf/bun-rce/challenge-server.js` now exercises a more
realistic Bun service surface: static `Bun.file()` delivery, JSON, NDJSON,
multipart `req.formData()`/`File.arrayBuffer()`, `crypto.subtle.digest`, SSE,
cookies, and WebSocket message handling. This pass runs the actual challenge
server as a child ASAN Bun process and sends local HTTP/WebSocket probes.

## Harnesses

- `lab/harnesses/16-ctf-real-service/real-service-surface-mutator.js`
- `lab/harnesses/16-ctf-real-service/multipart-report-stress.js`
- `lab/harnesses/16-ctf-real-service/websocket-close-stress.js`
- `lab/harnesses/16-ctf-real-service/static-bunfile-range-stress.js`

All runs used:

```sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1:quarantine_size_mb=0
```

## Results

### Broad actual-service mutator

Command:

```sh
TIMEOUT=90 ITERATIONS=500 \
  lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/real-service-surface-mutator.js
```

Log:

- `lab/findings/runs/20260510T035426Z-43185/asan.log`

Result: no ASAN crash. The run hit the service rate limit after covering the
major routes, so follow-up probes were split by surface.

### Multipart/FormData/File/digest

Command:

```sh
TIMEOUT=90 ITERATIONS=220 \
  lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/multipart-report-stress.js
```

Log:

- `lab/findings/runs/20260510T035642Z-47677/asan.log`

Result: no ASAN crash or memory-safety signal. Malformed multipart bodies with
missing/incorrect boundaries caused `req.formData()` to throw
`ERR_FORMDATA_PARSE_ERROR`; because `withErrors()` only catches `HttpError`,
those became application-level 500 responses. This is a hardening issue, not an
RCE or flag-read path. Valid weird filenames are reflected only as metadata and
are not used as filesystem paths.

### WebSocket close, fragmentation, malformed frames, permessage-deflate

Commands:

```sh
TIMEOUT=90 ITERATIONS=220 \
  lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/websocket-close-stress.js
```

After adding compressed RSV1/permessage-deflate-shaped payloads:

```sh
TIMEOUT=90 ITERATIONS=220 \
  lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/websocket-close-stress.js
```

Logs:

- `lab/findings/runs/20260510T035642Z-47678/asan.log`
- `lab/findings/runs/20260510T035831Z-52140/asan.log`

Result: no ASAN crash. All 220 connections upgraded in each run. Cases covered
oversize messages that force `ws.close()`, message-limit close paths,
fragmented frames, invalid UTF-8 binary frames, unmasked frames, inconsistent
declared lengths, RSV1 without valid compression, and compressed RSV1 payloads.

### Static Bun.file Range/header stress

Command:

```sh
TIMEOUT=120 ITERATIONS=2000 \
  lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/static-bunfile-range-stress.js
```

Log:

- `lab/findings/runs/20260510T035741Z-50024/asan.log`

Result: no ASAN crash and no 5xx responses. Static asset delivery returned
expected `200`, `206`, `404`, `416`, and later `429` for non-static paths that
fell through to the rate limiter.

## Current solve status

No request-reachable RCE primitive was obtained from the updated real-service
challenge. The local JS primitives in the `13`/`15` harnesses remain stronger
than before, but this service still does not expose local JS access to the
async `node:fs` BufferSource UAF or a completed fakeobj/native arbitrary-RW
chain through HTTP/WebSocket requests.

Best new service-level issue: malformed multipart parse errors are not
normalized into `HttpError` and produce 500s. That is worth hardening but does
not read `flag.txt`, execute code, or produce a sanitizer-backed primitive.
