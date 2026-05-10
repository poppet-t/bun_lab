# CTF real service deeper reachability probes

Date: 2026-05-10

Target: `lab/ctf/bun-rce/challenge-server.js`

## Summary

No local RCE, arbitrary read/write, or information leak was reached through the updated real-service CTF surface.

Two deeper request-reachable parser probes were added:

- `lab/harnesses/16-ctf-real-service/multipart-raw-framing-stress.js`
- `lab/harnesses/16-ctf-real-service/websocket-burst-close-stress.js`

Both ran cleanly under the ASAN Bun build with no sanitizer crash signature.

## Runs

### Multipart raw framing

Run log:

- `lab/findings/runs/20260510T041823Z-83182/asan.log`

Command shape:

```sh
ITERATIONS=220 TIMEOUT=180 lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/multipart-raw-framing-stress.js
```

Result:

```json
{
  "harness": "multipart-raw-framing-stress",
  "iterations": 220,
  "internalErrors": 64,
  "socketErrors": 0,
  "timeouts": 32,
  "statuses": {
    "100": 12,
    "200": 26,
    "400": 36,
    "413": 36,
    "415": 13,
    "500": 64,
    "no-status": 33
  }
}
```

The 500s are the same app-level hardening issue seen in the earlier multipart probe: malformed multipart bodies can make `req.formData()` throw `ERR_FORMDATA_PARSE_ERROR`, which is not converted into an `HttpError` by the challenge wrapper. This is not a memory-safety primitive and did not leak `flag.txt`.

The harness covers raw HTTP framing around `/api/reports`, including:

- missing and mismatched multipart boundaries
- overlong and quoted boundaries
- duplicate and malformed `Content-Length`
- `Transfer-Encoding: chunked` with and without `Content-Length`
- short and long declared lengths
- delayed body tails
- pipelined follow-up requests after multipart bodies
- long filenames and boundary-looking bytes inside file contents

### WebSocket burst close

Run log:

- `lab/findings/runs/20260510T042015Z-88092/asan.log`

Command shape:

```sh
ITERATIONS=180 TIMEOUT=180 lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/websocket-burst-close-stress.js
```

Result:

```json
{
  "harness": "websocket-burst-close-stress",
  "iterations": 180,
  "upgrades": 180,
  "noUpgrade": 0,
  "socketErrors": 0,
  "timeouts": 0,
  "closeBuckets": {
    "1008": 60,
    "1009": 30,
    "none": 90
  }
}
```

The harness sends one raw TCP write after upgrade for batched-frame cases:

- 48 valid text frames to cross the message limit
- oversize text/binary frames followed by valid frames
- invalid JSON/schema frames followed by valid frames
- fragmented oversize frames followed by valid frames
- ping/control-frame interleaving
- `RSV1`/compressed-looking frames as a negative control

No stale state was observed after the challenge's `ws.close()` paths.

## Source reachability constraints

### Known BufferSource UAF does not cross into `/api/reports`

The confirmed local BufferSource stale-read/write primitives require attacker-controlled JS objects and re-entry during `new Blob([...])`, `new File([...])`, `fs.read`, or related local JS APIs.

The CTF upload route is materially different:

1. uWS request bytes are copied into Bun's request body buffer.
2. `req.formData()` parses network bytes into `FormData`.
3. Multipart file parts are materialized as `File`/`Blob` data copied from parser slices.
4. `report.arrayBuffer()` returns a fresh ArrayBuffer view of the uploaded file bytes.
5. `crypto.subtle.digest("SHA-256", bytes)` copies the BufferSource into native digest storage before worker dispatch.

There is no request-controlled JS object coercion/re-entry point before those copies, so the existing Blob/File/BufferSource UAF primitive is not reachable from this route.

### WebSocket close path is graceful in this route

The route uses `ws.close()`, not `ws.terminate()`.

`ws.close()` maps to the graceful uWS end path, sets shutdown state, sends a close frame, and stops parsing further buffered frames after the JS callback. The stale-object shape is more plausible with raw termination during the callback, but this challenge route does not call `terminate()`.

The challenge also does not enable `websocket.perMessageDeflate`, so `RSV1` compressed frames are protocol-negative tests rather than a route to the permessage-deflate tail-copy logic.

## Current solve status

No local CTF solve yet.

The updated challenge deliberately removes app-layer file reads, dynamic code execution, subprocesses, request-controlled filesystem paths, and flag reflection. The currently confirmed primitives remain valuable locally, but they need a service-reachable trigger. This real-service version does not expose one through the multipart or WebSocket routes tested here.
