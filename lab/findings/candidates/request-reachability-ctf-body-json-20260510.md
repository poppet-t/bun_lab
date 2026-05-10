# Request reachability CTF body/JSON pass - 2026-05-10

Scope: targeted local probes for request-reachable surfaces in
`lab/ctf/bun-rce/challenge-server.js`: `Bun.serve`, request body streaming,
`Request.body.getReader()`, fatal UTF-8 decoding, and JSON parsing.

Ownership: new harness files only under
`lab/harnesses/15-request-reachability/`; this note is prefixed
`request-reachability-`.

## Subagent status

Two read-only Codex subagents were attempted for independent gap analysis:

```sh
codex exec --ephemeral --sandbox read-only -C /Users/CJ/Documents/bun_lab ...
codex exec --ephemeral --sandbox read-only -m gpt-5 -C /Users/CJ/Documents/bun_lab ...
```

Both failed before analysis due local CLI/account model negotiation:

- default `gpt-5.5`: `requires a newer version of Codex`
- explicit `gpt-5`: `model is not supported when using Codex with a ChatGPT account`
- an `o4-mini` smoke retry also failed with the same ChatGPT-account support
  class before producing analysis

The harness split below follows the intended subagent split manually:
body-stream/chunk lifetime, oversize cancel/pipeline behavior, and raw
UTF-8/JSON parsing parity.

## Harnesses added

- `lab/harnesses/15-request-reachability/chunk-copy-yield-stability.js`
  retains request-body chunk views across explicit yields, heap churn, and GC
  before copying/decode with the challenge's collection shape.
- `lab/harnesses/15-request-reachability/cancel-oversize-pipeline.js`
  forces the 512-byte limit and `reader.cancel()` path, then pipelines a valid
  audit request on the same connection.
- `lab/harnesses/15-request-reachability/raw-utf8-json-matrix.js`
  sends true raw invalid UTF-8 bytes through challenge-style manual parsing,
  `req.text()`, and `req.json()` comparison endpoints.

## ASAN triage runs

### Chunk copy/yield stability

Command:

```sh
TIMEOUT=90 ITERATIONS=600 \
  lab/scripts/triage.sh \
  lab/harnesses/15-request-reachability/chunk-copy-yield-stability.js
```

Log:

- `lab/findings/runs/20260510T034219Z-11812/asan.log`

Key output:

```text
[chunk-copy-yield-stability] done iterations=600 stale_alias_statuses=0 socket_errors=0
[triage] exit=0
[triage] no crash signature found (clean exit or non-sanitizer failure)
```

Assessment: no request-reachable crash, leak, or stale request chunk alias was
observed.

### Oversize cancel/pipeline

Command:

```sh
TIMEOUT=90 ITERATIONS=500 \
  lab/scripts/triage.sh \
  lab/harnesses/15-request-reachability/cancel-oversize-pipeline.js
```

Log:

- `lab/findings/runs/20260510T034228Z-13249/asan.log`

Key output:

```json
{"harness":"cancel-oversize-pipeline","iterations":500,"socketErrors":0,"internalErrors":0,"followupAccepted":9,"statusPatterns":{"413":21,"413,200":9,"no-status":470}}
```

```text
[triage] exit=0
[triage] no crash signature found (clean exit or non-sanitizer failure)
```

Assessment: no sanitizer crash and no 5xx/59x failure. The accepted follow-up
requests were clean `413,200` pipelines after an oversize rejection; this is
request-framing behavior in the probe, not evidence of a crash, leak, or
stale-body alias.

### Raw UTF-8/JSON matrix

Command:

```sh
TIMEOUT=90 ITERATIONS=300 \
  lab/scripts/triage.sh \
  lab/harnesses/15-request-reachability/raw-utf8-json-matrix.js
```

Log:

- `lab/findings/runs/20260510T034305Z-17269/asan.log`

Key output:

```json
{"harness":"raw-utf8-json-matrix","iterations":300,"mismatches":180,"internalErrors":0,"counters":{"json:200:array":7,"json:200:null":19,"json:200:object":99,"json:400:invalid_json":175,"manual:200:array":7,"manual:200:object":40,"manual:400:empty_body":22,"manual:400:invalid_json":73,"manual:400:invalid_utf8":158,"text:200:array":7,"text:200:object":99,"text:400:empty_body":22,"text:400:invalid_json":172}}
```

```text
[triage] exit=0
[triage] no crash signature found (clean exit or non-sanitizer failure)
```

Assessment: no crash or leak. The mismatches are semantic: Bun's built-in
`req.text()`/`req.json()` paths replacement-decode some invalid UTF-8 inputs
that the challenge's manual `TextDecoder("utf-8", { fatal: true })` rejects as
`invalid_utf8`. This does not widen the challenge request path because the
challenge uses the fatal manual decoder.

## Current request-reachability result

No new request-reachable crash, native leak, stale chunk alias, stale body
reuse, or primitive bridge was found in this pass. The local CTF route still
appears limited to bounded request-body streaming, fatal UTF-8 decode,
`JSON.parse`, and strict package-name validation.
