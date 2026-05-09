# 01 — HTTP/1.1 parser

Targets PicoHTTPParser + the `Bun.serve()` request path. We start a server,
fire malformed requests at it, and look for ASan reports in the parser /
header allocator.

## Risk model

`Bun.serve()` runs the parser inside the runtime process — a parser bug is
remote-reachable and lives in the same address space as user code. Any OOB
read leaks request memory; any write is heap corruption.

## Files

- `serve-malformed.js` — boots a server, sends a battery of malformed
  requests (oversized headers, weird folding, embedded CRLFs, chunked-body
  abuse), reports any panic.
- `mutate-loop.js` — long-running loop that takes a seed in `corpus/` and
  applies bit-flips / byte-deletes / chunk-splits, sending each variant.
  Run under `triage.sh` with a long timeout.

## Running

```sh
lab/scripts/triage.sh lab/harnesses/01-http-parser/serve-malformed.js
TIMEOUT=300 lab/scripts/triage.sh lab/harnesses/01-http-parser/mutate-loop.js
```

## Adding test cases

Drop raw HTTP byte sequences into `lab/corpus/01-http-parser/*.bin`. The
mutate loop iterates the corpus dir.
