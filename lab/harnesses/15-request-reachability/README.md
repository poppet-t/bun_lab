# Request reachability harnesses

Focused probes for the CTF request path in
`lab/ctf/bun-rce/challenge-server.js`: `Bun.serve`, request-body streaming,
fatal UTF-8 decoding, and JSON parsing.

- `chunk-copy-yield-stability.js` retains request-body chunks across explicit
  yields, heap churn, and GC before copying them with the same shape as the
  challenge handler. A `599 stale_chunk_alias` response or non-zero exit means a
  retained body chunk changed before the app copied it.
- `cancel-oversize-pipeline.js` sends body sizes that cross the 512-byte limit,
  including chunked bodies that force `reader.cancel()`, then pipelines a valid
  audit request on the same connection. Sanitizer reports, 500s, or 59x statuses
  are treated as failures.
- `raw-utf8-json-matrix.js` sends true raw invalid UTF-8 bytes through manual
  challenge-style parsing, `req.text()`, and `req.json()` comparison endpoints.
  Differences are logged as reachability context; sanitizer reports and 5xx
  responses are failures.

