# 03 — Decompression (gzip / deflate / brotli / zstd)

`fetch()` decompresses response bodies based on `Content-Encoding`. The
decompressor in `bun/src/http/Decompressor.zig` runs untrusted bytes through
zlib/brotli/zstd, growing a heap buffer as needed.

## Risk model

This is **the** classic decompression-bomb / parser-corruption attack
surface. Every node-style runtime ships at least one decompression bug per
year. Network-reachable, no auth required.

## Files

- `fetch-bombs.js` — local server returns content with mismatched/truncated
  encodings; client `fetch()`es and tries to decode.
