# Harness index

| # | Harness | Surface | Reachability | Files |
| --- | --- | --- | --- | --- |
| 00 | [canary](00-canary/) | bun:ffi memcpy OOB | self-test | heap-overflow.js |
| 01 | [http-parser](01-http-parser/) | HTTP/1.1 parser | network | serve-malformed.js, mutate-loop.js |
| 02 | [tarball-install](02-tarball-install/) | npm tarball / libarchive | local file (npm install) | crafted-tarballs.js |
| 03 | [decompression](03-decompression/) | gzip/deflate/brotli/zstd | network | fetch-bombs.js |
| 04 | [structured-clone](04-structured-clone/) | Worker postMessage codec | in-process | worker-roundtrip.js |
| 05 | [ffi](05-ffi/) | bun:ffi binding layer | local (privileged JS) | args-edge.js, callback-lifetime.js |
| 06 | [postgres](06-postgres/) | bun:sql wire parser | network (hostile server) | fake-server.js |
| 07 | [shell-glob](07-shell-glob/) | Bun.$ / Bun.glob | local (untrusted templates) | brace-bombs.js |
| 08 | [typed-arrays](08-typed-arrays/) | DataView / TypedArray / SAB | in-process | boundary.js |
| 09 | [css](09-css/) | CSS parser (bundler) | local (third-party CSS) | bundle-css.js |

## Coverage gaps (PRs welcome)

Open targets from `docs/ATTACK-SURFACE.md` that don't yet have a harness:

- HTTP/2 frame parser + HPACK (rank 5)
- HTTP/3 / QUIC + QPACK (rank 6)
- NAPI binding layer (rank 11) — needs a small native module
- BoringSSL X.509 / TLS (rank 14) — fake-tls-server harness
- JS parser / module loader (rank 15) — eval / Function() with hostile source

## How to add a harness

1. Create `lab/harnesses/<NN>-<name>/` with a `README.md` describing the
   surface and `<name>.js` containing the harness.
2. Add a row to this index.
3. (Optional) Drop seed inputs in `lab/corpus/<NN>-<name>/`.
4. Run it under `lab/scripts/triage.sh` and confirm:
   - On expected-clean exit, it returns 0
   - On synthetic crash (insert a known-bad input), `triage.sh` produces a
     `findings/crashes/<sig>/` entry
