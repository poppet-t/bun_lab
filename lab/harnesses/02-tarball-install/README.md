# 02 — npm tarball / libarchive

Targets `bun install`'s tarball ingestion path. `bun install` downloads npm
tarballs (`.tgz`) and pipes them through gzip → tar → filesystem. The
tarball stream is parsed by libarchive (vendored) and Bun's own
`TarballStream.zig` plumbing.

## Risk model

A malicious package on the npm registry can ship a tarball that causes
parser-side memory corruption. Even without RCE, OOB reads can leak
host-process memory into install logs / error paths. Path traversal in tar
entry names (`../../../etc/...`) is a classic; combined with a parser bug it
is high-impact.

## Files

- `crafted-tarballs.js` — emits a set of malformed `.tgz` files into a temp
  dir and invokes `bun install <local-tarball>` on each. We don't hit the
  network; everything's offline.

## What we shape

- gzip with truncated/garbage trailer
- gzip flagged as deflate
- tar with overlapping sparse extents
- tar entries whose `size` doesn't match the actual data block
- pax headers with extreme key/value lengths
- entry names with `..` traversal (already protected, but a parser oops here
  is a primitive)
- entries with names containing NUL / non-utf8

## Running

```sh
TIMEOUT=120 lab/scripts/triage.sh lab/harnesses/02-tarball-install/crafted-tarballs.js
```
