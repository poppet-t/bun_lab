# 06 — Postgres wire-protocol parser

Bun ships a built-in postgres client (`bun:sql`). The wire protocol is
binary, length-prefixed, and the parser lives in `bun/src/sql/postgres/`. A
malicious server can ship malformed messages — same threat model as the
HTTP/2 frame parser, but a less-audited target.

## Risk model

A user `bun:sql`-connecting to a hostile server reaches the parser. Real
attack scenarios: misconfigured DNS, MITM without TLS, or compromised
upstream. Bugs here yield in-process memory corruption with attacker-
controlled bytes.

## Files

- `fake-server.js` — listens on a TCP port, completes the postgres startup
  handshake, then sends a battery of malformed message variants. The
  client side is the same Bun process via `bun:sql`.
