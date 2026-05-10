# CTF local static symlink solve

Date: 2026-05-10

Target: `lab/ctf/bun-rce/challenge-server.js`

## Summary

Local filesystem write access to the challenge directory is enough to solve the
current CTF without modifying the server source or using a native memory-safety
bug.

The server's static asset allowlist maps `/assets/app.js` to a fixed local path,
but it constructs `Bun.file(asset.path)` at request time. If the allowlisted
asset path is replaced with a symlink to `../flag.txt`, the unchanged server
serves the flag through `/assets/app.js`.

This is a local-access solve chain, not remote RCE:

1. locally replace `lab/ctf/bun-rce/public/app.js` with a symlink to `../flag.txt`
2. start or keep using the challenge server
3. request `GET /assets/app.js`
4. the server process follows the symlink and reads `flag.txt`
5. restore the original asset

## Harness

- `lab/harnesses/16-ctf-real-service/local-static-symlink-solve.js`

The harness backs up `public/app.js`, installs the symlink, starts the challenge
on `PORT` or a random high loopback port, fetches `/assets/app.js`, reports
whether a flag was found, then restores the original asset in a `finally` block.

By default it redacts the flag in logs. Set `PRINT_FLAG=1` for an explicit local
solve print.

## Run

Redacted triage log:

- `lab/findings/runs/20260510T044736Z-43778/asan.log`

Command shape:

```sh
TIMEOUT=30 lab/scripts/triage.sh \
  lab/harnesses/16-ctf-real-service/local-static-symlink-solve.js
```

Result:

```json
{
  "harness": "local-static-symlink-solve",
  "mode": "local-filesystem-write",
  "status": 200,
  "contentType": "text/javascript; charset=utf-8",
  "symlinkTarget": "../flag.txt",
  "flagFound": true,
  "flag": "SCTF{redacted}"
}
```

The harness exits with code `86` when the local-only flag read succeeds, so the
triage wrapper records this as a non-sanitizer nonzero exit rather than a crash.

Manual full-print confirmation:

```sh
PRINT_FLAG=1 /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan \
  lab/harnesses/16-ctf-real-service/local-static-symlink-solve.js
```

Output recovered:

```text
SCTF{redacted}
```

## Assessment

This does not contradict the remote probes: the HTTP API still does not expose a
request-controlled filesystem path. The added assumption is local filesystem
write access to an allowlisted static asset path.

If the intended challenge allows local write access to the service directory,
this is a valid local CTF solve. If the intended challenge is remote-only, this
is out of scope and should be treated as a hardening note.

Potential hardening:

- pre-open static assets at startup and serve from those file descriptors
- reject symlinks for allowlisted static assets
- resolve realpaths and enforce that they remain regular files under `public/`
- avoid storing the flag below any directory where local writers can alter
  allowlisted served paths
