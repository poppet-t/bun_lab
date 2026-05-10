# Current Primitive Escalation Attempt - 2026-05-10

Scope: defensive/local attempt to determine whether the currently confirmed
primitives escalate to arbitrary native read/write, native pointer disclosure,
request-reachable information leak, or RCE.

This note records primitive boundaries only. It does not include a weaponized
exploit chain or mitigation bypass.

Update: this note is superseded by
`/Users/CJ/Documents/bun_lab/lab/findings/candidates/uaf-to-jsc-array-storage-primitives-20260510.md`.
Later probing showed stale fs reads/writes can cross into groomed JSC array
storage with pointer-like object-reference disclosure and controlled array
element writes. The stronger result still does not prove arbitrary native
address read/write.

## Fresh validation

### Controlled stale write: async `fs.read`

Command shape:

```sh
ASAN_OPTIONS=...:quarantine_size_mb=0 \
TIMEOUT=20 ITERATIONS=128 SPRAY_COUNT=4096 BUF_SIZE=8192 \
lab/scripts/triage.sh \
  lab/harnesses/10-async-buffer-lifetime/async-fs-read-canary.js
```

Result:

```text
[fs.read:canary] controlled stale write observed iteration=1 canary=2 bytesRead=8192
```

Saved log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T024902Z-82617/asan.log`

Assessment: still a controlled write into reclaimed JS byte storage. This
confirms data-only corruption and readback through the reclaimed target, not
corruption of JSCell headers, typed-array metadata, vtables, or code pointers.

### Stale native read: async `fs.write`

Command shape:

```sh
TIMEOUT=20 MODE=write SOURCE=arraybuffer TARGET=arraybuffer ITERATIONS=4 \
SPRAY_COUNT=2048 BUF_SIZE=8192 \
lab/scripts/triage.sh \
  lab/harnesses/12-uaf-models/async-fs-write-stale-read.js
```

Result:

```text
[fs.write:stale-read] reclaimed marker observed source=arraybuffer target=arraybuffer iteration=1 offset=0 detached=1 canaries=2048 bytesWritten=8192
```

Saved log:

- `/Users/CJ/Documents/bun_lab/lab/findings/runs/20260510T024842Z-81209/asan.log`

Assessment: stale native reads can observe reclaimed byte-storage contents and
write them to a file descriptor. In this run the observed data was a synthetic
marker from another JS byte allocation. No native pointer-bearing allocation was
shown to overlap the stale read source.

### Blob/File and zlib stale reads

The strongest non-fs information-disclosure candidates remain:

- `Blob`/`File` BufferSource borrowing across JS re-entry.
- async `node:zlib` input-buffer stale reads.

The only available Bun binary in this checkout is ASan-instrumented. ASan reports
and then wedges on the macOS sanitizer proc-maps check before post-UAF contents
can be characterized. A `Blob` detached-reclaim probe confirmed the UAF read but
could not continue to classify leaked bytes:

```text
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 4096
AddressSanitizer: CHECK failed: sanitizer_procmaps_mac.cpp:272
```

Assessment: these are credible information-disclosure candidates if run under a
non-ASan build, but current evidence does not show a native pointer leak.

## Source boundary

The core issue remains raw byte-slice borrowing without pinning:

- `/Users/CJ/Documents/bun_lab/bun/src/runtime/node/node_fs.zig:2560` roots the
  JS wrapper for `fs.read`, but does not pin the backing store.
- `/Users/CJ/Documents/bun_lab/bun/src/runtime/node/types.zig:840` through
  `:866` snapshots `readv` iovecs from `byteSlice()`.
- `/Users/CJ/Documents/bun_lab/bun/src/runtime/node/node_zlib_binding.zig:83`
  through `:113` snapshots zlib input/output byte slices before worker-thread
  execution.
- `/Users/CJ/Documents/bun_lab/bun/src/runtime/webcore/Blob.zig:4264` through
  `:4282` stores borrowed BufferSource bytes, then later paths can re-enter JS
  before `StringJoiner.done`.
- `/Users/CJ/Documents/bun_lab/bun/src/jsc/bindings/bindings.cpp:3310` through
  `:3387` already has pin/off-thread borrow helpers, but the vulnerable paths
  above do not consistently use them.

These code paths explain stale pointers into byte storage. They do not, by
themselves, expose a path from normal JS to JSCell/header allocation, JIT memory,
or a pointer-bearing native structure.

## Current escalation status

Confirmed:

- controlled stale write into reclaimed JS byte storage
- stale native read from reclaimed JS byte storage
- offset control inside reclaimed byte storage
- Blob/File and zlib UAF reads against detached byte storage
- zlib UAF write into detached output byte storage

Not confirmed in this earlier pass:

- arbitrary native read
- arbitrary native write
- JS object/header corruption
- typed-array metadata corruption from the stale-write bug
- JIT/code-pointer corruption
- ASLR/W^X/PAC bypass
- request-reachable trigger in `lab/ctf/bun-rce/challenge-server.js`

## CTF reachability check

`lab/ctf/bun-rce/challenge-server.js` exposes `Bun.serve`, bounded request-body
streaming, `TextDecoder("utf-8", { fatal: true })`, `JSON.parse`, and a strict
package-name validator. The confirmed local-JS primitives require direct access
to APIs such as `node:fs`, `node:zlib`, `Blob`/`File` construction with attacker
controlled JS re-entry, or `crypto.randomFill`. The current request handler does
not expose those APIs or a JS-code execution path.

Current implication: the primitives remain real local-JS memory-safety issues,
but this pass did not find an escalation to arbitrary native read/write,
information leak of native pointers, or CTF/RCE reachability.
