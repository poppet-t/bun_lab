# fs UAF object bridge → addrof + fakeobj + controlled native deref

Scope: local Bun/JSC exploit development from the confirmed async `fs.read`
BufferSource UAF documented in
`lab/findings/cve-disclosure/ADVISORY.md` and
`lab/findings/candidates/fs-uaf-typedarray-callback-pc-control-20260510.md`.

## Summary

Building on the controlled cross-allocation write proven by
`lab/harnesses/13-arb-rw-probes/fs-uaf-object-ref-roundtrip.js`, we now have
three stable, no-FFI JS-level primitives:

1. **addrof(target)** — leak the raw `JSCell*` of any attacker-chosen JS
   object. Confirmed stable across repeated leaks of the same target and
   distinct across distinct targets.
2. **fakeobj-from-known-cell-address** — plant a leaked JSCell pointer into
   a fresh JS object-array slot; reading the slot returns the original
   anchor by identity.
3. **fakeobj-from-arbitrary-bits / controlled native dereference** — plant
   any cell-shaped 64-bit value (top 16 bits zero, bit 1 zero) into a fresh
   JS object-array slot; reading the slot causes JSC to dereference our
   chosen address as a `JSCell*`. The crash address observed by ASAN is
   exactly `planted_bits + 5` (JSC reads a header byte at JSCell+5),
   proving full attacker control over the dereferenced native pointer.

Together, (1) + (3) is the standard JSC starting point for an arbitrary-R/W
primitive (build a fake `Uint8Array` whose `m_vector` points to attacker
memory). All three primitives are reachable from vanilla `node:fs` and JS
arrays — no FFI, no `bun:ffi`, no JIT warming, no native helper dylib.

## Pipeline

The roundtrip harness `fs-uaf-object-ref-roundtrip.js` implements the two
underlying side-effects:

* **leak** — `fs.write(fd, source, …)` schedules the read worker to copy
  `size` bytes *from* the BufferSource into a FIFO. We detach the
  BufferSource before the worker fires, spray a contiguous run of object
  arrays whose element[0]s are anchor objects, and wait for the worker to
  drain the *reclaimed* slot to the FIFO. Reading 8 bytes at fixed offset
  `ELEMENT_OFFSET=144` gives back the raw `JSCell*` of the anchor that
  landed in element[0] of the freshly reclaimed butterfly.
* **write** — `fs.read(fd, target, ELEMENT_OFFSET, 8, …)` schedules the
  write worker to write 8 bytes *into* the BufferSource at offset 144. We
  detach, spray sentinel-only object arrays, and unblock the worker by
  writing 8 bytes on the FIFO. Those 8 bytes land in element[0] of the
  freshly reclaimed butterfly; from JS we read back element[0] of the
  spray and observe whatever JSCell `JSC::JSValue::decode(planted_bits)`
  evaluates to.

Both sides depend on the same allocator behavior: ASan with
`quarantine_size_mb=0` and the spray sized to fit the freed BufferSource
size class. With `BUF_SIZE=8192 SLOTS=1024 SPRAY_COUNT=4096
ELEMENT_OFFSET=144`, the reclaim is reproducible on the first attempt.

## Evidence

### addrof: stable across repeats, distinct across targets

Harness: `lab/harnesses/13-arb-rw-probes/object-bridge-addrof-probe.js`.
Run: `lab/findings/runs/20260510T065655Z-68231/asan.log`.

```json
{
  "ok": true,
  "a1": "0x000062d000035640",
  "a2": "0x000062d000035640",
  "b1": "0x000062d000035660",
  "stableAcrossRepeatedLeaks": true,
  "changesAcrossDistinctTargets": true,
  "topBitsLooksLikeCellPointer": true
}
```

Two consecutive `addrof(targetA)` calls returned the same JSCell pointer
(`0x000062d000035640`) and `addrof(targetB)` returned a different but
nearby JSCell pointer (`0x000062d000035660` — exactly +0x20, matching the
JSObject IsoSubspace size class). All three pass the JSC `NotCellMask`
shape check (top 16 bits zero, bit 1 zero), confirming they are bona-fide
JSCell pointers. This is a textbook addrof primitive.

### fakeobj from known cell: anchor roundtrip is identity-preserving

Harness: `lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js`
with `FAKE_TARGET=anchor`.
Run: `lab/findings/runs/20260510T065821Z-70512/asan.log`.

```json
{"phase":"planted","fakeTargetSpec":"anchor","bits":"0x000062d000035ce0"}
{"phase":"read-back","fakeTargetSpec":"anchor","plantedBits":"0x000062d000035ce0",
 "found":{"arrayIndex":2,"classified":"anchor[51]"}}
```

We leaked an anchor's JSCell pointer (`0x000062d000035ce0`) and planted
those 8 bytes into element[0] of a freshly sprayed sentinel array via the
write side of the BufferSource UAF. Reading element[0] from JS returned
the original anchor object by identity. JSC fully accepted the planted
bits as a valid JSCell, dereferenced them, and reconstructed the object
reference.

### fakeobj from attacker-chosen bits: controlled native dereference

Harness: `lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js`
with `FAKE_TARGET=hex:0x00007fffdeadbef0`.
Run: `lab/findings/runs/20260510T065909Z-72122/asan.log` and crash dir
`lab/findings/crashes/9fb1438b7e67`.

```text
{"phase":"planted","fakeTargetSpec":"hex:0x00007fffdeadbef0","bits":"0x00007fffdeadbef0"}
==72142==ERROR: AddressSanitizer: SEGV on unknown address 0x7fffdeadbef5
        (pc 0x0001088d16fc bp 0x… sp 0x… T0)
```

We planted attacker-chosen invalid (but cell-shaped, top 16 bits zero,
bit 1 zero, 8-byte aligned) bits `0x0000_7fff_dead_bef0` into element[0]
of the spray. When JS code subsequently reads element[0] (via the planted
detection loop in the harness), JSC dereferences those bits as `JSCell*`
and ASan flags the SEGV at exactly **`planted_bits + 5`** (`0x7fffdeadbef5`),
which corresponds to JSC reading a JSCell header byte at offset +5 of
the fake cell.

The "+5" is the deterministic forensic fingerprint of "JSC followed our
controlled pointer into JSCell-header read territory". Observed PC
`0x0001088d16fc` is in real Bun native code, not JIT memory; this is a
non-IC native deref. The same harness with different `FAKE_TARGET`
produces correspondingly different SEGV addresses, confirming end-to-end
attacker control of the dereferenced native pointer.

A previous experiment with `FAKE_TARGET=hex:0xdeadbeefdeadbef0` did *not*
crash because that value has high bits intersecting JSC's `NotCellMask =
NumberTag | OtherTag = 0xfffe000000000002`, so JSC decoded it as a
NaN-boxed double rather than a cell. Once the bits are reshaped to
cell-form, the dereference fires every time
(`lab/findings/runs/20260510T065834Z-71101/asan.log` shows the
`"classified":"number"` no-deref result for the malformed mask).

## Threat-model implications

* **Local-JS arbitrary R/W is structurally reachable.** With addrof and
  fakeobj-from-arbitrary-bits, the textbook JSC chain to arbitrary native
  read/write is short:
  1. `addrof(victim)` for a real `Uint8Array` victim — get its JSCell
     address.
  2. Plant fake-cell bits in a JS-controlled storage (e.g. a Float64Array
     whose data we control), then `addrof` *that* storage to learn the
     base.
  3. fakeobj that base — JSC now treats our crafted bytes as a fake
     `Uint8Array` whose `m_vector` we control, giving R/W at any chosen
     address.

  We have not yet stabilised step (3) end-to-end with a successful
  read/write proof — the controlled-deref crash is currently the
  in-process boundary we have demonstrated — but the layout-level steps
  are unblocked from the JS side.

* **No FFI required.** Earlier "RCE-adjacent" evidence in this repo
  needed `bun:ffi` to load a marker dylib. The chain in this note runs
  entirely in pure `node:fs` + JS array primitives. That broadens the
  attack surface to any deployment that allows JS code to call
  `fs.read` with an `ArrayBuffer`, regardless of FFI policy.

* **The CVE advisory remains conservative.** The disclosure bundle in
  `lab/findings/cve-disclosure/` continues to claim only what is
  end-to-end demonstrated: controlled native heap write, controlled
  native indirect call target through the JIT IC stub, and now —
  optionally added in a follow-up — controlled native dereference via
  the fakeobj primitive. We have *not* yet demonstrated a successful
  arbitrary-read or arbitrary-write side-effect, only a SEGV at an
  attacker-chosen address. Stable RCE is therefore still not claimed.

## Reproduction

```sh
clang ... # not needed, no FFI

ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:fast_unwind_on_fatal=1:malloc_context_size=64:allocator_may_return_null=0:print_stats=0:symbolize=0:print_module_map=0:quarantine_size_mb=0 \
TIMEOUT=30 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/object-bridge-addrof-probe.js
# expect: stableAcrossRepeatedLeaks=true, changesAcrossDistinctTargets=true.

ASAN_OPTIONS=...:quarantine_size_mb=0 TIMEOUT=30 FAKE_TARGET=anchor \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js
# expect: classified == "anchor[k]" for some k. No crash.

ASAN_OPTIONS=...:quarantine_size_mb=0 TIMEOUT=30 FAKE_TARGET=hex:0x00007fffdeadbef0 \
lab/scripts/triage.sh \
  lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js
# expect: SEGV at 0x7fffdeadbef5 (planted_bits + 5).
```

## Open follow-ups

* Stabilise step (3) of the arb-R/W chain — i.e., turn the
  controlled-deref into a successful no-crash read by making the planted
  cell point into JS-controlled storage that JSC can fully traverse.
  Likely requires shaping a fake `Structure` / fake `Butterfly` reachable
  from the planted JSCell pointer.
* Re-evaluate whether the `PutByVal` IC slow-path callsite from
  `378039c` becomes useful once we can craft the structures it expects
  (in particular, whether we can build a JIT-IC-cache call frame and
  trigger it with an attacker-chosen target).
* If/when the arb-R/W chain produces a marker file or equivalent
  successful native side-effect, fold a separate "Additional
  exploitability evidence" section into `ADVISORY.md`. Until then keep
  the advisory conservative.
