# fs UAF — assessment of the five remaining-milestone candidates

Date: 2026-05-10

Scope: extends the wasm dispatch ABI probe in
`wasm-descriptor-system-abi-probe-20260510.md`. Records why none of the
five remaining standalone exploit milestones is tractable in this lab
session under the current set of primitives, and what each would
require as a follow-up research project. No new code is committed; no
new ASan run is performed (the offset-40 force run wedged a Bun child
in uninterruptible state — that behaviour is a real cost, not a free
experiment).

The five milestones (per the working notes' "what we are NOT claiming"
list) are:

1. remote / request-reachable RCE
2. standalone native `system(command)` (no attacker-supplied import)
3. standalone shellcode execution
4. generic ASLR / W^X / PAC bypass
5. request-reachable exploitability through the hardened HTTP service

## 1. remote / request-reachable RCE

The audited Bun HTTP service was previously swept across multipart/report
parsers, WebSocket burst/close, HTTP lifecycle/body, URL/header/cookie/SSE,
and static/parser surfaces (commits up to `8ae6566`, finding notes under
`lab/findings/candidates/`). None of those exposes the trigger:

* The async `fs.read` BufferSource UAF requires direct calls to
  `fs.read` with a JS-managed `BufferSource`. The HTTP layer hands
  remote callers copied / bounded network data; it does not expose
  `fs.read` against an attacker-controlled `ArrayBuffer`.
* The `commit 4896351 probe remote cve surfaces` round did not find a
  new request-reachable hazard.

Conclusion: not tractable from current evidence. A new finding would
require a separate vulnerability in the HTTP/WebSocket/TLS path that
either gives remote callers a `fs.read`-equivalent BufferSource
lifetime hazard, or an unrelated remote memory-corruption primitive.

## 2. standalone native `system(command)`

This is the ABI-blocked branch documented in
`wasm-descriptor-system-abi-probe-20260510.md`. Summary of the block:

* The forged wasm dispatch descriptor (`fakeDescriptor` mode `system`)
  is strong enough to redirect the call target to an arbitrary native
  address. We confirmed this by pointing it at libc `system`: the
  shell returned `32512 == 127 << 8` and printed
  `sh: @<replacement-char>: command not found`.
* The shell saw exactly two bytes followed by NUL: byte 0 = `0x40`,
  byte 1 = a non-printable byte, byte 2 = `0x00`. That pattern
  matches a JSCell header where `structureID` byte 0 is `0x40`,
  `structureID` byte 1 is some VM-specific value, and
  `indexingType = 0` acts as the NUL terminator. So **x0 at the
  forged BLR was a JSCell pointer** — almost certainly a wasm
  Instance / context cell — not the `i64` argument we passed and not
  attacker-controlled bytes.
* The wasm dispatch trampoline rebuilds x0 from baked context state
  before the BLR. Forcing function-cell offset 40 to a string pointer
  (instead of a real context pointer) wedged the Bun child in an
  uninterruptible state past `SIGKILL`, indicating JSC dereferences
  offset 40 *inside* dispatch setup and fails irrecoverably when the
  pointed-at memory is not a valid context cell.
* This rules out the simple route. To get standalone
  `system(command)` from this primitive, one of the following is
  required:
    * Reverse-engineer JSC's wasm-to-host trampoline on this build
      well enough to find a field whose value is loaded directly into
      x0 at the BLR (without intermediate dereferences). That is
      source-reading work, not blind probing — blind probing on the
      offset-40 path already produced a wedge.
    * Forge a *valid* wasm Instance / context cell whose first 8
      bytes (the part `system` reads when the BLR sets x0 to the
      Instance) spell out a command. JSC would have to walk that fake
      cell during dispatch without touching the bytes we replaced —
      an order-of-operations problem.
    * Find a different IC / JIT callsite whose first-arg ABI is
      directly attacker-controlled. The known `PutByVal` IC stub
      (commit `378039c`) bakes x0 to `JSValue::encode(int32_t 0)` and
      is therefore inert for this purpose.

Conclusion: not tractable in this session. Pushing further on the
offset-40 substitution path is not worth another wedge until JSC
source-side analysis identifies the safe x0 source.

## 3. standalone shellcode execution

* `data-ret` probe in `wasm-descriptor-system-i64-probe.js` already
  attempted the obvious heap-shellcode test. ASan flagged `BUS on
  unknown address` with `pc 0x6020001a5350` inside the ArrayBuffer
  data region. That confirmed W^X / NX behaviour — pages backing
  ArrayBuffer data are not executable.
* Without a W^X bypass, no heap-resident byte sequence becomes
  executable through the dispatch primitive.

Conclusion: not tractable without milestone (4).

## 4. generic ASLR / W^X / PAC bypass

This is its own multi-week research project. Sketch of what would be
needed:

* **ASLR**: derive a stable image base from leaked `low-code-or-image`
  pointers. The harness JSON already records pointers like
  `0x000000010ca0d294` — those are inside the bun-asan binary's
  `__TEXT` segment. Mapping one of them to a known symbol via a
  binary-side disassembly and computing the slide would give image
  base. Doable but requires care; not done here.
* **W^X**: macOS arm64 enforces W^X with extra hardware. Bypass
  routes typically require either a JIT-page race, a `mprotect`
  primitive after arb-write, or a confused-deputy syscall. None of
  the current primitives produces a `mprotect` on attacker-chosen
  pages.
* **PAC**: arm64e on Apple Silicon adds pointer authentication on
  function pointers. Bypass routes typically require a separate
  pointer-signing oracle; the existing call-target control through
  the wasm dispatch hijacks an already-PAC-signed call slot, so PAC
  is sidestepped *for that callsite*, but does not give us a generic
  PAC oracle for arbitrary forged signed pointers.

Conclusion: each leg is a research project on its own; none is
unlocked by the existing UAF / addrof / native-view chain.

## 5. request-reachable exploitability

Same as (1). Until a new HTTP/WebSocket/TLS bug exposes the
BufferSource lifetime trigger or an equivalent native memory
corruption surface, the local-JavaScript boundary remains the
required attacker capability. No new request-side hypothesis was
identified in the probe round in commit `4896351`.

Conclusion: not tractable from current evidence.

## Disclosure framing

None of the five milestones is in a state where the advisory
(`lab/findings/cve-disclosure/ADVISORY.md`) should claim it.
The advisory's existing scope is the right one:

* CWE-416 use-after-free in async `fs.read` / `fs.readv`,
* controlled native heap corruption from local JS,
* no-FFI native R/W over known mapped addresses,
* WebAssembly export dispatch metadata corruption,
* local marker / command side effect through attacker-supplied JS or
  WebAssembly import scaffolding (NOT standalone).

Continue to keep these out of the upstream report:

* remote / request-reachable RCE,
* standalone `system(command)`,
* standalone shellcode execution,
* ASLR / W^X / PAC bypass,
* any claim that the JS-supplied wasm import is "incidental" to the
  command side effect — it is the load-bearing scaffolding.

## Suggested next research moves (out of scope for this commit)

If you want one of the five later, the cleanest follow-ups are:

* For (2): read JSC's `BBQJIT` / `OMGJIT` wasm-to-host trampoline on
  this Bun build. Find the load that produces x0 at the BLR. If x0
  is loaded from a field of the Instance pointer at a fixed offset,
  swap that field via the existing arb-write to the `system` command
  pointer. Restore afterwards. This is bounded source-reading work,
  not blind probing.
* For (4) ASLR leg: pick one `low-code-or-image` pointer from the
  harness JSON, disassemble that address in `bun-asan`, compute
  slide. That alone is a useful disclosure-supporting artifact even
  without a W^X bypass.

## Side-effect note

The previous force-offset-40 run left an ASan Bun child wedged
(`pid 99450` according to the working notes). It is not the lab
harness's scheduling that wedges it; that is the kernel's
uninterruptible-syscall state. Future experiments that *force* the
offset-40 substitution should expect to leak a wedged child.
