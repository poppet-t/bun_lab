# Finding Candidate: CSS @property syntax raw UTF-8 OOB slice

**Severity:** unknown, likely low to medium pending release-mode validation
**Exploitability:** unknown
**ASan signature:** not cleanly captured yet; local ASan child wedged after repro
**Crash hash:** none yet
**First seen:** 2026-05-09 local subagent audit
**Bun rev:** `6d0d86b71a1978c8c16e80be24e36ade391084dc`
**Build profile:** `release-asan`

## TL;DR

Malformed raw bytes inside a CSS `@property syntax` string can make the parser advance by the claimed UTF-8 sequence length without checking that enough bytes remain. The parser then slices to the advanced offset. Safety builds trap with an out-of-bounds index; release-style builds need validation to determine whether this becomes an OOB read, invalid parser state, or only a checked crash.

## Reproducer Shape

The important property is raw CSS bytes, not a JavaScript string round-trip. A syntax literal containing a truncated multi-byte UTF-8 starter such as `0xf0` is enough to reach the suspect path:

```js
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "css-prop-syntax-"));
const css = Buffer.concat([
  Buffer.from('@property --x{syntax:"'),
  Buffer.from([0xf0]),
  Buffer.from('";inherits:false;initial-value:'),
  Buffer.from([0xf0]),
  Buffer.from("}"),
]);

writeFileSync(join(dir, "case.css"), css);
await Bun.build({ entrypoints: [join(dir, "case.css")], throw: false });
```

Do not treat this as disclosure-ready until it is captured with a clean sanitizer log. One local ASan run wedged in macOS process state `UEs` after this repro.

## Root Cause Notes

- **Bug class:** OOB slice / possible OOB read
- **Primary source:** `bun/src/css/values/syntax.zig:331`
- **Reachable from:** `@property` parsing via `bun/src/css/rules/property.zig:150`, reached during bundler CSS parsing from `bun/src/bundler/ParseTask.zig:578`
- **Trigger:** a raw byte `>= 0x80` at the end of a syntax literal

At `SyntaxComponentKind.parseString`, non-ASCII bytes are accepted as identifier/name code points. The loop increments `end_idx` by `bun.strings.utf8ByteSequenceLengthUnsafe(input.*[end_idx])`. For `0xf0`, that increment is 4. If only one byte remains, `end_idx` becomes 4 for a 1-byte input. The later `input.*[0..end_idx]` slice is out of bounds.

## Impact Notes

Reachability is through attacker-supplied CSS processed by Bun's bundler or static CSS pipeline. The current evidence supports a build-time crash and a plausible OOB-read candidate. It does not support an RCE claim.

Production relevance is higher than the initial ASan result suggests: Bun's normal non-Windows release profile uses Zig `ReleaseFast`, while `release-asan` uses `ReleaseSafe`. In `ReleaseSafe`, the malformed slice trips a safety check. In `ReleaseFast`, the same invalid UTF-8 length arithmetic may create an oversized slice instead of trapping.

Current RCE assessment: unlikely from this bug alone. The identified primitive is read/slice advancement, not an attacker-controlled write or use-after-free. At most, the malformed UTF-8 starter can make the literal component include a few bytes past the quoted syntax string, and the remaining parser input can underflow to an oversized slice. That is worth reporting and fixing, but it is not enough evidence for code execution.

## Validation Needed

- Capture a clean ASan/UBSan log without the macOS post-report wedge.
- Verify behavior under a release profile without Zig safety checks.
- Add a raw-byte regression test that writes bytes directly to disk. Existing fuzz tests convert byte arrays through JS strings, which can normalize invalid UTF-8 and miss this class.
- Variant-check CSS identifier, string, URL, and escape decoding paths that use unsafe UTF-8 length advancement.

## Disclosure

- [x] Verified against current `origin/main` as of 2026-05-09: `6d0d86b71a1978c8c16e80be24e36ade391084dc`
- [ ] Clean sanitizer log captured
- [ ] Minimal stable repro captured through `lab/scripts/triage.sh`
- [ ] Release-mode impact assessed
- [ ] Report prepared for `security@bun.com` per `bun/SECURITY.md`
