# Fuzzilli (coverage-guided JS engine fuzzer)

Bun ships a Fuzzilli build profile (`build:debug:fuzzilli`). Fuzzilli is
the fuzzer that has historically found the most bugs in JavaScriptCore /
V8 / SpiderMonkey. With ASan + Fuzzilli, you get coverage-guided
exploration of the runtime against semantically-valid JS programs.

## What it covers

Fuzzilli targets the **JS engine** — specifically JIT compilers, inline
caches, structured GC, builtin functions. It does not, by itself, drive
network/file parsers like the HTTP parser or postgres protocol. For those,
use the targeted harnesses in `lab/harnesses/`.

JS engine bugs Fuzzilli typically finds:

- Type-confusion in inline caches
- JIT speculation bugs (compiles assuming type X, runtime sees type Y, OOB)
- GC mark-stack overruns
- Builtin functions with hand-rolled length math (Array, TypedArray, Map)

## Building the Fuzzilli profile

`bun run build:debug:fuzzilli` (note: requires the same vendor deps as the
debug build). The build flag `enable_fuzzilli=on` adds
`-fsanitize-coverage=trace-pc-guard` and a REPRL (READ-EVAL-PRINT-RELOOP)
mode that lets Fuzzilli's controller talk to a long-lived bun process via
file descriptors.

`bun/build.zig` enforces that Fuzzilli requires ASan — that's deliberate.
A coverage-guided fuzzer without a memory-corruption oracle is mostly just
testing that the code runs.

## Running

You'll need the Fuzzilli upstream:

```sh
git clone https://github.com/googleprojectzero/fuzzilli.git ~/src/fuzzilli
cd ~/src/fuzzilli
swift build -c release
```

Then point Fuzzilli at the bun-fuzzilli binary:

```sh
~/src/fuzzilli/.build/release/FuzzilliCli \
  --profile=jsc \
  --storagePath=$HOME/fuzzilli-bun-out \
  --resume \
  /Users/CJ/Documents/bun_lab/bun/build/debug-fuzz/bun-debug
```

(There isn't a Bun-specific Fuzzilli profile upstream as of writing; the
JSC profile is closest because Bun uses JSC. Watch the corpus rate — if
it's not climbing, the binary isn't responding to REPRL correctly.)

## Triage

Fuzzilli writes `interesting/`, `crashes/` directories. Run any saved
crash through the lab's triage so you get a stable signature and dedup:

```sh
lab/scripts/triage.sh ~/fuzzilli-bun-out/crashes/<id>.js
```

## Caveats

- Fuzzilli's mutator generates JS that's semantically dense — it will
  exercise builtins you don't have explicit coverage for. Don't be
  surprised when it finds bugs in surface area unrelated to your stated
  target. (That's a feature.)
- Crashes Fuzzilli surfaces are usually in JSC, not Bun-specific code.
  If the top frame is `JSC::*`, file with WebKit (`bugs.webkit.org`) and
  *cross-link* to Bun (`security@bun.com`) so they coordinate.
- Fuzzilli mutates JS programs but **does not** drive HTTP / FFI / shell
  / etc. Those need their own harnesses.
