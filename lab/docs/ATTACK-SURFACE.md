# Bun Memory-Corruption Attack Surface (Top 15)

Ranked review queue for hunting memory corruption (UAF, heap overflow, OOB,
double-free, type confusion) in Bun. Every path in this doc was verified
against the local checkout at `bun/` on first authoring — re-verify before
quoting upstream.

Each entry: rank, area, why-risky (one line), key files, JS API that exposes
it, fuzz-target function names. Use these as starting points for the
harnesses in `lab/harnesses/`.

---

### 1. HTTP/1.1 header & request parser
- **Why risky:** PicoHTTPParser + llhttp parse untrusted bytes with manual length math.
- **Files:** `src/picohttp_sys/picohttpparser.zig`, `src/jsc/bindings/node/http/llhttp/` (vendor), `src/http/`
- **JS API:** `Bun.serve()`, `fetch()`, `node:http` server
- **Fuzz targets:** `phr_parse_request`, `llhttp_execute`, `picohttp.Response.parseParts`

### 2. IPC / Worker message deserialization
- **Why risky:** length-prefix parsing of u32 from untrusted side; SerializedScriptValue surface.
- **Files:** `src/jsc/ipc.zig`, `src/jsc/web_worker.zig`
- **JS API:** `new Worker(...)`, `worker.postMessage`, parent⇄child IPC, `node:worker_threads`
- **Fuzz targets:** `decodeIPCMessage`, structured-clone deserializer

### 3. Tarball / libarchive extraction
- **Why risky:** tar header parsing + sparse-file reconstruction with pointer arithmetic; path traversal.
- **Files:** `src/install/TarballStream.zig`, `src/install/extract_tarball.zig`, vendored libarchive
- **JS API:** `bun install` (npm tarball), indirect via fetch+decompress
- **Fuzz targets:** `TarballStream.onChunk`, `archive_read_next_header`, `writeDataBlock`

### 4. Decompression (zlib / brotli / zstd)
- **Why risky:** untrusted compressed bytes → inflated buffers; format autodetect on `windowBits`.
- **Files:** `src/http/Decompressor.zig`, `src/http/zlib.zig`, `src/brotli/`, `src/zstd/`
- **JS API:** `fetch()` with `Content-Encoding: gzip|deflate|br|zstd`, `Bun.file().text()`
- **Fuzz targets:** `Decompressor.updateBuffers`, `ZlibReaderArrayList.init`, `BrotliReaderArrayList.newWithOptions`

### 5. HTTP/2 frame parser
- **Why risky:** binary framing + HPACK header decoder, multiple length fields per frame.
- **Files:** `src/http/H2FrameParser.zig`, `src/http/h2_client/`, vendored lshpack
- **JS API:** `fetch()` to HTTP/2 servers, HTTP/2 `Bun.serve()`
- **Fuzz targets:** `parseFrames`, HPACK decode entry points

### 6. HTTP/3 / QUIC
- **Why risky:** packet framing + QPACK over unreliable transport, large state machine.
- **Files:** `src/http/H3Client.zig`, vendored lsquic + lsqpack
- **JS API:** `fetch()` to HTTP/3 endpoints
- **Fuzz targets:** `lsquic_engine_packet_in`, QPACK decoder, stream-frame handlers

### 7. Postgres wire-protocol parser
- **Why risky:** binary wire format with nested messages, types, SASL; malformed server response.
- **Files:** `src/sql/postgres/`, `src/sql_jsc/`
- **JS API:** `import { sql } from "bun:sql"`, `postgres()` driver
- **Fuzz targets:** `FieldDescription.read`, `DataRow.read`, `Authentication` handlers, `NewReader.decode*`

### 8. `bun:ffi` raw memory access
- **Why risky:** direct pointer casting, struct-layout assumptions, attacker-controlled C signatures.
- **Files:** `src/jsc/FFI.zig`, `src/runtime/ffi/`, `src/jsc/bindings/ffi.cpp`, `src/jsc/bindings/JSFFIFunction.cpp`
- **JS API:** `bun:ffi`, `dlopen`, callback registration
- **Fuzz targets:** `FFI.call`, struct field marshaling, callback dispatch
- **Caveat:** mis-typed FFI calls are unsafe **by design**. Bug only counts if a *binding* layer error (not user error) leads to corruption.

### 9. JSON parser (JSC + interchange)
- **Why risky:** JSC's JSON path + Bun's interchange parser for special types.
- **Files:** `src/interchange/json.zig`, `src/interchange/json5.zig`, JSC JSON (vendor)
- **JS API:** `JSON.parse`, `JSON.stringify`, `await response.json()`
- **Fuzz targets:** JSC JSON decoder (C++), `interchange.parse`

### 10. ArrayBuffer / TypedArray / DataView interop
- **Why risky:** length checks at JS↔native boundary, SAB races.
- **Files:** `src/jsc/array_buffer.zig`, `src/jsc/JSValue.zig`, `src/jsc/bindings/Uint8Array.cpp`
- **JS API:** `ArrayBuffer`, `*Array`, `DataView`, `SharedArrayBuffer`
- **Fuzz targets:** `getTypedArrayData`, buffer slicing, SAB concurrent access

### 11. NAPI bindings (Node-API)
- **Why risky:** lots of `@ptrCast` (1500+); user-controlled indices reach pointer arithmetic.
- **Files:** `src/napi/`, `src/jsc/bindings/napi.cpp`
- **JS API:** native modules via `require()`, `process.dlopen`
- **Fuzz targets:** `napi_get_element`, `napi_set_element`, property getters with untrusted keys

### 12. CSS parser
- **Why risky:** hand-written parser with backtracking; malformed selectors/values.
- **Files:** `src/css/css_parser.zig`, `src/css/declaration.zig`, `src/css_jsc/`
- **JS API:** static CSS via `Bun.serve`, bundler CSS, `<style>` in HTML imports
- **Fuzz targets:** `css_parser.parseRule`, selector tokenizer, value parsers

### 13. Shell parser & glob expansion
- **Why risky:** brace expansion limits, nested braces, glob + symlink interaction.
- **Files:** `src/shell_parser/braces.zig`, `src/shell/`, path canonicalization
- **JS API:** `Bun.$`, `Bun.shell()`, `Bun.glob()`, `import.meta.glob`
- **Fuzz targets:** `expand`, `braces::Parser.parse`, symlink resolution paths

### 14. BoringSSL / X.509 / ASN.1
- **Why risky:** classic CVE family; X.509 parsing is full of UB-traps.
- **Files:** `src/boringssl/`, `src/runtime/crypto/`, `src/jsc/bindings/node/crypto/`, vendored boringssl
- **JS API:** `fetch()` TLS, `node:https`, `bun:sql` w/ TLS, secure WebSocket
- **Fuzz targets:** X.509 DER parser, EVP_*, TLS record layer

### 15. JS parser / module loader
- **Why risky:** parser with macros, source maps, dynamic import; escape-sequence edge cases.
- **Files:** `src/js_parser_jsc/`, `src/js_parser/`, `src/jsc/ModuleLoader.zig`
- **JS API:** `eval`, `new Function()`, dynamic `import()`
- **Fuzz targets:** `JSParser.parse`, escape handling, template-literal nesting

---

## Hot patterns to grep for

```regex
# Pointer casts that drop alignment / lifetime info
@ptrCast | @intToPtr | @ptrFromInt | reinterpret_cast<

# Bounds-check arithmetic with untrusted operands
data\.len\s*-\s*[a-z_]+ | header_length\s*\+\s*[a-z_]+

# Buffer-size math from JS values
avail_in | avail_out | byteLength | byteOffset | toUint32

# Layout / size assumptions
@sizeOf .* @alignOf | extern struct | packed struct

# Manual byte copy with dynamic length
memcpy\( | memmove\( | @memcpy\( | std\.mem\.copy

# Re-entrancy: native code that may call back into JS mid-operation
callJSC | profiledCall | ->call\( | asyncTask
```

`lab/scripts/grep-risky.sh` runs a curated subset of these against `src/`.
