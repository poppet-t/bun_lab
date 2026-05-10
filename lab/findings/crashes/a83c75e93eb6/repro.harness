import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 128);
const size = Number(process.env.BUF_SIZE || 8192);
const path = join(tmpdir(), `bun-async-read-fifo-${process.pid}`);

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) {
  throw new Error(`mkfifo failed with status ${mkfifo.status}`);
}

const fd = fs.openSync(path, fs.constants.O_RDWR);
const payload = Buffer.alloc(size, 0x43);

let detached = 0;
let callbacks = 0;
let errors = 0;

function detach(ab) {
  try {
    if (typeof ab.transfer === "function") {
      ab.transfer(0);
    } else {
      structuredClone(ab, { transfer: [ab] });
    }
    if (ab.byteLength === 0) detached++;
  } catch (e) {
    console.error(`[fs.read:fifo] detach threw: ${e?.message}`);
  }
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

async function runOne(i) {
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);

  const done = new Promise((resolve) => {
    fs.read(fd, view, 0, view.byteLength, null, (err, bytesRead) => {
      callbacks++;
      if (err) errors++;
      resolve({ err, bytesRead });
    });
  });

  detach(ab);
  gcNow();

  // Release the worker read only after the original backing store has been
  // detached from JS.
  fs.writeSync(fd, payload, 0, payload.length);

  await done;
  if (i % 16 === 0) {
    console.error(`[fs.read:fifo] progress=${i} detached=${detached} callbacks=${callbacks} errors=${errors}`);
  }
}

try {
  for (let i = 1; i <= iterations; i++) {
    await runOne(i);
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

console.error(`[fs.read:fifo] done iterations=${iterations} detached=${detached} callbacks=${callbacks} errors=${errors}`);
