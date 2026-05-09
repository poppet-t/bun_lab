import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 128);
const viewsPerCall = Number(process.env.VIEWS_PER_CALL || 4);
const viewSize = Number(process.env.VIEW_SIZE || 2048);
const path = join(tmpdir(), `bun-async-readv-fifo-${process.pid}`);

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) {
  throw new Error(`mkfifo failed with status ${mkfifo.status}`);
}

const fd = fs.openSync(path, fs.constants.O_RDWR);
const payload = Buffer.alloc(viewsPerCall * viewSize, 0x44);

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
    console.error(`[fs.readv:fifo] detach threw: ${e?.message}`);
  }
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

async function runOne(i) {
  const buffers = Array.from({ length: viewsPerCall }, () => new Uint8Array(new ArrayBuffer(viewSize)));
  const backingStores = buffers.map((view) => view.buffer);

  const done = new Promise((resolve) => {
    fs.readv(fd, buffers, null, (err, bytesRead) => {
      callbacks++;
      if (err) errors++;
      resolve({ err, bytesRead });
    });
  });

  buffers.length = 0;
  for (const ab of backingStores) detach(ab);
  gcNow();

  fs.writeSync(fd, payload, 0, payload.length);

  await done;
  if (i % 16 === 0) {
    console.error(`[fs.readv:fifo] progress=${i} detached=${detached} callbacks=${callbacks} errors=${errors}`);
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

console.error(`[fs.readv:fifo] done iterations=${iterations} detached=${detached} callbacks=${callbacks} errors=${errors}`);
