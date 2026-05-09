import fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 2000);
const size = Number(process.env.BUF_SIZE || 65536);
const batchSize = Number(process.env.BATCH_SIZE || 64);
const path = join(tmpdir(), `bun-async-read-detach-${process.pid}.bin`);

fs.writeFileSync(path, Buffer.alloc(size, 0x41));
const fd = fs.openSync(path, "r");

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
    console.error(`[fs.read] detach threw: ${e?.message}`);
  }
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

function runOne() {
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);

  const done = new Promise((resolve) => {
    fs.read(fd, view, 0, view.byteLength, 0, (err, bytesRead) => {
      callbacks++;
      if (err) errors++;
      resolve({ err, bytesRead });
    });
  });

  detach(ab);
  gcNow();
  return done;
}

try {
  for (let i = 0; i < iterations; i += batchSize) {
    const batch = [];
    for (let j = 0; j < batchSize && i + j < iterations; j++) {
      batch.push(runOne());
    }
    await Promise.all(batch);
    if ((i / batchSize) % 16 === 0) {
      console.error(`[fs.read] progress=${Math.min(i + batchSize, iterations)} detached=${detached} callbacks=${callbacks} errors=${errors}`);
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

console.error(`[fs.read] done iterations=${iterations} detached=${detached} callbacks=${callbacks} errors=${errors}`);
