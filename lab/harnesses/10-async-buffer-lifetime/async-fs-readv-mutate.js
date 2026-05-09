import fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 2000);
const viewsPerCall = Number(process.env.VIEWS_PER_CALL || 4);
const viewSize = Number(process.env.VIEW_SIZE || 16384);
const batchSize = Number(process.env.BATCH_SIZE || 64);
const path = join(tmpdir(), `bun-async-readv-mutate-${process.pid}.bin`);

fs.writeFileSync(path, Buffer.alloc(viewsPerCall * viewSize, 0x42));
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
    console.error(`[fs.readv] detach threw: ${e?.message}`);
  }
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

function runOne() {
  const buffers = Array.from({ length: viewsPerCall }, () => new Uint8Array(new ArrayBuffer(viewSize)));
  const backingStores = buffers.map((view) => view.buffer);

  const done = new Promise((resolve) => {
    fs.readv(fd, buffers, 0, (err, bytesRead) => {
      callbacks++;
      if (err) errors++;
      resolve({ err, bytesRead });
    });
  });

  // Mutate the rooted outer array after scheduling so the raw iovec list is the
  // only remaining record of the original view pointers.
  buffers.length = 0;
  for (const ab of backingStores) detach(ab);
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
      console.error(`[fs.readv] progress=${Math.min(i + batchSize, iterations)} detached=${detached} callbacks=${callbacks} errors=${errors}`);
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

console.error(`[fs.readv] done iterations=${iterations} detached=${detached} callbacks=${callbacks} errors=${errors}`);
