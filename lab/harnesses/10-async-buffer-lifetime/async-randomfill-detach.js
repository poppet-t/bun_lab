import { randomFill } from "node:crypto";

const iterations = Number(process.env.ITERATIONS || 4000);
const size = Number(process.env.BUF_SIZE || 65536);
const batchSize = Number(process.env.BATCH_SIZE || 128);

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
    console.error(`[randomFill] detach threw: ${e?.message}`);
  }
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

function runOne() {
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);

  const done = new Promise((resolve) => {
    randomFill(view, (err) => {
      callbacks++;
      if (err) errors++;
      resolve(err);
    });
  });

  detach(ab);
  gcNow();
  return done;
}

for (let i = 0; i < iterations; i += batchSize) {
  const batch = [];
  for (let j = 0; j < batchSize && i + j < iterations; j++) {
    batch.push(runOne());
  }
  await Promise.all(batch);
  if ((i / batchSize) % 16 === 0) {
    console.error(`[randomFill] progress=${Math.min(i + batchSize, iterations)} detached=${detached} callbacks=${callbacks} errors=${errors}`);
  }
}

console.error(`[randomFill] done iterations=${iterations} detached=${detached} callbacks=${callbacks} errors=${errors}`);
