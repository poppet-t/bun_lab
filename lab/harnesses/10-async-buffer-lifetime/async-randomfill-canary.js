import { randomFill } from "node:crypto";

const iterations = Number(process.env.ITERATIONS || 256);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 2048);

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone(ab, { transfer: [ab] });
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

function allocateCanaries() {
  return Array.from({ length: sprayCount }, () => {
    const view = new Uint8Array(new ArrayBuffer(size));
    view.fill(0x7c);
    return view;
  });
}

function findChanged(canaries) {
  for (let i = 0; i < canaries.length; i++) {
    const view = canaries[i];
    for (let j = 0; j < 64; j++) {
      if (view[j] !== 0x7c) return i;
    }
  }
  return -1;
}

async function runOne(i) {
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);
  const done = new Promise((resolve) => randomFill(view, (err) => resolve(err)));

  detach(ab);
  gcNow();
  const canaries = allocateCanaries();

  const err = await done;
  const index = findChanged(canaries);
  if (index !== -1) {
    console.error(`[randomFill:canary] stale write changed canary iteration=${i} canary=${index} err=${err?.message || "none"}`);
    return true;
  }
  return false;
}

for (let i = 1; i <= iterations; i++) {
  if (await runOne(i)) {
    process.exitCode = 86;
    break;
  }
  if (i % 16 === 0) console.error(`[randomFill:canary] progress=${i}`);
}

console.error("[randomFill:canary] done");
