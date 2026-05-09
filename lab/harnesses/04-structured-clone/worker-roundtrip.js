// Exercise Worker structured-clone and transferable edge cases.

const workerSource = `
self.onmessage = (event) => {
  try {
    self.postMessage({ ok: true, value: event.data }, event.data?.transfer || []);
  } catch (error) {
    self.postMessage({ ok: false, error: String(error?.message || error) });
  }
};
`;

const workerURL = URL.createObjectURL(new Blob([workerSource], { type: "application/javascript" }));
const worker = new Worker(workerURL);

function roundTrip(value, transfer = []) {
  return new Promise((resolve) => {
    worker.onmessage = (event) => resolve(event.data);
    worker.postMessage(value, transfer);
  });
}

const cycle = {};
cycle.self = cycle;

const shared = new SharedArrayBuffer(64);
const ab = new ArrayBuffer(128);
const u8 = new Uint8Array(ab);
for (let i = 0; i < u8.length; i++) u8[i] = i & 0xff;

const payloads = [
  { label: "cycle", value: cycle },
  { label: "map-set", value: new Map([[{ k: 1 }, new Set([1, 2, 3])]]) },
  { label: "typed-views", value: { u8, dv: new DataView(ab, 1, 32), i32: new Int32Array(ab, 4, 8) } },
  { label: "sab", value: { shared, view: new Uint8Array(shared) } },
  { label: "deep", value: Array.from({ length: 256 }).reduce((acc, _, i) => ({ i, acc }), null) },
  { label: "transfer", value: { buf: new ArrayBuffer(4096) }, transfer: [] },
];

payloads[payloads.length - 1].transfer = [payloads[payloads.length - 1].value.buf];

for (const payload of payloads) {
  const result = await roundTrip(payload.value, payload.transfer || []);
  console.error(`[structured-clone] ${payload.label} ok=${result.ok}`);
}

worker.terminate();
URL.revokeObjectURL(workerURL);
console.error("[structured-clone] done");
