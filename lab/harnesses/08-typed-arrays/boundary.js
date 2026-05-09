// TypedArray/DataView boundary and detach edge cases.

function attempt(label, fn) {
  try {
    console.error(`[typed] ${label}: ${String(fn())}`);
  } catch (error) {
    console.error(`[typed] ${label}: threw ${error?.message || error}`);
  }
}

attempt("DataView ofs > buflen", () => new DataView(new ArrayBuffer(8), 9));
attempt("DataView neg ofs", () => new DataView(new ArrayBuffer(8), -1));
attempt("DataView ofs at buflen", () => new DataView(new ArrayBuffer(8), 8).getUint32(0));
attempt("DataView read past end", () => new DataView(new ArrayBuffer(4)).getUint32(1));
attempt("Uint32Array unaligned", () => new Uint32Array(new ArrayBuffer(8), 1));
attempt("Uint16Array odd offset", () => new Uint16Array(new ArrayBuffer(8), 1));
attempt("Uint8Array negative len", () => new Uint8Array(new ArrayBuffer(8), 0, -1));
attempt("Uint8Array oversize len", () => new Uint8Array(new ArrayBuffer(8), 4, 9));

attempt("set across resize", () => {
  const ab = new ArrayBuffer(16, { maxByteLength: 32 });
  const u8 = new Uint8Array(ab);
  ab.resize(4);
  u8.set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  return u8.length;
});

attempt("subarray after detach", () => {
  const ab = new ArrayBuffer(16);
  const u8 = new Uint8Array(ab);
  structuredClone(ab, { transfer: [ab] });
  return u8.subarray(0, 1).length;
});

attempt("SAB atomic OOB", () => {
  const sab = new SharedArrayBuffer(8);
  const view = new Int32Array(sab);
  return Atomics.load(view, 3);
});

attempt("SAB DataView oversize", () => {
  const sab = new SharedArrayBuffer(8);
  return new DataView(sab, 4, 8).byteLength;
});

attempt("Float64 NaN bit pattern", () => {
  const ab = new ArrayBuffer(8);
  new DataView(ab).setBigUint64(0, 0x7ff8000000000001n, true);
  return new Float64Array(ab)[0];
});

attempt("resize past max", () => {
  const ab = new ArrayBuffer(8, { maxByteLength: 16 });
  ab.resize(32);
  return ab.byteLength;
});

console.error("[typed] done");
