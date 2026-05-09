// Probe whether JSCallback keeps the JS closure alive across GC pressure.

import { CFunction, JSCallback, FFIType } from "bun:ffi";

const iterations = Number(process.env.ITERATIONS || 1000);
let calls = 0;

let callback = new JSCallback(
  (value) => {
    calls++;
    return value + 7;
  },
  { args: [FFIType.i32], returns: FFIType.i32 },
);

const fn = new CFunction({
  ptr: callback.ptr,
  args: [FFIType.i32],
  returns: FFIType.i32,
});
callback = null;

for (let i = 0; i < iterations; i++) {
  Bun.gc(true);
  const result = fn(35);
  if (result !== 42) {
    throw new Error(`bad callback result ${result}`);
  }
  if (i % 100 === 0) console.error(`[ffi-callback] iteration=${i}`);
}

fn.close();
console.error(`[ffi-callback] done calls=${calls}`);
