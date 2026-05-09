// Exercise bun:ffi argument conversion edges with correctly typed libc calls.

import { dlopen, FFIType, JSCallback, ptr, read, suffix } from "bun:ffi";

const { symbols } = dlopen(`libc.${suffix}`, {
  abs: { args: [FFIType.i32], returns: FFIType.i32 },
  strlen: { args: [FFIType.cstring], returns: FFIType.u64 },
  memcmp: { args: [FFIType.ptr, FFIType.ptr, FFIType.u64], returns: FFIType.i32 },
});

function attempt(label, fn) {
  try {
    const result = fn();
    console.error(`[ffi] ${label}: ${String(result)}`);
  } catch (error) {
    console.error(`[ffi] ${label}: threw ${error?.message || error}`);
  }
}

const a = new Uint8Array([0x41, 0x42, 0x43, 0]);
const b = new Uint8Array([0x41, 0x42, 0x44, 0]);

attempt("abs(INT_MAX)", () => symbols.abs(2147483647));
attempt("abs(INT_MIN)", () => symbols.abs(-2147483648));
attempt("abs(NaN)", () => symbols.abs(NaN));
attempt("abs(Infinity)", () => symbols.abs(Infinity));
attempt("abs(2**40)", () => symbols.abs(2 ** 40));
attempt("abs(-(2**40))", () => symbols.abs(-(2 ** 40)));
attempt("memcmp(small,small,3)", () => symbols.memcmp(ptr(a), ptr(b), 3n));
attempt("memcmp len=0", () => symbols.memcmp(ptr(a), ptr(b), 0n));
attempt("memcmp len as Number", () => symbols.memcmp(ptr(a), ptr(b), 3));
attempt("memcmp len negative-as-bigint", () => symbols.memcmp(ptr(a), ptr(b), -1n));
attempt("strlen(empty)", () => symbols.strlen(ptr(new Uint8Array([0]))));

attempt("strlen(detached)", () => {
  const buf = new ArrayBuffer(8);
  const view = new Uint8Array(buf);
  view[0] = 0;
  structuredClone(buf, { transfer: [buf] });
  return symbols.strlen(ptr(view));
});

attempt("ptr(zero-len)", () => ptr(new Uint8Array(0)));

const cb = new JSCallback(
  (value) => value + 1,
  { args: [FFIType.i32], returns: FFIType.i32 },
);
attempt("JSCallback.ptr()", () => cb.ptr);
attempt("read.intptr at cb.ptr", () => read.intptr(cb.ptr, 0));
cb.close();

console.error("[ffi] done");
