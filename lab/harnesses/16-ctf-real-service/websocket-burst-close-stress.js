import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { constants, deflateRawSync } from "node:zlib";

const iterations = Number(process.env.ITERATIONS || 120);
const port = Number(process.env.PORT || (46000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const enc = new TextEncoder();

let child;
let childExited = false;
let upgrades = 0;
let noUpgrade = 0;
let socketErrors = 0;
let timeouts = 0;
const closeBuckets = new Map();

function bytes(text) {
  return enc.encode(text);
}

function concat(parts) {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function wsKey(i) {
  const raw = new Uint8Array(16);
  for (let j = 0; j < raw.length; j++) raw[j] = (i * 73 + j * 19) & 0xff;
  return Buffer.from(raw).toString("base64");
}

function maskBytes(seed) {
  return [
    (seed >>> 24) & 0xff,
    (seed >>> 16) & 0xff,
    (seed >>> 8) & 0xff,
    seed & 0xff,
  ];
}

function frame({
  opcode = 1,
  payload = new Uint8Array(),
  fin = true,
  masked = true,
  rsv1 = false,
  declaredLength = payload.byteLength,
  maskSeed = 0x5a5a5a5a,
}) {
  const header = [(fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | opcode];
  if (declaredLength < 126) {
    header.push((masked ? 0x80 : 0) | declaredLength);
  } else if (declaredLength <= 0xffff) {
    header.push((masked ? 0x80 : 0) | 126, (declaredLength >>> 8) & 0xff, declaredLength & 0xff);
  } else {
    const n = BigInt(declaredLength);
    header.push((masked ? 0x80 : 0) | 127);
    for (let shift = 56n; shift >= 0n; shift -= 8n) header.push(Number((n >> shift) & 0xffn));
  }

  if (!masked) return new Uint8Array([...header, ...payload]);

  const mask = maskBytes(maskSeed);
  const out = new Uint8Array(header.length + 4 + payload.byteLength);
  out.set(header, 0);
  out.set(mask, header.length);
  for (let i = 0; i < payload.byteLength; i++) out[header.length + 4 + i] = payload[i] ^ mask[i & 3];
  return out;
}

function syncFlushDeflate(payload) {
  const compressed = deflateRawSync(payload, { flush: constants.Z_SYNC_FLUSH, finishFlush: constants.Z_SYNC_FLUSH });
  if (
    compressed.length >= 4 &&
    compressed[compressed.length - 4] === 0x00 &&
    compressed[compressed.length - 3] === 0x00 &&
    compressed[compressed.length - 2] === 0xff &&
    compressed[compressed.length - 1] === 0xff
  ) {
    return compressed.subarray(0, compressed.length - 4);
  }
  return compressed;
}

function closeCodeFromServerData(data) {
  const marker = Buffer.from("\r\n\r\n", "latin1");
  const headerEnd = data.indexOf(marker);
  let offset = headerEnd === -1 ? 0 : headerEnd + marker.byteLength;

  while (offset + 2 <= data.byteLength) {
    const first = data[offset++];
    const second = data[offset++];
    const opcode = first & 0x0f;
    let length = second & 0x7f;

    if (length === 126) {
      if (offset + 2 > data.byteLength) return 0;
      length = (data[offset] << 8) | data[offset + 1];
      offset += 2;
    } else if (length === 127) {
      if (offset + 8 > data.byteLength) return 0;
      const bigLength = data.readBigUInt64BE(offset);
      offset += 8;
      if (bigLength > BigInt(Number.MAX_SAFE_INTEGER)) return 0;
      length = Number(bigLength);
    }

    const masked = (second & 0x80) !== 0;
    if (masked) offset += 4;
    if (offset + length > data.byteLength) return 0;
    if (opcode === 8) {
      if (length < 2) return 0;
      return (data[offset] << 8) | data[offset + 1];
    }
    offset += length;
  }
  return 0;
}

function recordClose(data) {
  const code = closeCodeFromServerData(data);
  closeBuckets.set(String(code || "none"), (closeBuckets.get(String(code || "none")) || 0) + 1);
}

function startChallenge() {
  child = spawn(process.execPath, [challenge], {
    env: { ...process.env, PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", chunk => process.stdout.write(`[challenge:stdout] ${chunk}`));
  child.stderr.on("data", chunk => process.stderr.write(`[challenge:stderr] ${chunk}`));
  child.on("exit", (code, signal) => {
    childExited = true;
    process.stderr.write(`[challenge] exited code=${code} signal=${signal}\n`);
  });
}

async function waitForServer() {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (childExited) throw new Error("challenge exited before ready");
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("server did not become ready");
}

function frameBurst(i) {
  const valid = bytes(JSON.stringify({ action: "audit", package: "bun" }));
  const invalid = bytes("{");
  const schema = bytes(JSON.stringify({ action: "audit", package: "BUN" }));
  const oversize = bytes(JSON.stringify({ action: "audit", package: "bun", pad: "A".repeat(650) }));
  const textOversize = bytes("A".repeat(4096));
  const compressedValid = syncFlushDeflate(valid);
  const compressedOversize = syncFlushDeflate(textOversize);
  const compressedInvalid = syncFlushDeflate(invalid);

  switch (i % 12) {
    case 0:
      return Array.from({ length: 48 }, (_, j) => frame({ payload: valid, maskSeed: i + j }));
    case 1:
      return [frame({ payload: oversize, maskSeed: i }), ...Array.from({ length: 24 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 1 }))];
    case 2:
      return [frame({ opcode: 2, payload: textOversize, maskSeed: i }), ...Array.from({ length: 16 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 1 }))];
    case 3:
      return [frame({ payload: invalid, maskSeed: i }), ...Array.from({ length: 32 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 1 }))];
    case 4:
      return [frame({ payload: schema, maskSeed: i }), ...Array.from({ length: 32 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 1 }))];
    case 5:
      return [
        frame({ payload: textOversize.subarray(0, 96), fin: false, maskSeed: i }),
        frame({ opcode: 8, payload: bytes("\x03\xe8bye"), maskSeed: i + 1 }),
        frame({ opcode: 0, payload: textOversize.subarray(96), fin: true, maskSeed: i + 2 }),
      ];
    case 6:
      return [
        frame({ payload: compressedValid, rsv1: true, maskSeed: i }),
        ...Array.from({ length: 40 }, (_, j) => frame({ payload: compressedValid, rsv1: true, maskSeed: i + j + 1 })),
      ];
    case 7:
      return [frame({ payload: compressedOversize, opcode: 2, rsv1: true, maskSeed: i }), ...Array.from({ length: 16 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 1 }))];
    case 8:
      return [frame({ payload: compressedInvalid, rsv1: true, maskSeed: i }), ...Array.from({ length: 32 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 1 }))];
    case 9: {
      const split = Math.max(1, compressedOversize.byteLength >>> 1);
      return [
        frame({ payload: compressedOversize.subarray(0, split), fin: false, rsv1: true, maskSeed: i }),
        frame({ opcode: 0, payload: compressedOversize.subarray(split), fin: true, maskSeed: i + 1 }),
        ...Array.from({ length: 12 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 2 })),
      ];
    }
    case 10:
      return [
        frame({ opcode: 9, payload: bytes("P".repeat(125)), maskSeed: i }),
        frame({ opcode: 9, payload: bytes("Q".repeat(126)), maskSeed: i + 1 }),
        ...Array.from({ length: 12 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 2 })),
      ];
    default:
      return [
        frame({ payload: valid.subarray(0, 8), fin: false, maskSeed: i }),
        frame({ opcode: 0, payload: valid.subarray(8), fin: true, maskSeed: i + 1 }),
        ...Array.from({ length: 40 }, (_, j) => frame({ payload: valid, maskSeed: i + j + 2 })),
      ];
  }
}

async function oneConnection(i) {
  return new Promise(resolve => {
    let socketRef;
    let settled = false;
    let sent = false;
    const chunks = [];

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socketRef?.end();
      } catch {}
      recordClose(Buffer.concat(chunks));
      resolve();
    };

    const timer = setTimeout(() => {
      timeouts++;
      finish();
    }, 2000);

    Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(socket) {
          socketRef = socket;
          socket.write(bytes(
            `GET /ws HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${port}\r\n` +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Key: ${wsKey(i)}\r\n` +
            "Sec-WebSocket-Version: 13\r\n" +
            "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n" +
            "\r\n"
          ));
        },
        data(socket, data) {
          chunks.push(Buffer.from(data));
          const text = Buffer.concat(chunks).toString("latin1");
          if (!sent && text.includes("\r\n\r\n")) {
            if (!text.startsWith("HTTP/1.1 101")) {
              noUpgrade++;
              finish();
              return;
            }
            upgrades++;
            sent = true;
            socket.write(concat(frameBurst(i)));
          }
        },
        close() {
          finish();
        },
        error(_socket, error) {
          socketErrors++;
          process.stderr.write(`[websocket-burst-close-stress] socket error ${error?.message || error}\n`);
          finish();
        },
      },
    }).catch(error => {
      socketErrors++;
      process.stderr.write(`[websocket-burst-close-stress] connect error ${error?.message || error}\n`);
      finish();
    });
  });
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[websocket-burst-close-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    await oneConnection(i);
    if (childExited) throw new Error("challenge child exited during websocket burst close stress");
    if (i % 30 === 0) {
      console.error(`[websocket-burst-close-stress] iteration=${i} upgrades=${upgrades} noUpgrade=${noUpgrade} socketErrors=${socketErrors} timeouts=${timeouts}`);
    }
  }

  console.log(JSON.stringify({
    harness: "websocket-burst-close-stress",
    iterations,
    upgrades,
    noUpgrade,
    socketErrors,
    timeouts,
    closeBuckets: Object.fromEntries([...closeBuckets.entries()].sort()),
  }));
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
}

process.exitCode = 0;
