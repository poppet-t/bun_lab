import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const iterations = Number(process.env.ITERATIONS || 220);
const port = Number(process.env.PORT || (43000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const enc = new TextEncoder();

let child;
let childExited = false;
let upgrades = 0;
let protocolErrors = 0;
let socketErrors = 0;
let noUpgrade = 0;

function bytes(text) {
  return enc.encode(text);
}

function wsKey(i) {
  const raw = new Uint8Array(16);
  for (let j = 0; j < raw.length; j++) raw[j] = (i * 67 + j * 29) & 0xff;
  return Buffer.from(raw).toString("base64");
}

function frame({
  opcode = 1,
  payload = new Uint8Array(),
  fin = true,
  masked = true,
  rsv1 = false,
  declaredLength = payload.byteLength,
  maskSeed = 0x41424344,
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

  const mask = [
    (maskSeed >>> 24) & 0xff,
    (maskSeed >>> 16) & 0xff,
    (maskSeed >>> 8) & 0xff,
    maskSeed & 0xff,
  ];
  const out = new Uint8Array(header.length + 4 + payload.byteLength);
  out.set(header, 0);
  out.set(mask, header.length);
  for (let i = 0; i < payload.byteLength; i++) out[header.length + 4 + i] = payload[i] ^ mask[i & 3];
  return out;
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

function payloads(i) {
  const valid = bytes(JSON.stringify({ action: "audit", package: "bun" }));
  const invalidSchema = bytes(JSON.stringify({ action: "audit", package: "BUN" }));
  const oversizeJson = bytes(JSON.stringify({ action: "audit", package: "bun", pad: "A".repeat(700) }));
  const rawOversize = bytes("A".repeat(4096));
  const compressedValid = deflateRawSync(valid);
  const compressedOversize = deflateRawSync(rawOversize);

  switch (i % 16) {
    case 0:
      return [frame({ opcode: 1, payload: oversizeJson, maskSeed: i })];
    case 1:
      return Array.from({ length: 40 }, (_, j) => frame({ opcode: 1, payload: valid, maskSeed: i + j }));
    case 2:
      return [frame({ opcode: 2, payload: new Uint8Array([0xff, 0xfe, 0xfa]), maskSeed: i })];
    case 3:
      return [
        frame({ opcode: 1, payload: rawOversize.subarray(0, 32), fin: false, maskSeed: i }),
        frame({ opcode: 0, payload: rawOversize.subarray(32), fin: true, maskSeed: i + 1 }),
      ];
    case 4:
      return [frame({ opcode: 1, payload: valid, rsv1: true, maskSeed: i })];
    case 5:
      return [frame({ opcode: 2, payload: rawOversize, rsv1: true, maskSeed: i })];
    case 6:
      return [frame({ opcode: 1, payload: valid.subarray(0, 4), declaredLength: valid.byteLength + 1024, maskSeed: i })];
    case 7:
      return [frame({ opcode: 1, payload: valid, masked: false })];
    case 8:
      return [frame({ opcode: 9, payload: bytes("P".repeat(126)), maskSeed: i })];
    case 9:
      return [frame({ opcode: 1, payload: invalidSchema, maskSeed: i })];
    case 10:
      return [frame({ opcode: 1, payload: bytes("{"), maskSeed: i })];
    case 11:
      return [frame({ opcode: 1, payload: valid, maskSeed: i })];
    case 12:
      return [frame({ opcode: 1, payload: compressedValid, rsv1: true, maskSeed: i })];
    case 13:
      return [frame({ opcode: 2, payload: compressedValid, rsv1: true, maskSeed: i })];
    case 14:
      return [frame({ opcode: 1, payload: compressedOversize, rsv1: true, maskSeed: i })];
    default: {
      const split = Math.max(1, compressedOversize.length >>> 1);
      return [
        frame({ opcode: 1, payload: compressedOversize.subarray(0, split), fin: false, rsv1: true, maskSeed: i }),
        frame({ opcode: 0, payload: compressedOversize.subarray(split), fin: true, maskSeed: i + 1 }),
      ];
    }
  }
}

function startChallenge() {
  child = spawn(process.execPath, [challenge], {
    env: { ...process.env, PORT: String(port), FLAG: "SCTF{ws_probe}" },
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

async function oneConnection(i) {
  return new Promise(resolve => {
    let socketRef;
    let settled = false;
    let sentFrames = false;
    const chunks = [];
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socketRef?.end();
      } catch {}
      resolve();
    };
    const timer = setTimeout(finish, 1200);

    Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(socket) {
          socketRef = socket;
          const extension = i % 2 === 0 || i % 16 >= 12
            ? "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
            : "";
          socket.write(bytes(
            `GET /ws HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${port}\r\n` +
            `Upgrade: websocket\r\n` +
            `Connection: Upgrade\r\n` +
            `Sec-WebSocket-Key: ${wsKey(i)}\r\n` +
            `Sec-WebSocket-Version: 13\r\n` +
            extension +
            `\r\n`
          ));
        },
        data(socket, data) {
          chunks.push(Buffer.from(data));
          const text = Buffer.concat(chunks).toString("latin1");
          if (!sentFrames && text.includes("\r\n\r\n")) {
            if (text.startsWith("HTTP/1.1 101")) {
              sentFrames = true;
              upgrades++;
              for (const part of payloads(i)) socket.write(part);
              setTimeout(finish, 30);
            } else {
              noUpgrade++;
              if (text.includes("400") || text.includes("426")) protocolErrors++;
              finish();
            }
          }
        },
        close: finish,
        error(_socket, error) {
          socketErrors++;
          process.stderr.write(`[websocket-close-stress] socket error ${error?.message || error}\n`);
          finish();
        },
      },
    }).catch(error => {
      socketErrors++;
      process.stderr.write(`[websocket-close-stress] connect error ${error?.message || error}\n`);
      finish();
    });
  });
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[websocket-close-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    await oneConnection(i);
    if (childExited) throw new Error("challenge child exited during websocket stress");
    if (i % 50 === 0) console.error(`[websocket-close-stress] iteration=${i} upgrades=${upgrades} noUpgrade=${noUpgrade} socketErrors=${socketErrors}`);
  }

  console.log(JSON.stringify({
    harness: "websocket-close-stress",
    iterations,
    upgrades,
    noUpgrade,
    protocolErrors,
    socketErrors,
  }));
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
}

process.exitCode = 0;
