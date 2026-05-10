import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const iterations = Number(process.env.ITERATIONS || 1000);
const port = Number(process.env.PORT || (42000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const enc = new TextEncoder();

let child;
let childExited = false;
let internalErrors = 0;
let socketErrors = 0;
let wsUpgrades = 0;
let wsErrors = 0;
const statusCounts = new Map();

function bytes(text) {
  return enc.encode(text);
}

function concat(parts) {
  let total = 0;
  for (const part of parts) total += typeof part === "string" ? enc.encode(part).byteLength : part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    const chunk = typeof part === "string" ? enc.encode(part) : part;
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function recordStatuses(text) {
  const matches = [...text.matchAll(/HTTP\/1\.1\s+(\d+)/g)].map(match => Number(match[1]));
  if (matches.length === 0) {
    statusCounts.set("no-status", (statusCounts.get("no-status") || 0) + 1);
    return matches;
  }

  for (const status of matches) {
    statusCounts.set(String(status), (statusCounts.get(String(status)) || 0) + 1);
    if (status >= 500) internalErrors++;
  }
  return matches;
}

function rawHttp(payload, timeoutMs = 1500) {
  return new Promise(resolve => {
    let settled = false;
    const chunks = [];
    let socketRef;
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socketRef?.end();
      } catch {}
      resolve(result);
    };

    const timer = setTimeout(() => finish({ timeout: true, text: "" }), timeoutMs);

    Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(socket) {
          socketRef = socket;
          socket.write(payload);
          socket.end();
        },
        data(_socket, data) {
          chunks.push(Buffer.from(data));
        },
        close() {
          finish({ text: Buffer.concat(chunks).toString("latin1") });
        },
        error(_socket, error) {
          socketErrors++;
          finish({ error: error?.message || String(error), text: Buffer.concat(chunks).toString("latin1") });
        },
      },
    }).catch(error => {
      socketErrors++;
      finish({ error: error?.message || String(error), text: "" });
    });
  });
}

function httpRequest({ method = "GET", path = "/", headers = [], body = new Uint8Array(), connection = "close" }) {
  return concat([
    `${method} ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: ${connection}\r\n`,
    headers.length ? `${headers.join("\r\n")}\r\n` : "",
    `Content-Length: ${body.byteLength}\r\n\r\n`,
    body,
  ]);
}

function simpleGet(path, extraHeaders = []) {
  return concat([
    `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n`,
    extraHeaders.length ? `${extraHeaders.join("\r\n")}\r\n` : "",
    "\r\n",
  ]);
}

function multipartBody(i) {
  const boundary = `----bunlab${i.toString(16)}${"x".repeat(i % 64)}`;
  const reportSize = [1, 31, 512, 4096, 8192, 8193, 12000][i % 7];
  const report = new Uint8Array(reportSize);
  report.fill((0x41 + i) & 0xff);
  if (i % 5 === 0 && report.length > 64) {
    report.set(bytes(`\r\n--${boundary}\r\n`), 16);
  }

  const filenameCases = [
    "report.txt",
    "../flag.txt",
    "nul\u0000x.txt",
    "x".repeat(512),
    `utf-${String.fromCharCode(0xd800)}.txt`,
  ];
  const contentTypeCases = [
    "application/octet-stream",
    "text/plain; charset=utf-8",
    "multipart/mixed",
    "application/json",
  ];

  const fields = [
    `--${boundary}\r\nContent-Disposition: form-data; name="package"\r\n\r\n${i % 9 === 0 ? "@types/bun" : "bun"}\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="report"; filename="${filenameCases[i % filenameCases.length]}"\r\nContent-Type: ${contentTypeCases[i % contentTypeCases.length]}\r\n\r\n`,
    report,
    `\r\n--${boundary}--\r\n`,
  ];

  if (i % 11 === 0) fields.splice(1, 0, `--${boundary}\r\nContent-Disposition: form-data; name="package"\r\n\r\nhono\r\n`);
  if (i % 13 === 0) fields.pop();

  const body = concat(fields);
  const contentType = i % 17 === 0
    ? "multipart/form-data"
    : `multipart/form-data; boundary=${boundary}`;
  return { body, contentType };
}

function ndjsonBody(i) {
  const count = 1 + (i % 20);
  const lines = [];
  for (let j = 0; j < count; j++) {
    if (j === 3 && i % 7 === 0) lines.push("{");
    else lines.push(JSON.stringify({ package: j % 2 === 0 ? "bun" : "@types/bun" }));
  }
  return bytes(`${lines.join(i % 5 === 0 ? "\r\n" : "\n")}\n`);
}

function wsAcceptKey(i) {
  const raw = new Uint8Array(16);
  for (let j = 0; j < raw.length; j++) raw[j] = (i * 31 + j * 17) & 0xff;
  return Buffer.from(raw).toString("base64");
}

function wsFrame({ opcode = 1, payload = new Uint8Array(), fin = true, masked = true, declaredLength = payload.byteLength, maskSeed = 0x11223344 }) {
  let lenBytes;
  if (declaredLength < 126) {
    lenBytes = [declaredLength];
  } else if (declaredLength <= 0xffff) {
    lenBytes = [126, (declaredLength >>> 8) & 0xff, declaredLength & 0xff];
  } else {
    const n = BigInt(declaredLength);
    lenBytes = [127];
    for (let shift = 56n; shift >= 0n; shift -= 8n) lenBytes.push(Number((n >> shift) & 0xffn));
  }

  lenBytes[0] |= masked ? 0x80 : 0;
  const header = [fin ? 0x80 | opcode : opcode, ...lenBytes];
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

function wsPayloadCase(i) {
  const valid = bytes(JSON.stringify({ action: "audit", package: "bun" }));
  switch (i % 12) {
    case 0:
      return [wsFrame({ opcode: 1, payload: valid, maskSeed: i })];
    case 1:
      return [wsFrame({ opcode: 2, payload: valid, maskSeed: i })];
    case 2:
      return [wsFrame({ opcode: 2, payload: new Uint8Array([0xff, 0xfe, 0xfa]), maskSeed: i })];
    case 3:
      return [wsFrame({ opcode: 1, payload: bytes("x".repeat(513)), maskSeed: i })];
    case 4:
      return Array.from({ length: 34 }, (_, j) => wsFrame({ opcode: 1, payload: valid, maskSeed: i + j }));
    case 5: {
      const first = wsFrame({ opcode: 1, payload: valid.subarray(0, 8), fin: false, maskSeed: i });
      const second = wsFrame({ opcode: 0, payload: valid.subarray(8), fin: true, maskSeed: i + 1 });
      return [first, second];
    }
    case 6:
      return [wsFrame({ opcode: 9, payload: bytes("p".repeat(126)), maskSeed: i })];
    case 7:
      return [wsFrame({ opcode: 1, payload: valid, masked: false })];
    case 8:
      return [wsFrame({ opcode: 1, payload: valid.subarray(0, 4), declaredLength: valid.byteLength + 32, maskSeed: i })];
    case 9:
      return [wsFrame({ opcode: 8, payload: bytes("bye"), maskSeed: i })];
    case 10:
      return [wsFrame({ opcode: 1, payload: bytes("{"), maskSeed: i })];
    default:
      return [wsFrame({ opcode: 1, payload: bytes(JSON.stringify({ action: "audit", package: "BUN" })), maskSeed: i })];
  }
}

async function rawWebSocket(i) {
  return new Promise(resolve => {
    let settled = false;
    let socketRef;
    const chunks = [];
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socketRef?.end();
      } catch {}
      resolve(result);
    };

    const timer = setTimeout(() => finish({ timeout: true }), 1500);

    Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(socket) {
          socketRef = socket;
          const ext = i % 3 === 0 ? "Sec-WebSocket-Extensions: permessage-deflate\r\n" : "";
          socket.write(bytes(
            `GET /ws HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${port}\r\n` +
            `Upgrade: websocket\r\n` +
            `Connection: Upgrade\r\n` +
            `Sec-WebSocket-Key: ${wsAcceptKey(i)}\r\n` +
            `Sec-WebSocket-Version: 13\r\n` +
            ext +
            `\r\n`
          ));
        },
        data(socket, data) {
          chunks.push(Buffer.from(data));
          const text = Buffer.concat(chunks).toString("latin1");
          if (text.includes("\r\n\r\n")) {
            if (text.startsWith("HTTP/1.1 101")) {
              wsUpgrades++;
              for (const frame of wsPayloadCase(i)) socket.write(frame);
              setTimeout(() => finish({ text: Buffer.concat(chunks).toString("latin1") }), 20);
            } else {
              finish({ text });
            }
          }
        },
        close() {
          finish({ text: Buffer.concat(chunks).toString("latin1") });
        },
        error(_socket, error) {
          wsErrors++;
          finish({ error: error?.message || String(error), text: Buffer.concat(chunks).toString("latin1") });
        },
      },
    }).catch(error => {
      wsErrors++;
      finish({ error: error?.message || String(error), text: "" });
    });
  });
}

async function waitForServer() {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (childExited) throw new Error("challenge child exited before becoming ready");
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for challenge server");
}

function startChallenge() {
  child = spawn(process.execPath, [challenge], {
    env: {
      ...process.env,
      PORT: String(port),
      FLAG: "SCTF{local_real_service_probe}",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", chunk => process.stdout.write(`[challenge:stdout] ${chunk}`));
  child.stderr.on("data", chunk => process.stderr.write(`[challenge:stderr] ${chunk}`));
  child.on("exit", (code, signal) => {
    childExited = true;
    process.stderr.write(`[challenge] exited code=${code} signal=${signal}\n`);
  });
}

async function runCase(i) {
  const mode = i % 10;
  let result;

  if (mode === 0) {
    result = await rawHttp(simpleGet("/"));
  } else if (mode === 1) {
    const range = ["bytes=0-15", "bytes=0-", "bytes=-32", "bytes=999999999999-", "bytes=0-1,2-3"][i % 5];
    result = await rawHttp(simpleGet(i % 2 ? "/assets/app.js" : "/assets/app.css", [`Range: ${range}`]));
  } else if (mode === 2) {
    result = await rawHttp(simpleGet(`/api/packages?q=${encodeURIComponent("bun ".repeat(i % 20))}&limit=${i % 100}`));
  } else if (mode === 3) {
    const names = ["bun", "%40types%2Fbun", "%ff", "..%2fflag.txt", "%e0%80%af", "hono"];
    result = await rawHttp(simpleGet(`/api/packages/${names[i % names.length]}`));
  } else if (mode === 4) {
    const body = bytes(JSON.stringify({ username: "auditor", password: "password123" }));
    result = await rawHttp(httpRequest({
      method: "POST",
      path: "/api/session",
      headers: ["Content-Type: application/json"],
      body,
    }));
  } else if (mode === 5) {
    const body = ndjsonBody(i);
    result = await rawHttp(httpRequest({
      method: "POST",
      path: "/api/audit/bulk",
      headers: ["Content-Type: application/x-ndjson"],
      body,
    }));
  } else if (mode === 6) {
    const { body, contentType } = multipartBody(i);
    result = await rawHttp(httpRequest({
      method: "POST",
      path: "/api/reports",
      headers: [`Content-Type: ${contentType}`],
      body,
    }), 2500);
  } else if (mode === 7) {
    result = await rawHttp(simpleGet("/api/events"), 2500);
  } else if (mode === 8) {
    result = await rawWebSocket(i);
  } else {
    const body = bytes(JSON.stringify({ package: i % 2 ? "@types/bun" : "bun", includeMetadata: i % 4 === 0 }));
    result = await rawHttp(httpRequest({
      method: "POST",
      path: "/api/audit",
      headers: ["Content-Type: application/json"],
      body,
    }));
  }

  if (result?.text) recordStatuses(result.text);
  if (result?.error && i % 10 !== 8) socketErrors++;
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[real-service-surface-mutator] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    await runCase(i);
    if (childExited) throw new Error("challenge child exited during run");
    if (i % 100 === 0) {
      console.error(`[real-service-surface-mutator] iteration=${i} internalErrors=${internalErrors} socketErrors=${socketErrors} wsUpgrades=${wsUpgrades} wsErrors=${wsErrors}`);
    }
  }

  console.log(JSON.stringify({
    harness: "real-service-surface-mutator",
    iterations,
    port,
    internalErrors,
    socketErrors,
    wsUpgrades,
    wsErrors,
    statuses: Object.fromEntries([...statusCounts.entries()].sort()),
  }));
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
}

process.exitCode = internalErrors > 0 ? 86 : 0;
