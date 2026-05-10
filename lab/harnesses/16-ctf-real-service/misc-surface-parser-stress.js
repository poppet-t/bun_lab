import { spawn } from "node:child_process";
import { connect } from "node:net";
import { fileURLToPath } from "node:url";

const iterations = Number(process.env.ITERATIONS || 220);
const port = Number(process.env.PORT || (48000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const enc = new TextEncoder();

let child;
let childExited = false;
let socketErrors = 0;
let timeouts = 0;
let wsUpgrades = 0;
let internalErrors = 0;
const statuses = new Map();

function bytes(text) {
  return enc.encode(text);
}

function concat(parts) {
  let total = 0;
  for (const part of parts) total += typeof part === "string" ? bytes(part).byteLength : part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    const chunk = typeof part === "string" ? bytes(part) : part;
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function recordResponses(text) {
  const matches = [...text.matchAll(/HTTP\/1\.1\s+(\d+)/g)];
  if (matches.length === 0) {
    statuses.set("no-status", (statuses.get("no-status") || 0) + 1);
    return;
  }
  for (const match of matches) {
    const status = match[1];
    statuses.set(status, (statuses.get(status) || 0) + 1);
    if (Number(status) >= 500) internalErrors++;
  }
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

async function rawSocket(actions, timeoutMs = 1400) {
  return new Promise(resolve => {
    let settled = false;
    const chunks = [];
    const socket = connect({ host: "127.0.0.1", port });
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => {
      timeouts++;
      finish({ timeout: true, text: Buffer.concat(chunks).toString("latin1") });
    }, timeoutMs);

    socket.on("connect", () => {
      let delay = 0;
      for (const action of actions) {
        delay += action.delay || 0;
        setTimeout(() => {
          if (settled) return;
          if (action.write) socket.write(action.write);
          if (action.end) socket.end();
          if (action.destroy) socket.destroy();
        }, delay);
      }
    });
    socket.on("data", data => chunks.push(Buffer.from(data)));
    socket.on("close", () => finish({ text: Buffer.concat(chunks).toString("latin1") }));
    socket.on("error", error => {
      socketErrors++;
      finish({ error: error?.message || String(error), text: Buffer.concat(chunks).toString("latin1") });
    });
  });
}

function rawRequest({ method = "GET", target = "/", headers = [], body = new Uint8Array(), close = true }) {
  return concat([
    `${method} ${target} HTTP/1.1\r\n`,
    `Host: 127.0.0.1:${port}\r\n`,
    `Connection: ${close ? "close" : "keep-alive"}\r\n`,
    headers.length ? `${headers.join("\r\n")}\r\n` : "",
    body.byteLength ? `Content-Length: ${body.byteLength}\r\n\r\n` : "\r\n",
    body,
  ]);
}

function wsKey(i) {
  const raw = new Uint8Array(16);
  for (let j = 0; j < raw.length; j++) raw[j] = (i * 97 + j * 23) & 0xff;
  return Buffer.from(raw).toString("base64");
}

function wsFrame(payload, { opcode = 1, maskSeed = 0x12345678 } = {}) {
  const header = [0x80 | opcode];
  if (payload.byteLength < 126) {
    header.push(0x80 | payload.byteLength);
  } else {
    header.push(0x80 | 126, (payload.byteLength >>> 8) & 0xff, payload.byteLength & 0xff);
  }
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

function wsCase(i) {
  const valid = bytes(JSON.stringify({ action: "audit", package: "bun" }));
  const payloads = [
    new Uint8Array([0xef, 0xbb, 0xbf, ...valid]),
    bytes(JSON.stringify({ action: "audit", package: "bun", "__proto__": { polluted: true } })),
    bytes('{"action":"audit","package":"bun","package":"@types/bun"}'),
    bytes('{"action":"audit","package":"bun","nested":'.repeat(64)),
    new Uint8Array([0xf0, 0x9f, 0x92]),
    bytes('{"action":"audit","package":"bun\\ud800"}'),
  ];
  const frame = wsFrame(payloads[i % payloads.length], { opcode: i % 3 === 0 ? 2 : 1, maskSeed: i });
  return [
    {
      write: bytes(
        `GET /ws HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${port}\r\n` +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Key: ${wsKey(i)}\r\n` +
          "Sec-WebSocket-Version: 13\r\n\r\n",
      ),
    },
    { write: frame, delay: 20 },
    { end: true, delay: 20 },
  ];
}

function caseActions(i) {
  const target = i % 2 ? "/assets/app.js" : "/assets/app.css";
  const assetBody = bytes("ignored-body");
  const validAudit = bytes(JSON.stringify({ package: "bun", includeMetadata: true }));
  const weirdJson = [
    '{"package":"bun","includeMetadata":true,"__proto__":{"polluted":true}}',
    '{"package":"bun","package":"@types/bun"}',
    '{"package":"bun\\ud800"}',
    '{"package":"bun","includeMetadata":false}\r',
  ][i % 4];

  switch (i % 24) {
    case 0:
      return [{ write: rawRequest({ target: `http://example.invalid:${port}/api/packages/bun?limit=1`, close: true }) }];
    case 1:
      return [{ write: rawRequest({ target: `/api/packages/${"%2e%2e%2fflag.txt"}`, close: true }) }];
    case 2:
      return [{ write: rawRequest({ target: `/api/packages/${"%252e%252e%252fflag.txt"}`, close: true }) }];
    case 3:
      return [{ write: rawRequest({ target: `/api/packages/${"%".repeat(80)}`, close: true }) }];
    case 4:
      return [{ write: rawRequest({ target: `/api/packages/${"%e0%80%af".repeat(28)}`, close: true }) }];
    case 5:
      return [{ write: rawRequest({ target: `/api/packages?q=${encodeURIComponent("bun @types/bun ".repeat(8))}&limit=-999&limit=1`, close: true }) }];
    case 6:
      return [{ write: rawRequest({ target: "/api/me", headers: [`Cookie: ${"sid=x; ".repeat(2048)}`], close: true }) }];
    case 7:
      return [{ write: rawRequest({ target: "/api/me", headers: ["Cookie: sid=not-valid", "Cookie: sid=00000000-0000-4000-8000-000000000000"], close: true }) }];
    case 8:
      return [{ write: bytes(`GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\nCookie: sid=x;\r\n\t sid=00000000-0000-4000-8000-000000000000\r\n\r\n`) }];
    case 9:
      return [{ write: rawRequest({ method: "HEAD", target, headers: ["Range: bytes=0-3"], close: true }) }];
    case 10:
      return [{ write: rawRequest({ method: "POST", target, headers: ["Range: bytes=0-3", "Content-Type: application/octet-stream"], body: assetBody, close: true }) }];
    case 11:
      return [{ write: rawRequest({ method: "PUT", target, headers: ["Range: bytes=-0"], body: assetBody, close: true }) }];
    case 12:
      return [{ write: rawRequest({ target, headers: ["Range: bytes = 0 - 1"], close: true }) }];
    case 13:
      return [{ write: rawRequest({ target, headers: ["Range: bytes=999999999999999999999999-"], close: true }) }];
    case 14:
      return [{ write: rawRequest({ target, headers: ["If-None-Match: \"not-real\"", "Range: bytes=0-0"], close: true }) }];
    case 15:
      return [{ write: rawRequest({ target, headers: ["If-Range: \"not-real\"", "Range: bytes=0-0"], close: true }) }];
    case 16:
      return [{ write: rawRequest({ target: "/api/events", close: true }), destroy: true, delay: 2 }];
    case 17:
      return [{ write: rawRequest({ target: "/api/events", close: false }) }, { write: rawRequest({ target: "/health", close: true }), delay: 15 }];
    case 18:
      return [{ write: rawRequest({ method: "HEAD", target: "/api/events", close: true }) }];
    case 19:
      return [{ write: rawRequest({ method: "POST", target: "/api/audit", headers: ["Content-Type: application/json"], body: bytes(weirdJson), close: true }) }];
    case 20:
      return [{ write: rawRequest({ method: "POST", target: "/api/audit", headers: ["content-type: application/json", "Content-Type: text/plain"], body: validAudit, close: true }) }];
    case 21:
      return [{ write: rawRequest({ method: "POST", target: "/api/audit/bulk", headers: ["Content-Type: application/x-ndjson"], body: bytes('{"package":"bun"}\r{"package":"hono"}\r'), close: true }) }];
    case 22:
      return wsCase(i);
    default:
      return [{ write: rawRequest({ target: `/${"A".repeat(12_000)}`, close: true }) }];
  }
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[misc-surface-parser-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    const actions = caseActions(i);
    const result = await rawSocket(actions, i % 24 === 17 ? 2400 : 1400);
    const text = result.text || "";
    if (text.startsWith("HTTP/1.1 101")) wsUpgrades++;
    recordResponses(text);
    if (childExited) throw new Error("challenge child exited during misc surface stress");
    if (i % 50 === 0) {
      console.error(`[misc-surface-parser-stress] iteration=${i} internalErrors=${internalErrors} socketErrors=${socketErrors} timeouts=${timeouts} wsUpgrades=${wsUpgrades}`);
    }
  }

  console.log(JSON.stringify({
    harness: "misc-surface-parser-stress",
    iterations,
    internalErrors,
    socketErrors,
    timeouts,
    wsUpgrades,
    statuses: Object.fromEntries([...statuses.entries()].sort()),
  }));
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
}

process.exitCode = 0;
