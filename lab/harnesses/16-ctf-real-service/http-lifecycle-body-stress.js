import { spawn } from "node:child_process";
import { connect } from "node:net";
import { fileURLToPath } from "node:url";

const iterations = Number(process.env.ITERATIONS || 260);
const port = Number(process.env.PORT || (47000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const enc = new TextEncoder();

let child;
let childExited = false;
let socketErrors = 0;
let timeouts = 0;
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

async function rawExchange(actions, timeoutMs = 2600) {
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

function request({ method = "POST", path = "/api/audit", headers = [], body = new Uint8Array(), close = false }) {
  return concat([
    `${method} ${path} HTTP/1.1\r\n`,
    `Host: 127.0.0.1:${port}\r\n`,
    `Connection: ${close ? "close" : "keep-alive"}\r\n`,
    headers.length ? `${headers.join("\r\n")}\r\n` : "",
    `Content-Length: ${body.byteLength}\r\n\r\n`,
    body,
  ]);
}

function chunked({ path = "/api/audit", contentType = "application/json", chunks = [], trailer = "0\r\n\r\n", close = false }) {
  return concat([
    `POST ${path} HTTP/1.1\r\n`,
    `Host: 127.0.0.1:${port}\r\n`,
    `Connection: ${close ? "close" : "keep-alive"}\r\n`,
    `Content-Type: ${contentType}\r\n`,
    "Transfer-Encoding: chunked\r\n\r\n",
    ...chunks.flatMap(chunk => [`${chunk.byteLength.toString(16)}\r\n`, chunk, "\r\n"]),
    trailer,
  ]);
}

function get(path = "/health", close = true) {
  return bytes(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: ${close ? "close" : "keep-alive"}\r\n\r\n`);
}

function validAuditBody(i) {
  return bytes(JSON.stringify({ package: i % 2 ? "@types/bun" : "bun", includeMetadata: (i & 4) === 0 }));
}

function ndjsonBody(lines, pad = "") {
  return bytes(`${Array.from({ length: lines }, (_, i) => JSON.stringify({ package: i % 2 ? "bun" : "@types/bun" })).join("\n")}\n${pad}`);
}

function caseActions(i) {
  const valid = validAuditBody(i);
  const hugeJson = bytes(JSON.stringify({ package: "bun", pad: "A".repeat(4096) }));
  const overLimitNdjson = ndjsonBody(32, "B".repeat(2048));
  const malformedUtf8 = new Uint8Array([0x7b, 0x22, 0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x22, 0x3a, 0xff, 0x7d]);
  const pipelinedGet = get("/health", true);

  switch (i % 22) {
    case 0:
      return [{ write: concat([request({ headers: ["Content-Type: application/json"], body: valid }), pipelinedGet]) }];
    case 1:
      return [{ write: concat([request({ headers: ["Content-Type: application/json"], body: hugeJson }), pipelinedGet]) }];
    case 2:
      return [{ write: concat([request({ path: "/api/audit/bulk", headers: ["Content-Type: application/x-ndjson"], body: overLimitNdjson }), pipelinedGet]) }];
    case 3:
      return [{ write: concat([request({ headers: ["Content-Type: application/json"], body: malformedUtf8 }), pipelinedGet]) }];
    case 4:
      return [{
        write: concat([
          `POST /api/audit HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: ${hugeJson.byteLength + 2048}\r\n\r\n`,
          hugeJson,
          pipelinedGet,
        ]),
      }];
    case 5:
      return [{
        write: concat([
          `POST /api/audit HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: ${Math.max(1, valid.byteLength - 2)}\r\n\r\n`,
          valid,
          pipelinedGet,
        ]),
      }];
    case 6:
      return [{ write: chunked({ chunks: [valid], close: false }) }, { write: pipelinedGet, delay: 20 }];
    case 7:
      return [{ write: chunked({ chunks: [hugeJson.subarray(0, 1500), hugeJson.subarray(1500)], close: false }) }, { write: pipelinedGet, delay: 20 }];
    case 8:
      return [{ write: chunked({ path: "/api/audit/bulk", contentType: "application/x-ndjson", chunks: [overLimitNdjson.subarray(0, 1024), overLimitNdjson.subarray(1024)], close: false }) }, { write: pipelinedGet, delay: 20 }];
    case 9:
      return [{
        write: concat([
          `POST /api/audit HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: ${valid.byteLength}\r\n\r\n`,
          `${valid.byteLength.toString(16)}\r\n`,
          valid,
          "\r\n0\r\n\r\n",
          pipelinedGet,
        ]),
      }];
    case 10:
      return [{
        write: concat([
          `POST /api/audit HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: ${valid.byteLength}\r\nContent-Length: ${valid.byteLength + 1}\r\n\r\n`,
          valid,
          pipelinedGet,
        ]),
      }];
    case 11:
      return [{ write: request({ headers: ["Content-Type: text/plain"], body: hugeJson }) }, { write: pipelinedGet, delay: 15 }];
    case 12:
      return [{ write: request({ method: "POST", path: "/api/session", headers: ["Content-Type: application/json"], body: bytes(JSON.stringify({ username: "auditor", password: "password123" })) }) }, { write: get("/api/me", true), delay: 10 }];
    case 13:
      return [{ write: get(`/api/packages/${"%".repeat(64)}`, false) }, { write: pipelinedGet, delay: 5 }];
    case 14:
      return [{ write: get(`/api/packages/${"%e0%80%af".repeat(32)}`, false) }, { write: pipelinedGet, delay: 5 }];
    case 15:
      return [{ write: bytes(`GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nCookie: ${"sid=x; ".repeat(2048)}\r\n\r\n`) }, { write: pipelinedGet, delay: 5 }];
    case 16:
      return [{ write: bytes(`GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`), destroy: true, delay: 2 }];
    case 17:
      return [{ write: bytes(`GET /assets/app.js HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nRange: bytes=0-1,2-3\r\n\r\n`) }, { write: pipelinedGet, delay: 5 }];
    case 18:
      return [{
        write: concat([
          `POST /api/audit HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: ${valid.byteLength}\r\nExpect: 100-continue\r\n\r\n`,
          valid,
          pipelinedGet,
        ]),
      }];
    case 19:
      return [{ write: chunked({ chunks: [valid.subarray(0, 4)], trailer: "", close: false }) }, { write: valid.subarray(4), delay: 30 }, { destroy: true, delay: 30 }];
    case 20:
      return [{ write: concat([request({ path: "/api/audit/bulk", headers: ["Content-Type: application/x-ndjson"], body: ndjsonBody(1) }), request({ headers: ["Content-Type: application/json"], body: valid }), pipelinedGet]) }];
    default:
      return [{ write: bytes(`GET /${"A".repeat(8192)} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`) }];
  }
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[http-lifecycle-body-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    const result = await rawExchange(caseActions(i), i % 22 === 4 || i % 22 === 19 ? 3200 : 1800);
    recordResponses(result.text || "");
    if (childExited) throw new Error("challenge child exited during HTTP lifecycle stress");
    if (i % 50 === 0) {
      console.error(`[http-lifecycle-body-stress] iteration=${i} internalErrors=${internalErrors} socketErrors=${socketErrors} timeouts=${timeouts}`);
    }
  }

  console.log(JSON.stringify({
    harness: "http-lifecycle-body-stress",
    iterations,
    internalErrors,
    socketErrors,
    timeouts,
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
