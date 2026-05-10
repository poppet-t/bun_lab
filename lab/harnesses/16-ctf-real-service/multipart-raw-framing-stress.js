import { spawn } from "node:child_process";
import { connect } from "node:net";
import { fileURLToPath } from "node:url";

const iterations = Number(process.env.ITERATIONS || 220);
const port = Number(process.env.PORT || (45000 + (process.pid % 10000)));
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

function recordResponse(text) {
  const match = /^HTTP\/1\.1\s+(\d+)/.exec(text);
  const status = match ? match[1] : "no-status";
  statuses.set(status, (statuses.get(status) || 0) + 1);
  if (Number(status) >= 500) internalErrors++;
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

async function rawExchange(payload, { end = false, delayTail } = {}) {
  return new Promise(resolve => {
    let settled = false;
    const chunks = [];

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
    }, 2500);

    const socket = connect({ host: "127.0.0.1", port }, () => {
      if (delayTail) {
        socket.write(payload.subarray(0, delayTail.at));
        setTimeout(() => {
          if (settled) return;
          socket.write(payload.subarray(delayTail.at));
          if (end) socket.end();
        }, delayTail.ms);
        return;
      }
      socket.write(payload);
      if (end) socket.end();
    });

    socket.on("data", data => chunks.push(Buffer.from(data)));
    socket.on("close", () => finish({ text: Buffer.concat(chunks).toString("latin1") }));
    socket.on("error", error => {
      socketErrors++;
      finish({ error: error?.message || String(error), text: "" });
    });
  });
}

function makeMultipart(i) {
  const boundary = `----bunlabraw${i.toString(16)}${"r".repeat(i % 80)}`;
  const size = [1, 32, 511, 512, 4096, 8191, 8192, 8193][i % 8];
  const report = new Uint8Array(size);
  report.fill((0x41 + i) & 0xff);
  if (report.byteLength > 96 && i % 4 === 0) {
    report.set(bytes(`\r\n--${boundary}\r\nContent-Disposition: form-data; name="report"; filename="inner"\r\n\r\n`), 24);
  }

  const filename = [
    "report.txt",
    "../flag.txt",
    "quote\"x.txt",
    "semi;colon.txt",
    "x".repeat(768),
    "nul\u0000x.txt",
  ][i % 6];

  const body = concat([
    `--${boundary}\r\nContent-Disposition: form-data; name="package"\r\n\r\n${i % 9 === 0 ? "@types/bun" : "bun"}\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="report"; filename="${filename}"\r\n`,
    `Content-Type: ${i % 5 === 0 ? "multipart/mixed" : "application/octet-stream"}\r\n`,
    i % 7 === 0 ? `X-Long: ${"A".repeat(2048)}\r\n` : "",
    "\r\n",
    report,
    i % 11 === 0 ? "" : `\r\n--${boundary}--\r\n`,
  ]);

  return { body, boundary };
}

function requestForCase(i) {
  const { body, boundary } = makeMultipart(i);
  const host = `Host: 127.0.0.1:${port}\r\n`;
  const base = [
    "POST /api/reports HTTP/1.1\r\n",
    host,
    "Connection: close\r\n",
  ];
  const type = `multipart/form-data; boundary=${boundary}`;

  switch (i % 18) {
    case 0:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 1:
      return { payload: concat([...base, "Content-Type: multipart/form-data\r\n", `Content-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 2:
      return { payload: concat([...base, `Content-Type: multipart/form-data; boundary=${boundary}x\r\n`, `Content-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 3:
      return { payload: concat([...base, `Content-Type: "${type}"\r\n`, `Content-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 4:
      return { payload: concat([...base, `Content-Type: ${type}; charset=utf-8; boundary=ignored\r\n`, `Content-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 5:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${Math.max(1, body.byteLength - 17)}\r\n\r\n`, body]) };
    case 6:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength + 97}\r\n\r\n`, body]), end: true };
    case 7:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\nContent-Length: ${Math.max(1, body.byteLength - 1)}\r\n\r\n`, body]) };
    case 8:
      return { payload: concat([...base, `Transfer-Encoding: chunked\r\nContent-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 9: {
      const chunked = concat([
        `${body.byteLength.toString(16)}\r\n`,
        body,
        "\r\n0\r\n\r\n",
      ]);
      return { payload: concat([...base, `Transfer-Encoding: chunked\r\nContent-Type: ${type}\r\n\r\n`, chunked]) };
    }
    case 10:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: 0\r\n\r\n`, body]) };
    case 11:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${16_385}\r\n\r\n`, body]) };
    case 12: {
      const prefix = concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\n\r\n`, body]);
      return { payload: prefix, delayTail: { at: Math.max(1, prefix.byteLength - 23), ms: 50 } };
    }
    case 13:
      return { payload: concat([...base, `Content-Type: multipart/form-data; boundary=${"b".repeat(1024)}\r\n`, `Content-Length: ${body.byteLength}\r\n\r\n`, body]) };
    case 14:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: +${body.byteLength}\r\n\r\n`, body]) };
    case 15:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\nExpect: 100-continue\r\n\r\n`, body]) };
    case 16:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\n\r\n`, body, "GET /health HTTP/1.1\r\n", host, "Connection: close\r\n\r\n"]) };
    default:
      return { payload: concat([...base, `Content-Type: ${type}\r\nContent-Length: ${body.byteLength}\r\n\r\n`, body.subarray(0, Math.max(1, body.byteLength - 9))]), end: true };
  }
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[multipart-raw-framing-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    const request = requestForCase(i);
    const result = await rawExchange(request.payload, request);
    recordResponse(result.text || "");
    if (childExited) throw new Error("challenge child exited during multipart raw framing stress");
    if (i % 50 === 0) {
      console.error(`[multipart-raw-framing-stress] iteration=${i} internalErrors=${internalErrors} socketErrors=${socketErrors} timeouts=${timeouts}`);
    }
  }

  console.log(JSON.stringify({
    harness: "multipart-raw-framing-stress",
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
