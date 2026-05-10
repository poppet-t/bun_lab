import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const iterations = Number(process.env.ITERATIONS || 220);
const port = Number(process.env.PORT || (44000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const enc = new TextEncoder();

let child;
let childExited = false;
let fetchErrors = 0;
let internalErrors = 0;
let unexpectedOk = 0;
const statuses = new Map();

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

function record(status) {
  statuses.set(String(status), (statuses.get(String(status)) || 0) + 1);
  if (status >= 500) internalErrors++;
}

function makeMultipart(i) {
  const boundary = `----bunlab-report-${i.toString(16)}${"b".repeat(i % 48)}`;
  const packageName = ["bun", "@types/bun", "typescript", "hono", "BUN", "../flag.txt"][i % 6];
  const reportSize = [0, 1, 64, 511, 512, 4096, 8192, 8193, 12000][i % 9];
  const report = new Uint8Array(reportSize);
  report.fill((0x30 + i) & 0xff);

  if (report.length > 128 && i % 4 === 0) {
    report.set(bytes(`\r\n--${boundary}\r\nContent-Disposition: form-data; name="x"\r\n\r\nsplit\r\n`), 32);
  }

  const filename = [
    "report.txt",
    "../flag.txt",
    "..%2fflag.txt",
    "x".repeat(300),
    `utf-${String.fromCharCode(0xd800)}.txt`,
    "semi;colon.txt",
    "quote\"x.txt",
  ][i % 7];

  const reportHeaders = [
    `Content-Disposition: form-data; name="report"; filename="${filename}"`,
    `Content-Type: ${["application/octet-stream", "text/plain", "application/json", "multipart/mixed"][i % 4]}`,
  ];

  if (i % 10 === 0) reportHeaders.push("Content-Transfer-Encoding: binary");
  if (i % 14 === 0) reportHeaders.push(`X-Fill: ${"A".repeat(1024)}`);

  const parts = [
    `--${boundary}\r\nContent-Disposition: form-data; name="package"\r\n\r\n${packageName}\r\n`,
  ];

  if (i % 11 === 0) {
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="package"\r\n\r\nbun\r\n`);
  }

  if (i % 13 !== 0) {
    parts.push(`--${boundary}\r\n${reportHeaders.join("\r\n")}\r\n\r\n`);
    parts.push(report);
    parts.push("\r\n");
  }

  if (i % 17 !== 0) parts.push(`--${boundary}--\r\n`);
  else parts.push(`--${boundary}\r\n`);

  const body = concat(parts);
  const contentType = i % 19 === 0
    ? "multipart/form-data"
    : `multipart/form-data; boundary=${boundary}`;
  return { body, contentType, reportSize, packageName };
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

async function runOne(i) {
  const { body, contentType, reportSize, packageName } = makeMultipart(i);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/reports`, {
      method: "POST",
      headers: {
        "content-type": contentType,
        "x-probe": String(i),
      },
      body,
    });
    record(response.status);
    const text = await response.text();
    if (response.ok && (reportSize === 0 || reportSize > 8192 || packageName !== packageName.toLowerCase())) {
      unexpectedOk++;
      console.error(`[multipart-report-stress] unexpected ok i=${i} status=${response.status} body=${text.slice(0, 160)}`);
    }
  } catch (error) {
    fetchErrors++;
    console.error(`[multipart-report-stress] fetch error i=${i} ${error?.message || error}`);
  }
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[multipart-report-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    await runOne(i);
    if (childExited) throw new Error("challenge child exited during multipart stress");
    if (i % 50 === 0) console.error(`[multipart-report-stress] iteration=${i} internalErrors=${internalErrors} fetchErrors=${fetchErrors}`);
  }

  console.log(JSON.stringify({
    harness: "multipart-report-stress",
    iterations,
    internalErrors,
    fetchErrors,
    unexpectedOk,
    statuses: Object.fromEntries([...statuses.entries()].sort()),
  }));
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
}

process.exitCode = internalErrors > 0 || unexpectedOk > 0 ? 86 : 0;
