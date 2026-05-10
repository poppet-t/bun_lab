import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const iterations = Number(process.env.ITERATIONS || 2000);
const port = Number(process.env.PORT || (45000 + (process.pid % 10000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));

let child;
let childExited = false;
let fetchErrors = 0;
let internalErrors = 0;
const statuses = new Map();

function record(status) {
  statuses.set(String(status), (statuses.get(String(status)) || 0) + 1);
  if (status >= 500) internalErrors++;
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

function requestCase(i) {
  const paths = [
    "/assets/app.css",
    "/assets/app.js",
    "/assets/app.css?cache=bust",
    "/assets/app.js#frag",
    "/assets/%61pp.css",
    "/assets/app.css/..%2fflag.txt",
  ];
  const methods = ["GET", "HEAD", "POST", "PUT"];
  const ranges = [
    undefined,
    "bytes=0-0",
    "bytes=0-15",
    "bytes=15-0",
    "bytes=-1",
    "bytes=-999999",
    "bytes=999999999999-",
    "bytes=0-1,2-3",
    "bytes=0-18446744073709551615",
    "items=0-1",
    "bytes=abc-def",
  ];
  const headers = {};
  const range = ranges[i % ranges.length];
  if (range) headers.range = range;
  if (i % 7 === 0) headers["if-none-match"] = `"${"A".repeat(i % 4096)}"`;
  if (i % 11 === 0) headers["if-range"] = `"${"B".repeat(i % 2048)}"`;
  if (i % 13 === 0) headers["accept-encoding"] = "gzip, br, zstd";
  if (i % 17 === 0) headers["x-fill"] = "C".repeat(8192);

  return {
    path: paths[i % paths.length],
    method: methods[i % methods.length],
    headers,
    body: i % 4 >= 2 ? "body".repeat(i % 1024) : undefined,
  };
}

async function runOne(i) {
  const c = requestCase(i);
  try {
    const response = await fetch(`http://127.0.0.1:${port}${c.path}`, {
      method: c.method,
      headers: c.headers,
      body: c.method === "GET" || c.method === "HEAD" ? undefined : c.body,
    });
    record(response.status);
    await response.arrayBuffer();
  } catch (error) {
    fetchErrors++;
    console.error(`[static-bunfile-range-stress] fetch error i=${i} ${error?.message || error}`);
  }
}

try {
  startChallenge();
  await waitForServer();
  console.error(`[static-bunfile-range-stress] started port=${port} iterations=${iterations}`);

  for (let i = 0; i < iterations; i++) {
    await runOne(i);
    if (childExited) throw new Error("challenge child exited during static stress");
    if (i % 250 === 0) console.error(`[static-bunfile-range-stress] iteration=${i} internalErrors=${internalErrors} fetchErrors=${fetchErrors}`);
  }

  console.log(JSON.stringify({
    harness: "static-bunfile-range-stress",
    iterations,
    internalErrors,
    fetchErrors,
    statuses: Object.fromEntries([...statuses.entries()].sort()),
  }));
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
}

process.exitCode = internalErrors > 0 ? 86 : 0;
