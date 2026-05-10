import { spawn } from "node:child_process";
import { existsSync, lstatSync, readlinkSync, renameSync, symlinkSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const port = Number(process.env.PORT || (20000 + Math.floor(Math.random() * 40000)));
const challenge = fileURLToPath(new URL("../../ctf/bun-rce/challenge-server.js", import.meta.url));
const here = fileURLToPath(new URL("../../ctf/bun-rce/", import.meta.url));
const assetPath = join(here, "public", "app.js");
const backupPath = join(dirname(assetPath), `.app.js.codex-backup-${process.pid}`);
const symlinkTarget = "../flag.txt";
const printFlag = process.env.PRINT_FLAG === "1";

let child;
let childExited = false;
let hadOriginal = false;

function restoreAsset() {
  try {
    if (existsSync(assetPath) || lstatSync(assetPath, { throwIfNoEntry: false })) {
      unlinkSync(assetPath);
    }
  } catch {}

  if (hadOriginal && existsSync(backupPath)) {
    renameSync(backupPath, assetPath);
  }
}

function installSymlink() {
  const original = lstatSync(assetPath, { throwIfNoEntry: false });
  hadOriginal = Boolean(original);
  if (hadOriginal) renameSync(assetPath, backupPath);
  symlinkSync(symlinkTarget, assetPath);
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

try {
  installSymlink();
  const installed = lstatSync(assetPath);
  if (!installed.isSymbolicLink() || readlinkSync(assetPath) !== symlinkTarget) {
    throw new Error("failed to install expected symlink");
  }

  startChallenge();
  await waitForServer();

  const response = await fetch(`http://127.0.0.1:${port}/assets/app.js?local-static-symlink-solve=${Date.now()}`);
  const text = await response.text();
  const flag = text.match(/[A-Z0-9_]*CTF\{[^}\r\n]+\}/)?.[0] || "";

  console.log(JSON.stringify({
    harness: "local-static-symlink-solve",
    mode: "local-filesystem-write",
    status: response.status,
    contentType: response.headers.get("content-type"),
    symlinkTarget,
    flagFound: flag.length > 0,
    flag: printFlag ? flag : flag.replace(/\{[^}]*\}/, "{redacted}"),
  }));

  process.exitCode = response.ok && flag ? 86 : 1;
} finally {
  if (child && !childExited) {
    child.kill("SIGTERM");
    await new Promise(resolve => setTimeout(resolve, 100));
    if (!childExited) child.kill("SIGKILL");
  }
  restoreAsset();
}
