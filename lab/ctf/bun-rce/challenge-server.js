import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const port = Number(process.env.PORT || 31337);
const here = fileURLToPath(new URL(".", import.meta.url));
const flagPath = fileURLToPath(new URL("./flag.txt", import.meta.url));

if (process.env.FLAG) {
  writeFileSync(flagPath, `${process.env.FLAG}\n`, { mode: 0o600 });
}

if (!existsSync(flagPath)) {
  throw new Error("missing flag.txt");
}

function json(data, status = 200) {
  return Response.json(data, { status });
}

async function parseJson(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

function runAudit(target) {
  if (typeof target !== "string") {
    return { status: 400, body: { ok: false, error: "package must be a string" } };
  }

  const name = target.trim();
  if (name.length === 0 || name.length > 96 || /[\0\r\n]/.test(name)) {
    return { status: 400, body: { ok: false, error: "invalid package name" } };
  }

  const command = `test -d node_modules/${name} && printf 'cache: hit\\n' || printf 'cache: miss\\n'`;
  const child = spawnSync("/bin/sh", ["-c", command], {
    cwd: here,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
    timeout: 1500,
    maxBuffer: 4096,
  });

  return {
    status: 200,
    body: {
      ok: true,
      status: child.status,
      signal: child.signal,
      stdout: child.stdout || "",
      stderr: child.stderr || "",
      timedOut: child.error?.code === "ETIMEDOUT",
    },
  };
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      return json({
        name: "bun-rce-ctf",
        objective: "Get code execution on the server and read the flag.",
        endpoints: ["POST /api/audit"],
      });
    }

    if (url.pathname === "/api/audit") {
      if (req.method !== "POST") {
        return json({ ok: false, error: "method not allowed" }, 405);
      }

      const body = await parseJson(req);
      if (!body) return json({ ok: false, error: "invalid json" }, 400);

      const result = runAudit(body.package ?? body.packageName);
      return json(result.body, result.status);
    }

    return json({ ok: false, error: "not found" }, 404);
  },
});

console.log(`bun-rce-ctf listening on http://${server.hostname}:${server.port}`);
