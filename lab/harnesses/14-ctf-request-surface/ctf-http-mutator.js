const iterations = Number(process.env.ITERATIONS || 5000);
const maxBodyBytes = 512;
const maxPackageNameBytes = 96;
const enc = new TextEncoder();

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function readLimitedText(req) {
  const contentLength = req.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) throw new HttpError(400, "invalid_content_length");
    if (Number(contentLength) > maxBodyBytes) throw new HttpError(413, "payload_too_large");
  }

  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBodyBytes) {
      await reader.cancel().catch(() => {});
      throw new HttpError(413, "payload_too_large");
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new HttpError(400, "invalid_utf8");
  }
}

async function parseJson(req) {
  const contentType = req.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "unsupported_media_type");

  const text = await readLimitedText(req);
  if (text.length === 0) throw new HttpError(400, "empty_body");

  try {
    const body = JSON.parse(text);
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "invalid_json_schema");

    const keys = Object.keys(body);
    if (keys.length !== 1 || keys[0] !== "package") throw new HttpError(400, "invalid_json_schema");

    return body;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "invalid_json");
  }
}

function normalizePackageName(target) {
  if (typeof target !== "string") throw new HttpError(400, "invalid_package_name");
  if (target !== target.trim()) throw new HttpError(400, "invalid_package_name");

  const name = target.toLowerCase();
  if (name !== target || name.length === 0 || name.length > maxPackageNameBytes) throw new HttpError(400, "invalid_package_name");

  const unscoped = /^[a-z0-9](?:[a-z0-9._-]{0,94}[a-z0-9])?$/;
  const scoped = /^@[a-z0-9](?:[a-z0-9._-]{0,46}[a-z0-9])?\/[a-z0-9](?:[a-z0-9._-]{0,46}[a-z0-9])?$/;
  if (!unscoped.test(name) && !scoped.test(name)) throw new HttpError(400, "invalid_package_name");

  return name;
}

function runAudit(target) {
  const name = normalizePackageName(target);
  return { ok: true, package: name, cache: name === "bun" ? "hit" : "miss" };
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  idleTimeout: 5,
  async fetch(req, server) {
    server.timeout(req, 3);
    const url = new URL(req.url);
    if (url.pathname !== "/api/audit") return json({ ok: false, error: "not found" }, 404);
    if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    try {
      const body = await parseJson(req);
      return json(runAudit(body.package));
    } catch (error) {
      if (error instanceof HttpError) return json({ ok: false, error: error.code }, error.status);
      throw error;
    }
  },
});

function u32(seed) {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return seed >>> 0;
}

function requestBytes(i) {
  const valid = JSON.stringify({ package: "bun" });
  const bodyCases = [
    valid,
    "",
    "{",
    "[]",
    JSON.stringify({ package: "BUN" }),
    JSON.stringify({ package: "@scope/name" }),
    JSON.stringify({ package: "a".repeat(97) }),
    JSON.stringify({ package: "bun", extra: 1 }),
    `{"package":"${"a".repeat(i % 140)}"}`,
    `{"package":"bun${String.fromCharCode(0xd800)}"}`,
  ];

  let body = enc.encode(bodyCases[i % bodyCases.length]);
  let seed = u32(i + 0x9e3779b9);
  if (i % 11 === 0) body = new Uint8Array([...body, 0xff, 0xfe, 0xfa]);
  if (i % 13 === 0 && body.length) body[seed % body.length] ^= 0xff;

  const contentLength = [body.length, body.length + 1, Math.max(0, body.length - 1), 513, 0, "0001", " 1", "1x"][i % 8];
  const headerCase = i % 9;

  if (headerCase === 0) {
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${contentLength}\r\n\r\n${String.fromCharCode(...body)}`);
  }

  if (headerCase === 1) {
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n${body.length.toString(16)}\r\n${String.fromCharCode(...body)}\r\n0\r\n\r\n`);
  }

  if (headerCase === 2) {
    const split = body.length >>> 1;
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n${split.toString(16)};x=${"a".repeat(i % 256)}\r\n${String.fromCharCode(...body.subarray(0, split))}\r\n${(body.length - split).toString(16)}\r\n${String.fromCharCode(...body.subarray(split))}\r\n0\r\n\r\n`);
  }

  if (headerCase === 3) {
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nContent-Length: ${contentLength}\r\n\r\n${String.fromCharCode(...body)}`);
  }

  if (headerCase === 4) {
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: gzip, chunked\r\n\r\n${body.length.toString(16)}\r\n${String.fromCharCode(...body)}\r\n0\r\n\r\n`);
  }

  if (headerCase === 5) {
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n${String.fromCharCode(...body)}`);
  }

  if (headerCase === 6) {
    return enc.encode(`POST /api/audit?x=${"A".repeat(i % 1024)} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Fill: ${"B".repeat(i % 4096)}\r\nContent-Length: ${body.length}\r\n\r\n${String.fromCharCode(...body)}`);
  }

  if (headerCase === 7) {
    return enc.encode(`POST /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n${(body.length + 16).toString(16)}\r\n${String.fromCharCode(...body)}\r\n0\r\n\r\n`);
  }

  return enc.encode(`GET /api/audit HTTP/1.1\r\nHost: localhost\r\nContent-Length: ${body.length}\r\n\r\n${String.fromCharCode(...body)}`);
}

async function send(bytes) {
  await new Promise(resolve => {
    Bun.connect({
      hostname: "127.0.0.1",
      port: server.port,
      socket: {
        open(sock) {
          sock.write(bytes);
          sock.end();
        },
        data() {},
        close: resolve,
        error: resolve,
      },
    });
  });
}

for (let i = 0; i < iterations; i++) {
  await send(requestBytes(i));
  if (i % 500 === 0) console.error(`[ctf-http-mutator] iteration=${i}`);
}

server.stop(true);
console.error(`[ctf-http-mutator] done iterations=${iterations}`);
