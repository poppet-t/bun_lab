export const enc = new TextEncoder();
export const dec = new TextDecoder();
export const maxBodyBytes = 512;
export const maxPackageNameBytes = 96;

export class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export function ascii(text) {
  return enc.encode(text);
}

export function utf8(text) {
  return enc.encode(text);
}

export function concatBytes(parts) {
  let total = 0;
  for (const part of parts) total += typeof part === "string" ? enc.encode(part).byteLength : part.byteLength;

  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    const bytes = typeof part === "string" ? enc.encode(part) : part;
    out.set(bytes, offset);
    offset += bytes.byteLength;
  }
  return out;
}

export function forceGC() {
  try {
    Bun.gc?.(true);
  } catch {}

  try {
    globalThis.gc?.();
  } catch {}
}

export function stressHeap(rounds = 32, size = 1024) {
  const bag = [];
  let checksum = 0;
  for (let i = 0; i < rounds; i++) {
    const view = new Uint8Array(size + (i & 31));
    view.fill((0x41 + i) & 0xff);
    checksum ^= view[i & (view.byteLength - 1)];
    bag.push(view);
  }
  forceGC();
  return checksum ^ bag.length;
}

export async function readLimitedText(req) {
  const contentLength = req.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new HttpError(400, "invalid_content_length");
    }

    if (Number(contentLength) > maxBodyBytes) {
      throw new HttpError(413, "payload_too_large");
    }
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

export async function parseJson(req) {
  const contentType = req.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpError(415, "unsupported_media_type");
  }

  const text = await readLimitedText(req);
  if (text.length === 0) {
    throw new HttpError(400, "empty_body");
  }

  try {
    const body = JSON.parse(text);
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      throw new HttpError(400, "invalid_json_schema");
    }

    const keys = Object.keys(body);
    if (keys.length !== 1 || keys[0] !== "package") {
      throw new HttpError(400, "invalid_json_schema");
    }

    return body;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "invalid_json");
  }
}

export function normalizePackageName(target) {
  if (typeof target !== "string") {
    throw new HttpError(400, "invalid_package_name");
  }

  if (target !== target.trim()) {
    throw new HttpError(400, "invalid_package_name");
  }

  const name = target.toLowerCase();
  if (name !== target || name.length === 0 || name.length > maxPackageNameBytes) {
    throw new HttpError(400, "invalid_package_name");
  }

  const unscoped = /^[a-z0-9](?:[a-z0-9._-]{0,94}[a-z0-9])?$/;
  const scoped = /^@[a-z0-9](?:[a-z0-9._-]{0,46}[a-z0-9])?\/[a-z0-9](?:[a-z0-9._-]{0,46}[a-z0-9])?$/;
  if (!unscoped.test(name) && !scoped.test(name)) {
    throw new HttpError(400, "invalid_package_name");
  }

  return name;
}

export function runAudit(target) {
  const name = normalizePackageName(target);
  return {
    ok: true,
    package: name,
    cache: name === "bun" || name === "@types/bun" || name === "typescript" ? "hit" : "miss",
  };
}

export function statusCodes(responseText) {
  return [...responseText.matchAll(/HTTP\/1\.1\s+(\d+)/g)].map((match) => Number(match[1]));
}

export function responseJson(responseText) {
  const split = responseText.split("\r\n\r\n");
  const body = split[split.length - 1] || "";
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

export function requestHead({ method = "POST", path = "/api/audit", headers = [] } = {}) {
  return ascii(`${method} ${path} HTTP/1.1\r\nHost: localhost\r\n${headers.join("\r\n")}\r\n\r\n`);
}

export function contentLengthRequest({
  method = "POST",
  path = "/api/audit",
  body = new Uint8Array(),
  declaredLength = body.byteLength,
  contentType = "application/json",
  connection = "close",
  extraHeaders = [],
} = {}) {
  const headers = [
    `Content-Type: ${contentType}`,
    `Content-Length: ${declaredLength}`,
    `Connection: ${connection}`,
    ...extraHeaders,
  ];
  return [requestHead({ method, path, headers }), body];
}

export function chunkedRequest({
  method = "POST",
  path = "/api/audit",
  body = new Uint8Array(),
  chunkSizes = [body.byteLength],
  contentType = "application/json",
  connection = "close",
  extraHeaders = [],
  trailer = true,
} = {}) {
  const headers = [
    `Content-Type: ${contentType}`,
    "Transfer-Encoding: chunked",
    `Connection: ${connection}`,
    ...extraHeaders,
  ];
  const parts = [requestHead({ method, path, headers })];
  let offset = 0;
  for (const requestedSize of chunkSizes) {
    if (offset >= body.byteLength) break;
    const size = Math.max(1, Math.min(requestedSize, body.byteLength - offset));
    parts.push(ascii(`${size.toString(16)}\r\n`));
    parts.push(body.subarray(offset, offset + size));
    parts.push(ascii("\r\n"));
    offset += size;
  }

  if (offset < body.byteLength) {
    const rest = body.byteLength - offset;
    parts.push(ascii(`${rest.toString(16)}\r\n`));
    parts.push(body.subarray(offset));
    parts.push(ascii("\r\n"));
  }

  if (trailer) parts.push(ascii("0\r\n\r\n"));
  return parts;
}

export function splitPattern(length, seed) {
  const modes = [
    [1],
    [2, 3, 5, 7],
    [Math.max(1, length >>> 1)],
    [31, 1, 63, 2],
    [Math.max(1, length - 1), 1],
  ];
  return modes[seed % modes.length];
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function sendRaw(port, parts, { delayEvery = 0, delayMs = 0, endAfterWrite = true, endDelayMs = 0 } = {}) {
  return await new Promise((resolve) => {
    const chunks = [];
    let settled = false;

    function finish(result) {
      if (settled) return;
      settled = true;
      resolve(result);
    }

    Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open(sock) {
          (async () => {
            for (let i = 0; i < parts.length; i++) {
              sock.write(parts[i]);
              if (delayEvery > 0 && i % delayEvery === delayEvery - 1) {
                await sleep(delayMs);
              }
            }
            if (endAfterWrite) {
              if (endDelayMs > 0) await sleep(endDelayMs);
              sock.end();
            }
          })().catch((error) => finish({ error }));
        },
        data(_sock, data) {
          chunks.push(data.slice());
        },
        close() {
          finish({ text: dec.decode(concatBytes(chunks)) });
        },
        error(_sock, error) {
          finish({ error, text: dec.decode(concatBytes(chunks)) });
        },
      },
    });
  });
}
