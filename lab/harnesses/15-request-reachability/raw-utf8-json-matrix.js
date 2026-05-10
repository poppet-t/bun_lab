import {
  HttpError,
  ascii,
  chunkedRequest,
  concatBytes,
  contentLengthRequest,
  json,
  maxBodyBytes,
  responseJson,
  sendRaw,
  splitPattern,
  statusCodes,
  utf8,
} from "./request-reachability-shared.js";

const iterations = Number(process.env.ITERATIONS || 300);
const modes = ["manual", "text", "json"];

async function manual(req) {
  const contentType = req.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "unsupported_media_type");

  const contentLength = req.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) throw new HttpError(400, "invalid_content_length");
    if (Number(contentLength) > maxBodyBytes) throw new HttpError(413, "payload_too_large");
  }

  if (!req.body) throw new HttpError(400, "empty_body");

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

  if (total === 0) throw new HttpError(400, "empty_body");

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new HttpError(400, "invalid_utf8");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}

async function textThenParse(req) {
  const contentType = req.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "unsupported_media_type");
  const text = await req.text();
  if (text.length === 0) throw new HttpError(400, "empty_body");
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}

async function jsonBuiltin(req) {
  const contentType = req.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "unsupported_media_type");
  try {
    return await req.json();
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}

const handlers = { manual, text: textThenParse, json: jsonBuiltin };

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  idleTimeout: 5,
  async fetch(req, server) {
    server.timeout(req, 3);
    const mode = new URL(req.url).pathname.slice(1);
    if (!(mode in handlers)) return json({ ok: false, error: "not_found" }, 404);

    try {
      const body = await handlers[mode](req);
      return json({
        ok: true,
        kind: body === null ? "null" : Array.isArray(body) ? "array" : typeof body,
        keys: body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body).slice(0, 4) : [],
      });
    } catch (error) {
      if (error instanceof HttpError) return json({ ok: false, error: error.code }, error.status);
      throw error;
    }
  },
});

function baseCorpus(i) {
  const cases = [
    utf8(JSON.stringify({ package: "bun" })),
    utf8(""),
    utf8("{"),
    utf8("[]"),
    utf8(JSON.stringify({ package: "bun", extra: 1 })),
    utf8('{"package":"\\ud800"}'),
    concatBytes([new Uint8Array([0xef, 0xbb, 0xbf]), utf8(JSON.stringify({ package: "bun" }))]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xff]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xc0, 0xaf]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xe0, 0x80, 0x80]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xed, 0xa0, 0x80]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xf4, 0x90, 0x80, 0x80]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xf0, 0x9f]), ascii('"}')]),
    concatBytes([ascii('{"package":"bu'), new Uint8Array([0x00]), ascii('n"}')]),
    utf8(`{"package":"${"a".repeat(96)}"}`),
    utf8(`{"package":"${"a".repeat(97)}"}`),
  ];
  return cases[i % cases.length];
}

function mutate(body, i) {
  const out = new Uint8Array(body);
  if (out.byteLength === 0) return out;

  const mode = (i / 16) & 7;
  if (mode === 0) return out;
  if (mode === 1) {
    out[i % out.byteLength] ^= 0xff;
    return out;
  }
  if (mode === 2) return out.subarray(0, Math.max(0, out.byteLength - 1));
  if (mode === 3) return concatBytes([out, ascii("\n\t ")]);
  if (mode === 4) return concatBytes([out, new Uint8Array([0xff, 0xfe])]).subarray(0, maxBodyBytes);
  if (mode === 5) return concatBytes([ascii(" "), out, ascii(" ")]);
  if (mode === 6) return concatBytes([out, out]).subarray(0, maxBodyBytes);
  return concatBytes([out.subarray(0, i % out.byteLength), new Uint8Array([0]), out.subarray(i % out.byteLength)]).subarray(0, maxBodyBytes);
}

function framed(mode, body, i) {
  const contentType = i % 13 === 0 ? "application/json; charset=utf-8" : "application/json";
  if (i % 2 === 0) {
    return contentLengthRequest({ path: `/${mode}?i=${i}`, body, contentType });
  }
  return chunkedRequest({
    path: `/${mode}?i=${i}`,
    body,
    chunkSizes: splitPattern(body.byteLength, i),
    contentType,
  });
}

const counters = new Map();
let mismatches = 0;
let internalErrors = 0;

for (let i = 0; i < iterations; i++) {
  const body = mutate(baseCorpus(i), i);
  const seen = {};

  for (const mode of modes) {
    const result = await sendRaw(server.port, framed(mode, body, i), { endAfterWrite: false });
    if (result.error) {
      seen[mode] = "socket-error";
    } else {
      const statuses = statusCodes(result.text);
      const parsed = responseJson(result.text);
      seen[mode] = `${statuses[0] || "no-status"}:${parsed?.error || parsed?.kind || "unparsed"}`;
      if (statuses.some((status) => status >= 500)) internalErrors++;
    }
    counters.set(`${mode}:${seen[mode]}`, (counters.get(`${mode}:${seen[mode]}`) || 0) + 1);
  }

  if ((seen.manual !== seen.text || seen.manual !== seen.json) && mismatches < 20) {
    console.error(`[raw-utf8-json-matrix] mismatch iteration=${i} manual=${seen.manual} text=${seen.text} json=${seen.json} body_len=${body.byteLength}`);
    mismatches++;
  } else if (seen.manual !== seen.text || seen.manual !== seen.json) {
    mismatches++;
  }

  if (i % 50 === 0) {
    console.error(`[raw-utf8-json-matrix] iteration=${i} mismatches=${mismatches} internal_errors=${internalErrors}`);
  }
}

server.stop(true);

console.error(JSON.stringify({
  harness: "raw-utf8-json-matrix",
  iterations,
  mismatches,
  internalErrors,
  counters: Object.fromEntries([...counters.entries()].sort()),
}));

if (internalErrors > 0) process.exit(1);
