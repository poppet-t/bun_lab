import {
  HttpError,
  ascii,
  chunkedRequest,
  concatBytes,
  forceGC,
  json,
  maxBodyBytes,
  runAudit,
  sendRaw,
  splitPattern,
  statusCodes,
  stressHeap,
  utf8,
} from "./request-reachability-shared.js";

const iterations = Number(process.env.ITERATIONS || 600);
const stressRounds = Number(process.env.STRESS_ROUNDS || 16);

function equalBytes(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function readLimitedTextWithChunkChecks(req) {
  const contentLength = req.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) throw new HttpError(400, "invalid_content_length");
    if (Number(contentLength) > maxBodyBytes) throw new HttpError(413, "payload_too_large");
  }

  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks = [];
  const snapshots = [];
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
    snapshots.push(value.slice());

    await Promise.resolve();
    stressHeap(stressRounds, 256);
  }

  await Promise.resolve();
  forceGC();
  stressHeap(stressRounds * 2, 512);

  for (let i = 0; i < chunks.length; i++) {
    if (!equalBytes(chunks[i], snapshots[i])) {
      console.error(JSON.stringify({
        harness: "chunk-copy-yield-stability",
        type: "stale_chunk_alias",
        chunk: i,
        before: [...snapshots[i].subarray(0, 32)],
        after: [...chunks[i].subarray(0, 32)],
      }));
      throw new HttpError(599, "stale_chunk_alias");
    }
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

async function parseJsonWithChunkChecks(req) {
  const contentType = req.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "unsupported_media_type");

  const text = await readLimitedTextWithChunkChecks(req);
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

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  idleTimeout: 5,
  async fetch(req, server) {
    server.timeout(req, 3);

    const url = new URL(req.url);
    if (url.pathname !== "/api/audit") return json({ ok: false, error: "not_found" }, 404);
    if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);

    try {
      const body = await parseJsonWithChunkChecks(req);
      return json(runAudit(body.package));
    } catch (error) {
      if (error instanceof HttpError) return json({ ok: false, error: error.code }, error.status);
      throw error;
    }
  },
});

function corpusBody(i) {
  const cases = [
    utf8(JSON.stringify({ package: "bun" })),
    utf8(JSON.stringify({ package: "@types/bun" })),
    utf8(`{"package":"${"a".repeat(96)}"}`),
    utf8(JSON.stringify({ package: "BUN" })),
    utf8(JSON.stringify({ package: "bun", extra: 1 })),
    utf8("{"),
    concatBytes([ascii('{"package":"a'), new Uint8Array([0xc3]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xed, 0xa0, 0x80]), ascii('"}')]),
    concatBytes([ascii('{"package":"'), new Uint8Array([0xf0, 0x9f]), ascii('"}')]),
    concatBytes([ascii('{"package":"bu'), new Uint8Array([0x00]), ascii('n"}')]),
  ];
  return cases[i % cases.length];
}

let status599 = 0;
let socketErrors = 0;

for (let i = 0; i < iterations; i++) {
  const body = corpusBody(i);
  const result = await sendRaw(server.port, chunkedRequest({
    path: `/api/audit?i=${i}&pad=${"x".repeat(i % 257)}`,
    body,
    chunkSizes: splitPattern(body.byteLength, i),
    contentType: i % 7 === 0 ? "application/json; charset=utf-8" : "application/json",
  }), { delayEvery: i % 9 === 0 ? 3 : 0, delayMs: 1 });

  if (result.error) {
    socketErrors++;
  } else if (statusCodes(result.text).includes(599)) {
    status599++;
  }

  if (i % 100 === 0) {
    console.error(`[chunk-copy-yield-stability] iteration=${i} stale_alias_statuses=${status599} socket_errors=${socketErrors}`);
  }
}

server.stop(true);

if (status599 > 0) {
  console.error(`[chunk-copy-yield-stability] stale chunk alias observed count=${status599}`);
  process.exit(1);
}

console.error(`[chunk-copy-yield-stability] done iterations=${iterations} stale_alias_statuses=${status599} socket_errors=${socketErrors}`);

