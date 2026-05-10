import {
  HttpError,
  ascii,
  chunkedRequest,
  concatBytes,
  contentLengthRequest,
  json,
  parseJson,
  runAudit,
  sendRaw,
  statusCodes,
  utf8,
} from "./request-reachability-shared.js";

const iterations = Number(process.env.ITERATIONS || 500);

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
      const body = await parseJson(req);
      return json(runAudit(body.package));
    } catch (error) {
      if (error instanceof HttpError) return json({ ok: false, error: error.code }, error.status);
      throw error;
    }
  },
});

function validFollowup(connection = "close") {
  return contentLengthRequest({
    body: utf8(JSON.stringify({ package: "bun" })),
    connection,
  });
}

function oversizeChunkedThenValid(i) {
  const body = new Uint8Array(640 + (i % 64)).fill(0x41 + (i % 26));
  return [
    ...chunkedRequest({
      body,
      chunkSizes: [255, 1, 255, 1, 255],
      connection: "keep-alive",
      path: `/api/audit?case=chunked&i=${i}`,
    }),
    ...validFollowup(),
  ];
}

function oversizeContentLengthThenValid(i) {
  const body = new Uint8Array(620 + (i % 80)).fill(0x30 + (i % 10));
  return [
    ...contentLengthRequest({
      body,
      declaredLength: body.byteLength,
      connection: "keep-alive",
      path: `/api/audit?case=cl-body&i=${i}`,
    }),
    ...validFollowup(),
  ];
}

function declaredOversizeNoBodyThenValid(i) {
  return [
    ...contentLengthRequest({
      body: new Uint8Array(),
      declaredLength: 513 + (i % 64),
      connection: "keep-alive",
      path: `/api/audit?case=cl-empty&i=${i}`,
    }),
    ...validFollowup(),
  ];
}

function shortChunkThenValid(i) {
  const partial = concatBytes([ascii("200\r\n"), new Uint8Array(128).fill(0x61 + (i % 26)), ascii("\r\n")]);
  return [
    ascii(`POST /api/audit?case=short-chunk&i=${i} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n`),
    partial,
    ...validFollowup(),
  ];
}

const builders = [
  oversizeChunkedThenValid,
  oversizeContentLengthThenValid,
  declaredOversizeNoBodyThenValid,
  shortChunkThenValid,
];

const patterns = new Map();
let socketErrors = 0;
let internalErrors = 0;
let followupAccepted = 0;

for (let i = 0; i < iterations; i++) {
  const parts = builders[i % builders.length](i);
  const result = await sendRaw(server.port, parts, {
    delayEvery: i % 11 === 0 ? 4 : 0,
    delayMs: 1,
  });

  if (result.error) {
    socketErrors++;
  } else {
    const statuses = statusCodes(result.text);
    const key = statuses.join(",") || "no-status";
    patterns.set(key, (patterns.get(key) || 0) + 1);
    if (statuses.includes(500) || statuses.some((status) => status >= 590)) internalErrors++;
    if (statuses.includes(200)) followupAccepted++;
  }

  if (i % 100 === 0) {
    console.error(`[cancel-oversize-pipeline] iteration=${i} socket_errors=${socketErrors} internal_or_59x=${internalErrors}`);
  }
}

server.stop(true);

console.error(JSON.stringify({
  harness: "cancel-oversize-pipeline",
  iterations,
  socketErrors,
  internalErrors,
  followupAccepted,
  statusPatterns: Object.fromEntries([...patterns.entries()].sort()),
}));

if (internalErrors > 0) process.exit(1);

