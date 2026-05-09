// Local server returns malformed compressed bodies under various
// Content-Encoding headers. Client fetch() decodes — bugs land in the
// decompressor or its buffer-growth path.

import { gzipSync, deflateRawSync, brotliCompressSync } from "node:zlib";

function bombs() {
  const ok = Buffer.from("hello world".repeat(64));
  return [
    // gzip body, deflate header (forces wrong codec)
    { enc: "deflate", body: gzipSync(ok), label: "gzip-as-deflate" },
    // truncated gzip
    { enc: "gzip", body: gzipSync(ok).slice(0, 16), label: "trunc-gzip" },
    // gzip with corrupt trailer (CRC + isize XORed)
    { enc: "gzip", body: (() => {
        const b = Buffer.from(gzipSync(ok));
        for (let i = b.length - 8; i < b.length; i++) b[i] ^= 0xff;
        return b;
      })(), label: "bad-gzip-trailer" },
    // raw deflate of garbage
    { enc: "deflate", body: deflateRawSync(Buffer.alloc(1024, 0xff)), label: "deflate-noise" },
    // brotli where ratio is enormous (10MB → 16 bytes), tests buffer growth
    { enc: "br", body: brotliCompressSync(Buffer.alloc(10 * 1024 * 1024, 0x41)), label: "br-bomb-10mb" },
    // empty body
    { enc: "gzip", body: Buffer.alloc(0), label: "gzip-empty" },
    // valid gzip but advertises zstd
    { enc: "zstd", body: gzipSync(ok), label: "gzip-as-zstd" },
  ];
}

const server = Bun.serve({
  port: 0,
  routes: {
    "/:label": (req) => {
      const url = new URL(req.url);
      const label = url.pathname.slice(1);
      const b = bombs().find((x) => x.label === label);
      if (!b) return new Response("missing", { status: 404 });
      return new Response(b.body, {
        headers: { "content-encoding": b.enc, "content-type": "text/plain" },
      });
    },
  },
});

const base = `http://127.0.0.1:${server.port}`;
console.error(`[decomp] server up at ${base}`);

for (const b of bombs()) {
  console.error(`[decomp] ${b.label} (${b.body.length} bytes, ce=${b.enc})`);
  try {
    const r = await fetch(`${base}/${b.label}`);
    // touch the body — that's where decompression actually happens
    const t = await r.text().catch((e) => `<err: ${e?.message}>`);
    console.error(`[decomp]   status=${r.status} len=${t.length}`);
  } catch (e) {
    console.error(`[decomp]   threw: ${e?.message}`);
  }
}

server.stop(true);
console.error(`[decomp] done`);
