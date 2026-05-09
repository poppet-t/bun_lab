// Boot a local Bun.serve() instance and send raw malformed HTTP/1.1 bytes.

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(req) {
    const body = await req.text().catch(() => "");
    return new Response(`ok ${req.method} ${new URL(req.url).pathname} ${body.length}\n`);
  },
});

const addr = `127.0.0.1:${server.port}`;
console.error(`[http-parser] listening on ${addr}`);

const enc = new TextEncoder();
const cases = [
  ["baseline", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"],
  ["missing-host", "GET /missing HTTP/1.1\r\nUser-Agent: lab\r\n\r\n"],
  ["obs-fold", "GET /fold HTTP/1.1\r\nHost: localhost\r\nX-Test: a\r\n b\r\n\r\n"],
  ["duplicate-cl", "POST /dupe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\n12345678"],
  ["chunk-ext", "POST /chunk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nbody\r\n0\r\n\r\n"],
  ["short-chunk", "POST /short HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc\r\n0\r\n\r\n"],
  ["nul-header", "GET /nul HTTP/1.1\r\nHost: local\0host\r\n\r\n"],
  ["long-header", `GET /long HTTP/1.1\r\nHost: localhost\r\nX-Long: ${"A".repeat(64 * 1024)}\r\n\r\n`],
  ["weird-method", "G\xffT /weird HTTP/1.1\r\nHost: localhost\r\n\r\n"],
  ["absolute", "GET http://example.test/a?b=c HTTP/1.1\r\nHost: localhost\r\n\r\n"],
];

function toBytes(data) {
  return typeof data === "string" ? enc.encode(data) : data;
}

async function sendRaw(label, data) {
  const bytes = toBytes(data);
  await new Promise((resolve) => {
    const socket = Bun.connect({
      hostname: "127.0.0.1",
      port: server.port,
      socket: {
        open(sock) {
          sock.write(bytes);
          sock.end();
        },
        data() {},
        close() {
          console.error(`[http-parser] ${label} bytes=${bytes.length}`);
          resolve();
        },
        error(sock, err) {
          console.error(`[http-parser] ${label} socket-error=${err?.message || err}`);
          resolve();
        },
      },
    });
    void socket;
  });
}

for (const [label, data] of cases) {
  await sendRaw(label, data);
}

server.stop(true);
console.error("[http-parser] done");
