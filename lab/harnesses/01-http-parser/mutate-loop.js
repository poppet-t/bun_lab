// Mutate raw HTTP corpus entries and send them to a local Bun.serve() parser.

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const corpusDir = join(here, "../../corpus/01-http-parser");
const iterations = Number(process.env.ITERATIONS || 1000);

if (!existsSync(corpusDir)) {
  mkdirSync(corpusDir, { recursive: true });
  const seed = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: lab\r\n\r\n";
  writeFileSync(join(corpusDir, "01-baseline.bin"), seed);
}

const seeds = readdirSync(corpusDir)
  .filter((name) => name.endsWith(".bin"))
  .map((name) => readFileSync(join(corpusDir, name)));

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(req) {
    await req.arrayBuffer().catch(() => null);
    return new Response("ok\n");
  },
});

function mutate(input, i) {
  const out = new Uint8Array(input);
  if (out.length === 0) return out;
  const mode = i % 6;
  if (mode === 0) out[i % out.length] ^= 0xff;
  if (mode === 1) out[i % out.length] = 0;
  if (mode === 2) out[i % out.length] = 0x0d;
  if (mode === 3) out[i % out.length] = 0x0a;
  if (mode === 4) return new Uint8Array([...out, ...new TextEncoder().encode("X-Fill: " + "A".repeat(4096) + "\r\n")]);
  if (mode === 5) return out.slice(0, Math.max(1, out.length - (i % out.length)));
  return out;
}

async function send(bytes) {
  await new Promise((resolve) => {
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
  const seed = seeds[i % seeds.length];
  await send(mutate(seed, i));
  if (i % 100 === 0) console.error(`[http-mutator] iteration=${i}`);
}

server.stop(true);
console.error(`[http-mutator] done iterations=${iterations}`);
