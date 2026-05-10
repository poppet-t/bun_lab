const firstSize = Number(process.env.FIRST_SIZE || 256);
const secondSize = Number(process.env.SECOND_SIZE || 256);
const delayMs = Number(process.env.DELAY_MS || 20);
const iterations = Number(process.env.ITERATIONS || 1000);

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function allEqual(view, byte) {
  for (let i = 0; i < view.byteLength; i++) {
    if (view[i] !== byte) return false;
  }
  return true;
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(req) {
    const reader = req.body.getReader();
    const first = await reader.read();
    if (first.done) return new Response("empty", { status: 400 });

    const firstView = first.value;
    const firstBefore = firstView.slice();
    await sleep(delayMs);

    const chunks = [firstView];
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      chunks.push(next.value);
    }

    const stable = firstView.byteLength === firstBefore.byteLength && firstView.every((byte, i) => byte === firstBefore[i]);
    const expected = allEqual(firstView, 0x41);
    if (!stable || !expected) {
      console.error(JSON.stringify({
        stable,
        expected,
        firstByteLength: firstView.byteLength,
        beforePrefix: [...firstBefore.subarray(0, 32)],
        afterPrefix: [...firstView.subarray(0, 32)],
      }));
      return new Response("changed", { status: 599 });
    }

    return new Response("ok");
  },
});

async function sendOne(iteration) {
  await new Promise(resolve => {
    Bun.connect({
      hostname: "127.0.0.1",
      port: server.port,
      socket: {
        open(sock) {
          sock.write(`POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n${firstSize.toString(16)}\r\n`);
          sock.write(new Uint8Array(firstSize).fill(0x41));
          sock.write("\r\n");
          setTimeout(() => {
            sock.write(`${secondSize.toString(16)}\r\n`);
            sock.write(new Uint8Array(secondSize).fill(0x42 + (iteration & 15)));
            sock.write("\r\n0\r\n\r\n");
            sock.end();
          }, delayMs >>> 1);
        },
        data() {},
        close: resolve,
        error: resolve,
      },
    });
  });
}

for (let i = 0; i < iterations; i++) {
  await sendOne(i);
  if (i % 100 === 0) console.error(`[body-chunk-stability] iteration=${i}`);
}

server.stop(true);
console.error(`[body-chunk-stability] done iterations=${iterations}`);
