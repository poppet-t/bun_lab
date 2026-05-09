// Fake postgres server feeding malformed messages to bun:sql. We complete
// just enough of the startup handshake that the client commits to parsing,
// then start emitting hostile bytes.
//
// Message types we abuse:
//   'R'  Authentication                — wrong sub-codes, oversized SASL data
//   'S'  ParameterStatus               — huge key/value, no NUL terminators
//   'K'  BackendKeyData                — wrong length
//   'Z'  ReadyForQuery                 — invalid status byte
//   'T'  RowDescription                — bogus field counts
//   'D'  DataRow                       — column count vs column data mismatch
//   'E'  ErrorResponse                 — malformed field tag stream
//   'N'  NoticeResponse                — same shape as 'E'
//
// Postgres frame format:
//   1-byte type tag, 4-byte big-endian length INCLUDING the length field
//   itself, then payload. We hand-build these.

import { sql } from "bun:sql";

function frame(tag, payload) {
  const buf = Buffer.alloc(5 + payload.length);
  buf.write(tag, 0, "latin1");
  buf.writeUInt32BE(4 + payload.length, 1);
  payload.copy(buf, 5);
  return buf;
}

const variants = [];

// 1. RowDescription claiming 65535 fields, none provided
variants.push(frame("T", (() => {
  const p = Buffer.alloc(2);
  p.writeUInt16BE(0xffff, 0);
  return p;
})()));

// 2. DataRow claiming 1 column, length 0x7fffffff, no data
variants.push(frame("D", (() => {
  const p = Buffer.alloc(2 + 4);
  p.writeUInt16BE(1, 0);
  p.writeInt32BE(0x7fffffff, 2);
  return p;
})()));

// 3. ParameterStatus with 1MB key, no NUL
variants.push(frame("S", Buffer.concat([
  Buffer.alloc(1 << 20, 0x41),
  Buffer.from([0]),
  Buffer.from("v"),
  Buffer.from([0]),
])));

// 4. ErrorResponse with infinite field stream (no terminating NUL)
variants.push(frame("E", Buffer.alloc(4096, 0x53)));

// 5. Authentication with sub-code 99 (undefined)
variants.push(frame("R", (() => {
  const p = Buffer.alloc(4);
  p.writeUInt32BE(99, 0);
  return p;
})()));

// 6. Frame with length=0 (smaller than the 4-byte length field)
variants.push((() => {
  const buf = Buffer.alloc(5);
  buf.write("E", 0, "latin1");
  buf.writeUInt32BE(0, 1);
  return buf;
})());

// 7. Frame with length far beyond what's actually sent
variants.push((() => {
  const buf = Buffer.alloc(5 + 8);
  buf.write("D", 0, "latin1");
  buf.writeUInt32BE(0x7fffffff, 1);
  return buf;
})());

const server = Bun.listen({
  hostname: "127.0.0.1",
  port: 0,
  socket: {
    open(s) { console.error(`[pg] client connected`); },
    async data(s, chunk) {
      // first message from the client is StartupMessage. Accept any.
      // Reply: AuthenticationOk, ParameterStatus, BackendKeyData, ReadyForQuery,
      // then start blasting variants.
      const auth_ok = frame("R", (() => { const p = Buffer.alloc(4); p.writeUInt32BE(0, 0); return p; })());
      const param = frame("S", Buffer.concat([Buffer.from("server_version"), Buffer.from([0]), Buffer.from("99.0"), Buffer.from([0])]));
      const key = frame("K", (() => { const p = Buffer.alloc(8); p.writeUInt32BE(1, 0); p.writeUInt32BE(2, 4); return p; })());
      const ready = frame("Z", Buffer.from("I"));
      s.write(Buffer.concat([auth_ok, param, key, ready]));

      // Now blast variants
      for (const v of variants) {
        s.write(v);
      }
      // half-close
      await Bun.sleep(50);
      s.end();
    },
    error(s, e) { console.error(`[pg] sock err: ${e?.message}`); },
    close() { console.error(`[pg] client disconnected`); },
  },
});

const url = `postgresql://lab:lab@127.0.0.1:${server.port}/lab`;
console.error(`[pg] fake server up at ${url}`);

const client = sql(url, { idle_timeout: 1, connect_timeout: 1 });

try {
  // Trigger the client's connect path; we don't care that the query fails.
  // We care that the parser walks our hostile bytes without exploding.
  await client`SELECT 1`;
} catch (e) {
  console.error(`[pg] query threw: ${e?.message}`);
}

await Bun.sleep(200);
await client.end();
server.stop(true);
console.error(`[pg] done`);
