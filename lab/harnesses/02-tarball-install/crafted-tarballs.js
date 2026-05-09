// Build malformed .tgz files in a temp dir and run `bun install` against
// each. We use the same Bun binary the harness is launched under, so this
// exercises whatever build profile (e.g. release-asan) the lab's run-asan.sh
// loaded.

import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const ROOT = mkdtempSync(join(tmpdir(), "lab-tarball-"));
console.error(`[tarball] workdir: ${ROOT}`);

// ── Tar header builder ─────────────────────────────────────────────────────
// Classic ustar; not full POSIX. Enough to feed the parser bad shapes.
function tarHeader({ name, size = 0, typeflag = "0", mode = 0o644, linkname = "" }) {
  const buf = Buffer.alloc(512);
  // file name (100 bytes)
  buf.write(name.slice(0, 100), 0, "utf8");
  // mode, uid, gid (octal, 8 each)
  buf.write(mode.toString(8).padStart(7, "0") + "\0", 100);
  buf.write("0000000\0", 108);
  buf.write("0000000\0", 116);
  // size (12 octal)
  buf.write(size.toString(8).padStart(11, "0") + "\0", 124);
  // mtime (12 octal)
  buf.write("00000000000\0", 136);
  // checksum placeholder (8 spaces, fill later)
  for (let i = 148; i < 156; i++) buf[i] = 0x20;
  // typeflag
  buf.write(typeflag, 156);
  // linkname (100)
  buf.write(linkname.slice(0, 100), 157, "utf8");
  // ustar magic + version
  buf.write("ustar\0", 257);
  buf.write("00", 263);
  // uname/gname/devmajor/devminor — leave zero
  // checksum
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += buf[i];
  buf.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return buf;
}

function pad512(buf) {
  const rem = buf.length % 512;
  if (rem === 0) return Buffer.alloc(0);
  return Buffer.alloc(512 - rem);
}

function tarball(entries) {
  const parts = [];
  for (const e of entries) {
    const data = Buffer.from(e.data ?? "");
    parts.push(tarHeader({ name: e.name, size: data.length, typeflag: e.typeflag, linkname: e.linkname }));
    parts.push(data);
    parts.push(pad512(data));
  }
  // Two zero blocks = end of archive
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

const PKG_JSON_OK = JSON.stringify({ name: "lab-target", version: "0.0.0" });

// ── Variants ───────────────────────────────────────────────────────────────
const variants = [
  {
    name: "01-baseline.tgz",
    bytes: gzipSync(tarball([
      { name: "package/package.json", data: PKG_JSON_OK },
    ])),
  },
  {
    name: "02-truncated-gz.tgz",
    bytes: gzipSync(tarball([{ name: "package/package.json", data: PKG_JSON_OK }])).slice(0, 64),
  },
  {
    name: "03-gz-bad-trailer.tgz",
    bytes: (() => {
      const ok = gzipSync(tarball([{ name: "package/package.json", data: PKG_JSON_OK }]));
      // flip the last 8 bytes (gzip CRC32 + ISIZE)
      for (let i = ok.length - 8; i < ok.length; i++) ok[i] ^= 0xff;
      return ok;
    })(),
  },
  {
    name: "04-size-mismatch.tgz",
    bytes: gzipSync((() => {
      // Header claims size=1, body actually has 4096 bytes.
      const fake = tarHeader({ name: "package/package.json", size: 1 });
      return Buffer.concat([fake, Buffer.alloc(4096, 0x41), Buffer.alloc(1024)]);
    })()),
  },
  {
    name: "05-traversal.tgz",
    bytes: gzipSync(tarball([
      { name: "package/package.json", data: PKG_JSON_OK },
      { name: "../../../tmp/lab-evil", data: "x" },
    ])),
  },
  {
    name: "06-symlink-loop.tgz",
    bytes: gzipSync(tarball([
      { name: "package/package.json", data: PKG_JSON_OK },
      { name: "package/a", typeflag: "2", linkname: "package/b" },
      { name: "package/b", typeflag: "2", linkname: "package/a" },
    ])),
  },
  {
    name: "07-huge-name.tgz",
    bytes: gzipSync(tarball([
      { name: "package/" + "n".repeat(90), data: PKG_JSON_OK },
    ])),
  },
  {
    name: "08-nul-in-name.tgz",
    bytes: gzipSync(tarball([
      { name: "package/a\x00b", data: PKG_JSON_OK },
    ])),
  },
  {
    name: "09-zero-size-entries-x10000.tgz",
    bytes: gzipSync(tarball(
      Array.from({ length: 10_000 }, (_, i) => ({
        name: `package/${i}.txt`,
        data: "",
      })).concat([{ name: "package/package.json", data: PKG_JSON_OK }]),
    )),
  },
];

const bun = process.execPath;
let i = 0;
for (const v of variants) {
  i++;
  const dir = join(ROOT, `t${String(i).padStart(2, "0")}`);
  mkdirSync(dir, { recursive: true });
  const tgz = join(dir, v.name);
  writeFileSync(tgz, v.bytes);
  // minimal package.json so `bun install` has somewhere to install into
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "host", version: "0.0.0" }));

  console.error(`[tarball] ${v.name} (${v.bytes.length} bytes)`);
  const proc = Bun.spawnSync({
    cmd: [bun, "install", "--no-save", "--ignore-scripts", "--force", tgz],
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, BUN_DEBUG_QUIET_LOGS: "1" },
  });
  if (proc.exitCode !== 0) {
    console.error(`[tarball]   exit=${proc.exitCode} (expected for malformed inputs)`);
  }
}

console.error(`[tarball] done — ${variants.length} variants installed`);
