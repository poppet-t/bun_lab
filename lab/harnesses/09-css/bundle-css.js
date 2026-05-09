// Feed malformed CSS through the bundler.

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = mkdtempSync(join(tmpdir(), "lab-css-"));
console.error(`[css] workdir: ${ROOT}`);

const variants = [
  // unbalanced braces
  ".a{color:red;",
  ".a{}".repeat(10_000),                                    // wide
  ":not(:not(:not(:not(:not(.x)))))".repeat(100) + "{}",    // deep selectors
  `@import url("${"a".repeat(1 << 16)}");`,
  `.a{content:"${"\\".repeat(1024)}";}`,                    // big escape run
  ".a{--var:" + "(".repeat(1024) + ";}",                    // unbalanced vars
  ".a{font:" + "100 ".repeat(10_000) + "italic;}",          // long shorthand
  "@keyframes k {" + Array.from({ length: 4096 }, (_, i) => `${i}%{x:${i};}`).join("") + "}",
  // calc with deep nesting
  ".a{width:" + "calc(".repeat(512) + "1px" + ")".repeat(512) + ";}",
  // null bytes
  ".a{color:red\x00;}",
  // unicode-range edges
  ".a{unicode-range:U+0-10FFFF;}",
];

for (let i = 0; i < variants.length; i++) {
  const id = String(i + 1).padStart(2, "0");
  const css = join(ROOT, `${id}.css`);
  const entry = join(ROOT, `${id}.js`);
  writeFileSync(css, variants[i]);
  writeFileSync(entry, `import "./${id}.css";`);
  console.error(`[css] case ${id} (${variants[i].length} bytes)`);
  try {
    const out = await Bun.build({
      entrypoints: [entry],
      outdir: join(ROOT, "out", id),
      target: "browser",
      throw: false,
    });
    if (!out.success) {
      console.error(`[css]   logs: ${out.logs.length}`);
    }
  } catch (e) {
    console.error(`[css] case ${id} threw: ${e?.message?.slice(0, 200)}`);
  }
}

console.error(`[css] done`);
