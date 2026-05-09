// Drive deeply nested CSS calc() parsing through Bun.build.

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const depth = Number(process.env.CSS_CALC_DEPTH ?? "5000");
const root = mkdtempSync(join(tmpdir(), "lab-css-calc-"));
const cssPath = join(root, "calc.css");
const entryPath = join(root, "entry.js");

const css = `.a{width:${"calc(".repeat(depth)}1px${")".repeat(depth)};}`;
writeFileSync(cssPath, css);
writeFileSync(entryPath, `import "./calc.css";`);

console.error(`[calc-depth] workdir=${root}`);
console.error(`[calc-depth] depth=${depth} bytes=${css.length}`);

const out = await Bun.build({
  entrypoints: [entryPath],
  outdir: join(root, "out"),
  target: "browser",
  throw: false,
});

console.error(`[calc-depth] success=${out.success} logs=${out.logs.length}`);
