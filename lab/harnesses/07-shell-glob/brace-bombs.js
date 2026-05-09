// Stress shell/glob/brace expansion without invoking external commands.

const patterns = [
  "{a,b,c}{d,e,f}{g,h,i}{j,k,l}",
  "src/**/{*.js,*.ts,*.tsx,*.jsx}",
  "{1..100}",
  "{{{{a,b},c},d},e}",
  "{a,{b,{c,{d,{e,f}}}}}",
  "*".repeat(512),
];

for (const pattern of patterns) {
  try {
    const glob = new Bun.Glob(pattern);
    let count = 0;
    for await (const _ of glob.scan({ cwd: "." })) {
      count++;
      if (count > 1000) break;
    }
    console.error(`[glob] ${pattern.slice(0, 32)} count=${count}`);
  } catch (error) {
    console.error(`[glob] threw ${error?.message || error}`);
  }
}

console.error("[glob] done");
