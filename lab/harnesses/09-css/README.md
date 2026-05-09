# 09 — CSS parser

Bun's bundler parses CSS via a hand-written Zig parser at
`bun/src/css/`. Hand-written parsers with backtracking are a fertile bug
ground; bundler users feed it third-party CSS via `import "./style.css"`.

## Files

- `bundle-css.js` — drops a battery of malformed CSS into a temp dir and
  invokes the bundler.
