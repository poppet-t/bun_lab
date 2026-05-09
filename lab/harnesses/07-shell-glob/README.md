# 07 — Shell parser & glob expansion

`Bun.$` and `Bun.glob()` parse shell-style strings: brace expansion,
quoting, redirections, glob patterns. The expansion code in
`bun/src/shell_parser/` has hard caps (e.g., u16) that an attacker-influenced
template can blow through.

## Risk model

Shell strings often interpolate user-controlled values (CLI args, config,
environment). A parser bug that escalates a brace-expansion oops into
memory corruption is reachable wherever a project does `Bun.$\`...${untrusted}...\``.

## Files

- `brace-bombs.js` — hostile brace patterns and glob inputs.
