# Bun RCE CTF

The flag is not exposed by any normal HTTP route. Solving the challenge
requires remote code execution against the Bun server and reading `flag.txt`
from the server process working directory.

Start:

```sh
/Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan \
  /Users/CJ/Documents/bun_lab/lab/ctf/bun-rce/challenge-server.js
```

Solve:

```sh
/Users/CJ/Documents/bun_lab/bun/build/release-asan/bun-asan \
  /Users/CJ/Documents/bun_lab/lab/ctf/bun-rce/solve.js
```

Useful env:

- `PORT=31337`
- `FLAG=SCTF{rce_or_it_didnt_happen}`
- `CTF_URL=http://127.0.0.1:31337`
