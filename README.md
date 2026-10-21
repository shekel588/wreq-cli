# wreq — fast stealth HTTP client

Single binary wrapping [wreq](https://github.com/0x676e67/wreq)/btls: real-browser TLS & HTTP/2 fingerprint impersonation. Scoop manifest: `bucket/wreq.json`.

## Agent rules (read before calling)

- Call as plain `wreq <URL>`. **NEVER pass `-e/--emulation` on Windows** — the Chrome profile matching the host OS is the default and already active. Use `-e firefox|safari|edge|chrome_137` only to cross-impersonate another OS/browser.
- Exit codes: **0** = done, including HTTP 4xx/5xx (parse `-v`/`-I` output for the status). **1** = any error — transport failure, invalid `--resolve`/`--proxy`, output I/O.
- URL without a scheme gets `https://` (or `http://` when `-k`). Full flag set: `wreq --help`.