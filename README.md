# wreq — fast stealth HTTP client

Single binary wrapping [wreq](https://github.com/0x676e67/wreq)/btls: real-browser TLS & HTTP/2 fingerprint impersonation. Scoop manifest: `bucket/wreq.json`.

## Default Behavior: 100% Chrome Out-of-the-Box

By default, calling `wreq <URL>` with no extra flags behaves **in exact accordance with a real Chrome browser on your host OS**:
- **TLS layer**: Sends the authentic Chrome 154 `ClientHello` (JA3/JA4, extension permutation, GREASE, ML-KEM key shares, Brotli cert compression, and Chromium Root Store `trust_anchors` IDs).
- **HTTP/2 layer**: Uses Chrome's exact `SETTINGS`, `WINDOW_UPDATE`, and `PRIORITY` frame parameters.
- **HTTP headers & order**: Automatically sends the complete standard set of Chrome headers (`User-Agent`, `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`, `Upgrade-Insecure-Requests`, `Accept`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-User`, `Sec-Fetch-Dest`, `Accept-Encoding: gzip, deflate, br, zstd`, `Accept-Language`) in Chrome's exact wire order (`orig_headers`).
- **Redirects & cookies**: Follows up to 10 redirects (`Referer` updated across hops per `Referrer-Policy`) and keeps an in-memory session cookie jar (`Set-Cookie` on 302 hops is automatically sent on subsequent requests).

**Explicit Overrides**: All tuning flags (`-A`, `-H`, `--http1.1`, `--tlsv1.2`, `--raw`, `-nf`, `-m`, `--retry`, etc.) do **nothing** unless explicitly passed on the command line — when specified, they selectively override only that part of the default Chrome preset.

## Agent rules (read before calling)

- Call as plain `wreq <URL>`. **Do not pass `-e/--emulation` on Windows** — the Chrome profile matching the host OS is the default and already active. Use `-e firefox|safari|edge|chrome_137` only to cross-impersonate another OS/browser.
- Exit codes: **0** = done, including HTTP 4xx/5xx (parse `-v`/`-I` output for the status). **1** = any error — transport failure, timeout, invalid `--resolve`/`--proxy`, output I/O.
- Status badges (`-I` / `-v`): The 3-digit HTTP status code is highlighted with an inverted ANSI badge:
  - **Green** (`200..=299`): Success
  - **Yellow** (`100..=199`, `300..=399`, `CERT`): Informational / Redirect / Certificate warning
  - **Red** (`400..=599`, `ERR`): Client/Server HTTP error or transport error
  - Pass `--no-color` (or `NO_COLOR=1`) to disable ANSI badges.
- URL without a scheme gets `https://` (or `http://` when `-k` without `--https-only`). Full flag set: `wreq --help`.
