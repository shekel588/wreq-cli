# Changelog

Notable changes to wreq-cli. Format follows [Keep a Changelog](https://keepachangelog.com/); versions track `Cargo.toml` / release tags.

## [0.4.3] — 2026-10-12

### Added
- Redirects are followed by default (up to 10 hops; error past that). Disable with `--nofollow` — short `-n`, combined `-nf`.

### Changed
- `install-or-update.ps1`: idempotent scoop bucket add + install/update fallback.

## [0.4.2] — 2026-10-12

### Fixed
- Wildcard match arm for macro-generated `Platform` variants (E0004).

## [0.4.1] — 2026-10-12

### Added
- `--resolve <host:ip|host:port:ip>` (repeatable): pin a hostname to an IP for origin-bypass behind CDNs; SNI/Host stay intact.
- `-k, --insecure`: skip TLS certificate verification.
- `-c, --cookie <K=V>` (repeatable, joined into one `Cookie` header).
- `-x, --proxy <URL>`: http/https/socks5/socks5h.
- Fingerprint banner when run without a URL.

## [0.3.4] — 2026-10-10

### Changed
- Upstream wreq/btls sync.

## [0.3.3] — 2026-10-09

### Changed
- Upstream wreq/btls sync.

## [0.3.2] — 2026-10-08

### Added
- Apache-2.0 LICENSE to match the scoop manifest claim.

### Changed
- Upstream wreq/btls sync.

## [0.3.1] — 2026-10-08

### Added
- Scoop manifest (`bucket/wreq.json`), `install.ps1`, and the upstream auto-update & release workflow (first CI release).

## [0.3.0] — 2026-10-08

### Added
- Chrome 154 default fingerprint ("etalon") matching host OS.
- `emulation-chromium-pki` and `emulation-compression` features.

### Changed
- Release profile optimized for size: LTO, `codegen-units=1`, `panic="abort"`, `strip=true`, `opt-level="z"`.
- `wreq` and `btls` ecosystem pinned to git main (trust anchors, GREASE sigalgs).
- CLI simplified to minimal essentials.

## [0.2.0] — 2026-10-06

### Added
- Host OS auto-detection and toml config support.

## [0.1.0] — 2026-10-06

### Added
- Initial CLI: `wreq [OPTIONS] <URL>` wrapping the wreq library with browser TLS & HTTP/2 impersonation (`-X/-e/-H/-d/-o/-I/-v`).
