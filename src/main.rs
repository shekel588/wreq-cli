use clap::Parser;
use std::fs::{self, File};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use wreq::cookie::Jar;
use wreq::multipart::{Form as MultipartForm, Part as MultipartPart};
use wreq::redirect::Policy as RedirectPolicy;
use wreq::retry::Policy as RetryPolicy;
use wreq::tls::keylog::KeyLog;
use wreq::tls::trust::{CertStore, Identity};
use wreq::tls::TlsVersion;
use wreq::{Client, IntoEmulation, NoProxy, Proxy};
use wreq_util::{Emulation, Platform, Profile};

#[derive(Parser, Debug)]
#[command(
    name = "wreq",
    version,
    about = "Fast stealth HTTP client — behaves 100% identically to Chrome by default (TLS, HTTP/2, headers & order)",
    after_help = "Default Chrome behavior:\n  \
        By default, `wreq <URL>` acts identically to a real Chrome browser on your OS:\n  \
        it sends the exact Chrome TLS ClientHello (JA3/JA4 + Chromium Trust Anchor IDs),\n  \
        HTTP/2 SETTINGS/WINDOW_UPDATE/PRIORITY frames, the full set and exact order of\n  \
        standard Chrome headers (User-Agent, Sec-CH-UA*, Sec-Fetch-*, Accept*, etc.),\n  \
        follows up to 10 redirects with Referer handling, and keeps session cookies across hops.\n  \
        Any CLI flags below (-A, -H, --http1.1, --tlsv1.2, --raw, -nf, etc.), only when\n  \
        passed explicitly, selectively override the corresponding part of the default Chrome preset."
)]
struct Args {
    /// URL to fetch (omit to print the active fingerprint banner)
    url: Option<String>,

    /// HTTP method (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS).
    /// Defaults to POST when -d/--json/-F/--data-urlencode is used, otherwise GET.
    #[arg(short = 'X', long = "method", alias = "request")]
    method: Option<String>,

    /// Fingerprint override. Default: Chrome profile matching the host OS (already enabled).
    /// Do not pass -e on Windows (or any host): it is enabled by default.
    /// Use only to cross-impersonate: firefox | safari | edge | chrome_137.
    #[arg(
        short = 'e',
        long = "emulation",
        alias = "impersonate",
        short_alias = 'i'
    )]
    emulation: Option<String>,

    /// Add/override header on top of Chrome's default headers (e.g. -H "Authorization: Bearer xxx")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Explicitly override the profile's default User-Agent header
    #[arg(short = 'A', long = "user-agent")]
    user_agent: Option<String>,

    /// Request body string (defaults method to POST if -X is omitted)
    #[arg(
        short = 'd',
        long = "data",
        aliases = ["data-raw", "data-binary"]
    )]
    data: Option<String>,

    /// URL-encoded form field "name=value" or "name@file" (repeatable, sets application/x-www-form-urlencoded)
    #[arg(long = "data-urlencode")]
    data_urlencode: Vec<String>,

    /// Send JSON body (or "@file") with Content-Type: application/json
    #[arg(long = "json")]
    json: Option<String>,

    /// Multipart form field "name=value" or file "name=@path[;type=mime][;filename=name]" (repeatable, Chromium WebKitFormBoundary)
    #[arg(short = 'F', long = "form")]
    form: Vec<String>,

    /// Save response body to file instead of stdout
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Print response status and headers only
    #[arg(short = 'I', long = "head")]
    head_only: bool,

    /// Print response status and headers alongside body
    #[arg(short = 'v', long = "verbose", alias = "include")]
    include_headers: bool,

    /// Disable ANSI color badges on status codes and errors (also respects NO_COLOR env)
    #[arg(long = "no-color")]
    no_color: bool,

    /// Pin a hostname to one or more fixed IPs, curl-style:
    /// "host:ip", "host:port:ip", or "host:port:ip1,ip2" (repeatable).
    /// Port is kept for curl compatibility; put non-default ports in the URL itself.
    #[arg(long = "resolve")]
    resolve: Vec<String>,

    /// Skip TLS certificate and hostname verification (self-signed / stale-cert origins)
    #[arg(short = 'k', long = "insecure")]
    insecure: bool,

    /// Skip TLS hostname verification only (still verifies certificate chain)
    #[arg(long = "no-verify-hostname")]
    no_verify_hostname: bool,

    /// Disable TLS Server Name Indication (SNI)
    #[arg(long = "no-sni", alias = "no-tls-sni")]
    no_sni: bool,

    /// Write TLS session keys to file (NSS Key Log format for Wireshark).
    /// Also respects SSLKEYLOGFILE environment variable if set.
    #[arg(long = "keylog", alias = "tls-keylog")]
    keylog: Option<String>,

    /// Override minimum TLS version to 1.0
    #[arg(long = "tlsv1.0")]
    tlsv1_0: bool,

    /// Override minimum TLS version to 1.1
    #[arg(long = "tlsv1.1")]
    tlsv1_1: bool,

    /// Override minimum TLS version to 1.2
    #[arg(long = "tlsv1.2")]
    tlsv1_2: bool,

    /// Override minimum TLS version to 1.3
    #[arg(long = "tlsv1.3")]
    tlsv1_3: bool,

    /// Explicit minimum TLS version override (1.0, 1.1, 1.2, 1.3)
    #[arg(long = "tls-min")]
    tls_min: Option<String>,

    /// Explicit maximum TLS version override (1.0, 1.1, 1.2, 1.3)
    #[arg(long = "tls-max")]
    tls_max: Option<String>,

    /// Custom CA certificate bundle (PEM) for server verification
    #[arg(long = "cacert")]
    cacert: Option<String>,

    /// Client certificate file (PEM or PKCS#12 DER) for mTLS
    #[arg(short = 'E', long = "cert")]
    cert: Option<String>,

    /// Client private key file (PKCS#8 PEM) for mTLS when --cert is PEM
    #[arg(long = "key")]
    key: Option<String>,

    /// Password for PKCS#12 client certificate (--cert)
    #[arg(long = "pass")]
    cert_pass: Option<String>,

    /// Cookie to send, e.g. "name=value" (repeatable, merged into session cookie jar)
    #[arg(short = 'c', short_alias = 'b', long = "cookie")]
    cookies: Vec<String>,

    /// Read/write persistent cookies from/to file
    #[arg(long = "cookie-jar")]
    cookie_jar: Option<String>,

    /// Disable the automatic session cookie store across redirects
    #[arg(long = "no-cookies", alias = "no-cookie-store")]
    no_cookies: bool,

    /// Proxy URL (http://, https://, socks5://, socks5h://)
    #[arg(short = 'x', long = "proxy")]
    proxy: Option<String>,

    /// Bypass proxy for comma-separated hosts, or "*" (or bare --noproxy) to disable all/system proxies
    #[arg(
        long = "noproxy",
        alias = "no-proxy",
        num_args = 0..=1,
        default_missing_value = "*"
    )]
    noproxy: Option<String>,

    /// Do not follow redirects (default: follow up to 10 hops).
    /// Short aliases -n and -f combine as -nf.
    #[arg(
        short = 'n',
        long = "nofollow",
        short_alias = 'f',
        overrides_with = "nofollow"
    )]
    nofollow: bool,

    /// Follow redirects (enabled by default; accepted for curl compatibility)
    #[arg(short = 'L', long = "location", overrides_with = "nofollow")]
    location: bool,

    /// Maximum number of redirects to follow (default: 10)
    #[arg(long = "max-redirs")]
    max_redirs: Option<usize>,

    /// Initial Referer header (automatically updated/forwarded across redirects)
    #[arg(long = "referer")]
    referer: Option<String>,

    /// Disable automatic Referer header forwarding across redirects
    #[arg(long = "no-referer")]
    no_referer: bool,

    /// Maximum total time in seconds for the whole request (curl -m / --max-time)
    #[arg(short = 'm', long = "max-time", alias = "timeout")]
    max_time: Option<f64>,

    /// Maximum time in seconds for the connection phase (DNS + TCP + TLS)
    #[arg(long = "connect-timeout")]
    connect_timeout: Option<f64>,

    /// Maximum time in seconds for reading response data
    #[arg(long = "read-timeout")]
    read_timeout: Option<f64>,

    /// Retry transient failures (transport errors, 429/502/503/504) up to N times (0 disables retries)
    #[arg(long = "retry")]
    retry: Option<u32>,

    /// Disable all automatic response decompression (return raw wire bytes)
    #[arg(long = "raw", aliases = ["no-decompress", "no-compressed"])]
    raw: bool,

    /// Disable automatic gzip decompression
    #[arg(long = "no-gzip")]
    no_gzip: bool,

    /// Disable automatic brotli decompression
    #[arg(long = "no-brotli")]
    no_brotli: bool,

    /// Disable automatic zstd decompression
    #[arg(long = "no-zstd")]
    no_zstd: bool,

    /// Disable automatic deflate decompression
    #[arg(long = "no-deflate")]
    no_deflate: bool,

    /// Force HTTP/1.1 only (overrides Chrome's default HTTP/2 negotiation)
    #[arg(long = "http1.1", aliases = ["http1", "http1-only"])]
    http1_only: bool,

    /// Force HTTP/2 only
    #[arg(long = "http2", alias = "http2-only")]
    http2_only: bool,

    /// Restrict client and redirects to HTTPS only
    #[arg(long = "https-only")]
    https_only: bool,

    /// Bind outgoing connections to a local IP address or network interface name
    #[arg(long = "interface")]
    interface: Option<String>,

    /// Bind outgoing connections to a local IP address (IPv4 or IPv6)
    #[arg(long = "local-address")]
    local_address: Option<IpAddr>,
}

fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Windows
    }
}

fn platform_name(platform: Platform) -> String {
    match platform {
        Platform::Windows => "Windows".into(),
        Platform::MacOS => "macOS".into(),
        Platform::Linux => "Linux".into(),
        _ => "host OS".into(),
    }
}

fn profile_label(profile: &Profile) -> String {
    match profile {
        Profile::Chrome154 => "Chrome 154".into(),
        Profile::Chrome137 => "Chrome 137".into(),
        Profile::Firefox136 => "Firefox 136".into(),
        Profile::Firefox152 => "Firefox 152".into(),
        Profile::Safari26 => "Safari 26".into(),
        Profile::Edge137 => "Edge 137".into(),
        Profile::Edge148 => "Edge 148".into(),
        Profile::OkHttp5 => "OkHttp 5".into(),
        _ => "custom profile".into(),
    }
}

fn select_profile(explicit: Option<&str>) -> (Profile, Platform) {
    let norm = explicit.map(|s| s.trim().to_ascii_lowercase());
    match norm.as_deref() {
        None | Some("chrome" | "default" | "etalon" | "chrome_154" | "chrome154") => {
            (Profile::Chrome154, host_platform())
        }
        Some("chrome_137" | "chrome137") => (Profile::Chrome137, host_platform()),
        Some("firefox" | "firefox_136" | "firefox136") => (Profile::Firefox136, host_platform()),
        Some("firefox_152" | "firefox152") => (Profile::Firefox152, host_platform()),
        Some("safari" | "safari_26" | "safari26") => (Profile::Safari26, Platform::MacOS),
        Some("edge" | "edge_137" | "edge137") => (Profile::Edge137, host_platform()),
        Some("edge_148" | "edge148") => (Profile::Edge148, host_platform()),
        Some("okhttp" | "okhttp_5" | "okhttp5") => (Profile::OkHttp5, Platform::Android),
        Some(_) => (Profile::Chrome154, host_platform()),
    }
}

fn resolve_emulation(explicit: Option<&str>) -> Emulation {
    let (profile, platform) = select_profile(explicit);

    Emulation::builder()
        .profile(profile)
        .platform(platform)
        .build()
}

fn colors_enabled(no_color_flag: bool) -> bool {
    !no_color_flag && std::env::var_os("NO_COLOR").is_none()
}

/// Format HTTP status line with an inverted ANSI color badge on the status code digits:
/// - 2xx (200..=299) -> Green background, black bold text (`\x1b[1;30;42m 200 \x1b[0m`)
/// - 1xx / 3xx (100..=199, 300..=399) -> Yellow background, black bold text (`\x1b[1;30;43m 302 \x1b[0m`)
/// - 4xx / 5xx (400..=599) -> Red background, black bold text (`\x1b[1;30;41m 404 \x1b[0m`)
fn format_status_line(version: wreq::Version, status: wreq::StatusCode, use_color: bool) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("");
    if !use_color {
        return if reason.is_empty() {
            format!("{version:?} {code}")
        } else {
            format!("{version:?} {code} {reason}")
        };
    }

    let badge_ansi = match code {
        200..=299 => "\x1b[1;30;42m",
        100..=199 | 300..=399 => "\x1b[1;30;43m",
        _ => "\x1b[1;30;41m",
    };

    if reason.is_empty() {
        format!("{version:?} {badge_ansi} {code} \x1b[0m")
    } else {
        format!("{version:?} {badge_ansi} {code} \x1b[0m {reason}")
    }
}

/// Format CLI error message with an inverted ANSI badge:
/// - Yellow (`CERT`) for TLS/certificate verification issues
/// - Red (`ERR`) for transport, timeout, or argument errors
fn format_error_line(msg: &str, use_color: bool) -> String {
    if !use_color {
        return format!("wreq: {msg}");
    }
    let lower = msg.to_ascii_lowercase();
    let is_cert = lower.contains("certificate")
        || lower.contains("cert")
        || lower.contains("unknown issuer")
        || lower.contains("self signed")
        || lower.contains("self-signed")
        || lower.contains("hostname mismatch");
    if is_cert {
        format!("wreq: \x1b[1;30;43m CERT \x1b[0m {msg}")
    } else {
        format!("wreq: \x1b[1;30;41m ERR \x1b[0m {msg}")
    }
}

fn banner(args: &Args, profile: &Profile, platform: Platform) {
    let name = profile_label(profile);
    let source = match (&args.emulation, name.as_str()) {
        (None, _) => "default",
        (Some(e), "custom profile") => e.as_str(),
        (Some(_), _) => "-e override",
    };
    println!(
        "wreq {} — stealth HTTP client (browser TLS & HTTP/2 impersonation)",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!(
        "  Active fingerprint : {} on {}   [{}]",
        name,
        platform_name(platform),
        source
    );
    println!("  Default behavior   : Acts identically to real Chrome on this OS.");
    println!("                       Sends full Chrome headers & header order (User-Agent,");
    println!("                       Sec-CH-UA*, Sec-Fetch-*, Accept*, etc.), Chrome TLS");
    println!("                       ClientHello (with Chromium Trust Anchor IDs), and HTTP/2");
    println!("                       frames. Follows redirects and persists session cookies.");
    println!("  Overrides          : Do not pass -e on Windows — Chrome is already active.");
    println!("                       Flags like -A, -H, --http1.1, --tlsv1.2, --raw, -nf");
    println!("                       override the corresponding Chrome default only when");
    println!("                       passed explicitly.");
    println!();
    println!("  Usage: wreq [OPTIONS] <URL>      Help: wreq --help");
}

fn parse_ip_list(ips_str: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for raw in ips_str.split(',') {
        let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
        if trimmed.is_empty() {
            return None;
        }
        let ip: IpAddr = trimmed.parse().ok()?;
        addrs.push(SocketAddr::new(ip, port));
    }
    if addrs.is_empty() {
        None
    } else {
        Some(addrs)
    }
}

/// Parse `--resolve` specification:
/// - `host:ip1[,ip2...]` (defaults port to 443)
/// - `host:port:ip1[,ip2...]`
fn parse_resolve(spec: &str) -> Option<(String, Vec<SocketAddr>)> {
    let (host, rest) = spec.split_once(':')?;
    if host.is_empty() || rest.is_empty() {
        return None;
    }

    if let Some((port_str, ips_str)) = rest.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            if let Some(addrs) = parse_ip_list(ips_str, port) {
                return Some((host.to_string(), addrs));
            }
        }
    }

    let addrs = parse_ip_list(rest, 443)?;
    Some((host.to_string(), addrs))
}

fn parse_tls_version(ver: &str) -> Option<TlsVersion> {
    match ver.trim().trim_start_matches("TLSv").trim_start_matches("tlsv") {
        "1.0" | "1" => Some(TlsVersion::TLS_1_0),
        "1.1" => Some(TlsVersion::TLS_1_1),
        "1.2" => Some(TlsVersion::TLS_1_2),
        "1.3" => Some(TlsVersion::TLS_1_3),
        _ => None,
    }
}

fn resolve_min_tls_version(args: &Args) -> Result<Option<TlsVersion>, String> {
    if let Some(ref s) = args.tls_min {
        let v = parse_tls_version(s).ok_or_else(|| {
            format!("invalid --tls-min '{s}', expected 1.0, 1.1, 1.2, or 1.3")
        })?;
        return Ok(Some(v));
    }
    if args.tlsv1_3 {
        Ok(Some(TlsVersion::TLS_1_3))
    } else if args.tlsv1_2 {
        Ok(Some(TlsVersion::TLS_1_2))
    } else if args.tlsv1_1 {
        Ok(Some(TlsVersion::TLS_1_1))
    } else if args.tlsv1_0 {
        Ok(Some(TlsVersion::TLS_1_0))
    } else {
        Ok(None)
    }
}

fn parse_duration_secs(flag: &str, secs: f64) -> Result<Duration, String> {
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("invalid {flag} '{secs}', must be a positive number of seconds"));
    }
    Duration::try_from_secs_f64(secs)
        .map_err(|_| format!("invalid {flag} '{secs}', out of range"))
}

fn guess_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => "application/json",
        Some("txt" | "log") => "text/plain",
        Some("html" | "htm") => "text/html",
        Some("csv") => "text/csv",
        Some("xml") => "application/xml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz" | "tgz") => "application/gzip",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

/// Build a `wreq::multipart::Form` from curl-style `-F / --form` specifications:
/// - `name=value[;type=mime]`
/// - `name=@filepath[;type=mime][;filename=custom.ext]`
fn build_multipart_form(specs: &[String]) -> Result<MultipartForm, Box<dyn std::error::Error>> {
    let mut form = MultipartForm::new();
    for spec in specs {
        let Some((name, rest)) = spec.split_once('=') else {
            return Err(format!("invalid --form '{spec}', expected name=value or name=@file").into());
        };
        if name.is_empty() {
            return Err(format!("invalid --form '{spec}', field name cannot be empty").into());
        }

        let mut segments = rest.split(';');
        let primary = segments.next().unwrap_or("");
        let mut explicit_mime: Option<&str> = None;
        let mut explicit_filename: Option<&str> = None;
        for param in segments {
            let param = param.trim();
            if let Some(t) = param.strip_prefix("type=") {
                explicit_mime = Some(t.trim());
            } else if let Some(f) = param.strip_prefix("filename=") {
                explicit_filename = Some(f.trim().trim_matches('"'));
            }
        }

        if let Some(file_path_str) = primary.strip_prefix('@') {
            let path = Path::new(file_path_str);
            let bytes = fs::read(path)
                .map_err(|e| format!("cannot read --form file '{file_path_str}': {e}"))?;
            let filename = explicit_filename
                .map(str::to_string)
                .or_else(|| {
                    path.file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "file".to_string());
            let mime = explicit_mime.unwrap_or_else(|| guess_mime(path));
            let part = MultipartPart::bytes(bytes)
                .file_name(filename)
                .mime_str(mime)
                .map_err(|e| fail(&format!("invalid MIME '{mime}' in --form '{spec}'"), &e))?;
            form = form.part(name.to_string(), part);
        } else {
            let mut part = MultipartPart::text(primary.to_string());
            if let Some(mime) = explicit_mime {
                part = part
                    .mime_str(mime)
                    .map_err(|e| fail(&format!("invalid MIME '{mime}' in --form '{spec}'"), &e))?;
            }
            form = form.part(name.to_string(), part);
        }
    }
    Ok(form)
}

/// Add CLI `-c / -b / --cookie` string to `Jar`.
/// Handles both multiple pairs (`"a=1; b=2"`) and full Set-Cookie strings (`"sid=123; Path=/; Secure"`).
fn add_cli_cookie(jar: &Jar, raw: &str, url: &str) {
    let mut parts = raw.split(';').map(str::trim).filter(|s| !s.is_empty());
    let Some(first) = parts.next() else {
        return;
    };
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        jar.add(format!("{first}; Path=/"), url);
        return;
    }

    let has_cookie_attr = rest.iter().any(|seg| {
        let key = seg.split_once('=').map(|(k, _)| k.trim()).unwrap_or(*seg);
        matches!(
            key.to_ascii_lowercase().as_str(),
            "path" | "domain" | "max-age" | "expires" | "samesite" | "secure" | "httponly" | "partitioned"
        )
    });

    if has_cookie_attr {
        let has_path = rest.iter().any(|seg| {
            seg.split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("path"))
        });
        if has_path {
            jar.add(raw, url);
        } else {
            jar.add(format!("{raw}; Path=/"), url);
        }
    } else {
        for pair in std::iter::once(first).chain(rest) {
            jar.add(format!("{pair}; Path=/"), url);
        }
    }
}

/// Parse `--data-urlencode` items:
/// - `name=value`
/// - `=value` (empty key)
/// - `name@file` (reads file content as value)
/// - `value` (empty key)
fn parse_urlencoded_items(
    specs: &[String],
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut pairs = Vec::with_capacity(specs.len());
    for spec in specs {
        if let Some((name, val)) = spec.split_once('=') {
            pairs.push((name.to_string(), val.to_string()));
        } else if let Some((name, file_path)) = spec.split_once('@') {
            let content = fs::read_to_string(file_path)
                .map_err(|e| format!("cannot read --data-urlencode file '{file_path}': {e}"))?;
            pairs.push((name.to_string(), content));
        } else {
            pairs.push((String::new(), spec.clone()));
        }
    }
    Ok(pairs)
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let use_color = colors_enabled(args.no_color);
    match run(args, use_color) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "{}",
                format_error_line(&e.to_string(), use_color)
            );
            std::process::ExitCode::FAILURE
        }
    }
}

/// One-line cause chain (Display only, no Debug internals).
fn err_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        let p = s.to_string();
        if !parts.contains(&p) {
            parts.push(p);
        }
        src = s.source();
    }
    parts.join(": ")
}

/// Attach a short "what failed" context to an error.
fn fail(what: &str, e: &(dyn std::error::Error + 'static)) -> Box<dyn std::error::Error> {
    format!("{what}: {}", err_chain(e)).into()
}

#[tokio::main(flavor = "current_thread")]
async fn run(args: Args, use_color: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut emulation = resolve_emulation(args.emulation.as_deref()).into_emulation();

    let Some(mut url) = args.url.clone() else {
        let (profile, platform) = select_profile(args.emulation.as_deref());
        banner(&args, &profile, platform);
        return Ok(());
    };

    // Default the scheme: https normally, http with -k (unless --https-only).
    if !url.contains("://") {
        url = if args.insecure && !args.https_only {
            format!("http://{url}")
        } else {
            format!("https://{url}")
        };
    }

    let min_tls = resolve_min_tls_version(&args)?;
    let max_tls = match &args.tls_max {
        Some(s) => Some(parse_tls_version(s).ok_or_else(|| {
            format!("invalid --tls-max '{s}', expected 1.0, 1.1, 1.2, or 1.3")
        })?),
        None => None,
    };

    // Emulation's TlsOptions min/max takes priority over ClientBuilder::tls_min/max_version,
    // so update both when the user explicitly requests a TLS version boundary.
    if let Some(ref mut tls_opts) = emulation.tls_options {
        if let Some(v) = min_tls {
            tls_opts.min_tls_version = Some(v);
        }
        if let Some(v) = max_tls {
            tls_opts.max_tls_version = Some(v);
        }
    }

    let mut builder = Client::builder().emulation(emulation);

    if let Some(ref ua) = args.user_agent {
        builder = builder.user_agent(ua.as_str());
    }

    if args.insecure {
        builder = builder
            .tls_cert_verification(false)
            .tls_verify_hostname(false);
    } else if args.no_verify_hostname {
        builder = builder.tls_verify_hostname(false);
    }

    if args.no_sni {
        builder = builder.tls_sni(false);
    }

    if let Some(v) = min_tls {
        builder = builder.tls_min_version(v);
    }
    if let Some(v) = max_tls {
        builder = builder.tls_max_version(v);
    }

    if let Some(ref path) = args.keylog {
        builder = builder.tls_keylog(KeyLog::from_file(path));
    } else if std::env::var_os("SSLKEYLOGFILE").is_some_and(|v| !v.is_empty()) {
        builder = builder.tls_keylog(KeyLog::from_env());
    }

    if let Some(ref ca_path) = args.cacert {
        let pem = fs::read(ca_path)
            .map_err(|e| format!("cannot read --cacert '{ca_path}': {e}"))?;
        let store = CertStore::from_pem_stack(&pem)
            .map_err(|e| fail(&format!("invalid --cacert '{ca_path}'"), &e))?;
        builder = builder.tls_cert_store(store);
    }

    if let Some(ref cert_path) = args.cert {
        let cert_bytes = fs::read(cert_path)
            .map_err(|e| format!("cannot read --cert '{cert_path}': {e}"))?;
        let identity = if let Some(ref key_path) = args.key {
            let key_bytes = fs::read(key_path)
                .map_err(|e| format!("cannot read --key '{key_path}': {e}"))?;
            Identity::from_pkcs8_pem(&cert_bytes, &key_bytes)
                .map_err(|e| fail("invalid PEM client identity (--cert/--key)", &e))?
        } else {
            let pass = args.cert_pass.as_deref().unwrap_or("");
            Identity::from_pkcs12_der(&cert_bytes, pass)
                .map_err(|e| fail("invalid PKCS#12 client identity (--cert)", &e))?
        };
        builder = builder.tls_identity(identity);
    }

    // Group --resolve overrides by host so multiple flags or comma-separated IPs
    // all feed into resolve_to_addrs without overwriting earlier entries.
    let mut resolve_map: Vec<(String, Vec<SocketAddr>)> = Vec::new();
    for spec in &args.resolve {
        match parse_resolve(spec) {
            Some((host, addrs)) => {
                if let Some((_, existing)) = resolve_map
                    .iter_mut()
                    .find(|(h, _)| h.eq_ignore_ascii_case(&host))
                {
                    existing.extend(addrs);
                } else {
                    resolve_map.push((host, addrs));
                }
            }
            None => {
                return Err(format!(
                    "invalid --resolve '{spec}', expected host:ip, host:port:ip, or host:port:ip1,ip2"
                )
                .into());
            }
        }
    }
    for (host, addrs) in resolve_map {
        builder = builder.resolve_to_addrs(host, addrs);
    }

    // Proxy & no_proxy handling
    let disable_all_proxies = matches!(args.noproxy.as_deref(), Some("*" | ""));
    if disable_all_proxies {
        builder = builder.no_proxy();
    } else if let Some(ref proxy_url) = args.proxy {
        let mut proxy = Proxy::all(proxy_url.as_str())
            .map_err(|e| format!("invalid --proxy '{proxy_url}': {e}"))?;
        if let Some(ref no_proxy_list) = args.noproxy {
            proxy = proxy.no_proxy(NoProxy::from_string(no_proxy_list));
        }
        builder = builder.proxy(proxy);
    } else if let Some(ref no_proxy_list) = args.noproxy {
        // Let wreq's system/env proxy matcher pick up the host exclusion list.
        std::env::set_var("NO_PROXY", no_proxy_list);
        std::env::set_var("no_proxy", no_proxy_list);
    }

    // Redirect policy & Referer forwarding
    let redirect_policy = if args.nofollow && !args.location {
        RedirectPolicy::none()
    } else {
        match args.max_redirs {
            Some(0) => RedirectPolicy::none(),
            Some(n) => RedirectPolicy::limited(n),
            None => RedirectPolicy::limited(10),
        }
    };
    builder = builder
        .redirect(redirect_policy)
        .referer(!args.no_referer);

    // Timeouts
    if let Some(secs) = args.max_time {
        builder = builder.timeout(parse_duration_secs("--max-time", secs)?);
    }
    if let Some(secs) = args.connect_timeout {
        builder = builder.connect_timeout(parse_duration_secs("--connect-timeout", secs)?);
    }
    if let Some(secs) = args.read_timeout {
        builder = builder.read_timeout(parse_duration_secs("--read-timeout", secs)?);
    }

    // Retries
    if let Some(max_retries) = args.retry {
        let policy = if max_retries == 0 {
            RetryPolicy::never()
        } else {
            RetryPolicy::default()
                .max_retries_per_request(max_retries)
                .no_budget()
                .classify_fn(|req_rep| {
                    if req_rep.error().is_some() {
                        return req_rep.retryable();
                    }
                    if let Some(status) = req_rep.status() {
                        if matches!(status.as_u16(), 429 | 502 | 503 | 504) {
                            return req_rep.retryable();
                        }
                    }
                    req_rep.success()
                })
        };
        builder = builder.retry(policy);
    }

    // Decompression toggles
    if args.raw {
        builder = builder.no_gzip().no_brotli().no_zstd().no_deflate();
    } else {
        if args.no_gzip {
            builder = builder.no_gzip();
        }
        if args.no_brotli {
            builder = builder.no_brotli();
        }
        if args.no_zstd {
            builder = builder.no_zstd();
        }
        if args.no_deflate {
            builder = builder.no_deflate();
        }
    }

    // HTTP version & HTTPS-only enforcement
    if args.http1_only && args.http2_only {
        return Err("cannot combine --http1.1 and --http2".into());
    }
    if args.http1_only {
        builder = builder.http1_only();
    } else if args.http2_only {
        builder = builder.http2_only();
    }
    if args.https_only {
        builder = builder.https_only(true);
    }

    // Local address / interface binding
    if let Some(ip) = args.local_address {
        builder = builder.local_address(ip);
    }
    if let Some(ref iface) = args.interface {
        if let Ok(ip) = iface.parse::<IpAddr>() {
            builder = builder.local_address(ip);
        } else {
            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "solaris",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos",
            ))]
            {
                builder = builder.interface(iface.clone());
            }
            #[cfg(not(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "solaris",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos",
            )))]
            {
                return Err(format!(
                    "--interface '{iface}' on Windows requires a local IP address (e.g. --interface 192.168.1.10)"
                )
                .into());
            }
        }
    }

    // Session cookie jar (enabled by default so Set-Cookie persists across redirect hops)
    let jar = if !args.no_cookies {
        let jar = Arc::new(Jar::default());
        if let Some(ref jar_path) = args.cookie_jar {
            if let Ok(contents) = fs::read_to_string(jar_path) {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((uri_part, cookie_part)) = line.split_once('\t') {
                        jar.add(cookie_part.trim(), uri_part.trim());
                    } else {
                        jar.add(line, url.as_str());
                    }
                }
            }
        }
        for c in &args.cookies {
            add_cli_cookie(&jar, c, url.as_str());
        }
        builder = builder.cookie_provider(jar.clone());
        Some(jar)
    } else {
        builder = builder.cookie_store(false);
        None
    };

    let client = builder
        .build()
        .map_err(|e| fail("client build failed", &e))?;

    let has_body_payload = args.data.is_some()
        || args.json.is_some()
        || !args.form.is_empty()
        || !args.data_urlencode.is_empty();
    let method = args
        .method
        .as_deref()
        .unwrap_or(if has_body_payload { "POST" } else { "GET" });

    let mut req = match method.to_uppercase().as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        "PATCH" => client.patch(&url),
        "OPTIONS" => client.options(&url),
        _ => client.get(&url),
    };

    if let Some(ref referer) = args.referer {
        req = req.header("Referer", referer.as_str());
    }

    for h in args.headers {
        if let Some((k, v)) = h.split_once(':') {
            req = req.header(k.trim(), v.trim());
        }
    }

    // If cookie jar is disabled (or could not parse custom cookies), send Cookie header directly.
    if !args.cookies.is_empty() && jar.as_ref().is_none_or(|j| j.is_empty()) {
        req = req.header("Cookie", args.cookies.join("; "));
    }

    // Body handling: -F (multipart), --json (application/json), --data-urlencode (form), or -d (raw)
    if !args.form.is_empty() {
        let multipart = build_multipart_form(&args.form)?;
        req = req.multipart(multipart);
    } else if let Some(ref json_spec) = args.json {
        let raw_json = if let Some(file_path) = json_spec.strip_prefix('@') {
            fs::read_to_string(file_path)
                .map_err(|e| format!("cannot read --json file '{file_path}': {e}"))?
        } else {
            json_spec.clone()
        };
        req = req
            .header("Content-Type", "application/json")
            .body(raw_json);
    } else if !args.data_urlencode.is_empty() {
        let pairs = parse_urlencoded_items(&args.data_urlencode)?;
        req = req.form(&pairs);
    } else if let Some(body) = args.data {
        req = req.body(body);
    }

    let resp = req.send().await.map_err(|e| fail("request failed", &e))?;

    if let (Some(ref jar_path), Some(ref jar)) = (&args.cookie_jar, &jar) {
        let mut out = String::new();
        for c in jar.get_all() {
            if let Some(host) = c.host() {
                let scheme = if c.secure() { "https" } else { "http" };
                let path = c.path().unwrap_or("/");
                out.push_str(&format!("{scheme}://{host}{path}\t{c}\n"));
            }
        }
        fs::write(jar_path, out)
            .map_err(|e| format!("cannot write --cookie-jar '{jar_path}': {e}"))?;
    }

    let status = resp.status();
    let version = resp.version();
    let headers = resp.headers().clone();

    if args.head_only || args.include_headers {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{}", format_status_line(version, status, use_color));
        for (k, v) in headers.iter() {
            let _ = writeln!(stderr, "{}: {}", k, v.to_str().unwrap_or(""));
        }
        if args.head_only {
            return Ok(());
        }
        let _ = writeln!(stderr);
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| fail("read body failed", &e))?;

    if let Some(out_path) = args.output {
        let mut file =
            File::create(&out_path).map_err(|e| format!("cannot create '{out_path}': {e}"))?;
        file.write_all(&bytes)
            .map_err(|e| format!("cannot write '{out_path}': {e}"))?;
        let _ = writeln!(std::io::stderr(), "Saved to {}", out_path);
    } else if let Err(e) = std::io::stdout().write_all(&bytes) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(fail("write to stdout failed", &e));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolve_single_and_multi_ip() {
        let (host, addrs) = parse_resolve("example.com:1.1.1.1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(addrs, vec!["1.1.1.1:443".parse().unwrap()]);

        let (host, addrs) = parse_resolve("example.com:8443:1.1.1.1,1.0.0.1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(
            addrs,
            vec![
                "1.1.1.1:8443".parse().unwrap(),
                "1.0.0.1:8443".parse().unwrap()
            ]
        );

        let (host, addrs) = parse_resolve("example.com:443:[2606:4700::1],1.1.1.1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(
            addrs,
            vec![
                "[2606:4700::1]:443".parse().unwrap(),
                "1.1.1.1:443".parse().unwrap()
            ]
        );

        assert!(parse_resolve("invalid").is_none());
        assert!(parse_resolve("example.com:").is_none());
        assert!(parse_resolve(":1.1.1.1").is_none());
    }

    #[test]
    fn test_parse_tls_version() {
        assert_eq!(parse_tls_version("1.0"), Some(TlsVersion::TLS_1_0));
        assert_eq!(parse_tls_version("1.1"), Some(TlsVersion::TLS_1_1));
        assert_eq!(parse_tls_version("1.2"), Some(TlsVersion::TLS_1_2));
        assert_eq!(parse_tls_version("1.3"), Some(TlsVersion::TLS_1_3));
        assert_eq!(parse_tls_version("TLSv1.2"), Some(TlsVersion::TLS_1_2));
        assert_eq!(parse_tls_version("1.4"), None);
    }

    #[test]
    fn test_status_and_error_ansi_badges() {
        let ok_line = format_status_line(wreq::Version::HTTP_2, wreq::StatusCode::OK, true);
        assert!(ok_line.contains("\x1b[1;30;42m 200 \x1b[0m OK"));

        let redir_line = format_status_line(wreq::Version::HTTP_2, wreq::StatusCode::FOUND, true);
        assert!(redir_line.contains("\x1b[1;30;43m 302 \x1b[0m Found"));

        let err_line = format_status_line(wreq::Version::HTTP_2, wreq::StatusCode::FORBIDDEN, true);
        assert!(err_line.contains("\x1b[1;30;41m 403 \x1b[0m Forbidden"));

        let plain_line = format_status_line(wreq::Version::HTTP_2, wreq::StatusCode::OK, false);
        assert_eq!(plain_line, "HTTP/2.0 200 OK");

        let cert_err = format_error_line("request failed: certificate verify failed", true);
        assert!(cert_err.contains("\x1b[1;30;43m CERT \x1b[0m"));

        let net_err = format_error_line("request failed: connection refused", true);
        assert!(net_err.contains("\x1b[1;30;41m ERR \x1b[0m"));
    }

    #[test]
    fn test_add_cli_cookie_pairs_and_attributes() {
        let jar = Jar::default();
        add_cli_cookie(&jar, "a=1; b=2", "https://example.com/path");
        add_cli_cookie(&jar, "sid=xyz; Path=/; Secure; HttpOnly", "https://example.com/path");
        assert_eq!(jar.len(), 3);
        assert!(jar.contains("a", "https://example.com/"));
        assert!(jar.contains("b", "https://example.com/"));
        assert!(jar.contains("sid", "https://example.com/"));
    }

    #[test]
    fn test_multipart_and_urlencoded_builders() {
        let form = build_multipart_form(&[
            "field1=val1".to_string(),
            "json={\"a\":1};type=application/json".to_string(),
        ])
        .unwrap();
        assert!(form.boundary().starts_with("----WebKitFormBoundary"));

        let pairs = parse_urlencoded_items(&[
            "key=hello world".to_string(),
            "=raw_val".to_string(),
        ])
        .unwrap();
        assert_eq!(
            pairs,
            vec![
                ("key".to_string(), "hello world".to_string()),
                ("".to_string(), "raw_val".to_string())
            ]
        );
    }

    #[test]
    fn test_clap_curl_flags_parsing() {
        let args = Args::try_parse_from([
            "wreq",
            "-L",
            "--max-redirs",
            "5",
            "-m",
            "10.5",
            "--connect-timeout",
            "3",
            "--retry",
            "2",
            "-A",
            "CustomUA/1.0",
            "--referer",
            "https://google.com",
            "--http1.1",
            "--https-only",
            "--tlsv1.2",
            "--tls-max",
            "1.3",
            "--no-sni",
            "--raw",
            "--noproxy",
            "-b",
            "sid=123",
            "-F",
            "a=b",
            "--data-urlencode",
            "k=v",
            "--json",
            "{\"ok\":true}",
            "--resolve",
            "example.com:443:1.1.1.1,1.0.0.1",
            "--local-address",
            "127.0.0.1",
            "https://example.com",
        ])
        .unwrap();

        assert!(args.location);
        assert_eq!(args.max_redirs, Some(5));
        assert_eq!(args.max_time, Some(10.5));
        assert_eq!(args.connect_timeout, Some(3.0));
        assert_eq!(args.retry, Some(2));
        assert_eq!(args.user_agent.as_deref(), Some("CustomUA/1.0"));
        assert_eq!(args.referer.as_deref(), Some("https://google.com"));
        assert!(args.http1_only);
        assert!(args.https_only);
        assert!(args.tlsv1_2);
        assert_eq!(args.tls_max.as_deref(), Some("1.3"));
        assert!(args.no_sni);
        assert!(args.raw);
        assert_eq!(args.noproxy.as_deref(), Some("*"));
        assert_eq!(args.cookies, vec!["sid=123"]);
        assert_eq!(args.form, vec!["a=b"]);
        assert_eq!(args.data_urlencode, vec!["k=v"]);
        assert_eq!(args.json.as_deref(), Some("{\"ok\":true}"));
        assert_eq!(
            args.local_address,
            Some("127.0.0.1".parse::<IpAddr>().unwrap())
        );
    }
}
