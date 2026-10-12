use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use wreq::redirect::Policy;
use wreq::{Client, Proxy};
use wreq_util::{Emulation, Platform, Profile};

#[derive(Parser, Debug)]
#[command(name = "wreq", version, about = "Fast stealth HTTP client with browser TLS & HTTP/2 impersonation")]
struct Args {
    /// URL to fetch (omit to print the active fingerprint banner)
    url: Option<String>,

    /// HTTP method (GET, POST, PUT, DELETE, HEAD)
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Fingerprint override (e.g. chrome, chrome_154, chrome_137, firefox, safari, edge)
    /// Default: Chrome 154 matching host OS
    #[arg(short = 'e', long = "emulation", alias = "impersonate", short_alias = 'i')]
    emulation: Option<String>,

    /// Add custom header (e.g. -H "Authorization: Bearer xxx")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Request body string (for POST/PUT)
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// Save response body to file instead of stdout
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Print response headers only
    #[arg(short = 'I', long = "head")]
    head_only: bool,

    /// Print response status and headers alongside body
    #[arg(short = 'v', long = "verbose", alias = "include")]
    include_headers: bool,

    /// Pin a hostname to a fixed IP, curl-style: "host:ip" or "host:port:ip" (repeatable).
    /// Port is kept for curl compatibility but ignored by the resolver — put the
    /// port in the URL itself instead.
    #[arg(long = "resolve")]
    resolve: Vec<String>,

    /// Skip TLS certificate verification (self-signed / stale-certs origins)
    #[arg(short = 'k', long = "insecure")]
    insecure: bool,

    /// Cookie to send, e.g. "name=value" (repeatable, joined with "; ")
    #[arg(short = 'c', long = "cookie")]
    cookies: Vec<String>,

    /// Proxy URL (http://, https://, socks5://, socks5h://)
    #[arg(short = 'x', long = "proxy")]
    proxy: Option<String>,

    /// Do not follow redirects (default: follow up to 10 hops).
    /// Short aliases -n and -f combine as -nf.
    #[arg(short = 'n', long = "nofollow", short_alias = 'f')]
    nofollow: bool,
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
        Profile::Safari26 => "Safari 26".into(),
        Profile::Edge137 => "Edge 137".into(),
        _ => "custom profile".into(),
    }
}

fn select_profile(explicit: Option<&str>) -> (Profile, Platform) {
    match explicit {
        None | Some("chrome" | "default" | "etalon" | "chrome_154") => {
            (Profile::Chrome154, host_platform())
        }
        Some("chrome_137") => (Profile::Chrome137, host_platform()),
        Some("firefox") => (Profile::Firefox136, host_platform()),
        Some("safari") => (Profile::Safari26, Platform::MacOS),
        Some("edge") => (Profile::Edge137, host_platform()),
        Some(custom) => {
            let p = serde_json::from_str::<Profile>(&format!("\"{}\"", custom))
                .or_else(|_| serde_json::from_str::<Profile>(&format!("\"{}\"", custom.to_lowercase())))
                .unwrap_or(Profile::Chrome154);
            (p, host_platform())
        }
    }
}

fn resolve_emulation(explicit: Option<&str>) -> Emulation {
    let (profile, platform) = select_profile(explicit);

    Emulation::builder()
        .profile(profile)
        .platform(platform)
        .build()
}

fn banner(args: &Args, profile: &Profile, platform: Platform) {
    let name = profile_label(profile);
    let source = match (&args.emulation, name.as_str()) {
        (None, _) => "default",
        (Some(e), "custom profile") => e.as_str(),
        (Some(_), _) => "-e override",
    };
    println!("wreq {} — stealth HTTP client (browser TLS & HTTP/2 impersonation)", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  Active fingerprint : {} on {}   [{}]", name, platform_name(platform), source);
    println!("  Override with      : -e chrome_154 | chrome_137 | firefox | safari | edge");
    println!();
    println!("  Usage: wreq [OPTIONS] <URL>");
    println!("  Help : wreq --help");
}

fn parse_resolve(spec: &str) -> Option<(String, SocketAddr)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [host, ip] => {
            let ip: IpAddr = ip.parse().ok()?;
            Some(((*host).to_string(), SocketAddr::new(ip, 443)))
        }
        [host, port, ip] => {
            let port: u16 = port.parse().ok()?;
            let ip: IpAddr = ip.parse().ok()?;
            Some(((*host).to_string(), SocketAddr::new(ip, port)))
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let emulation = resolve_emulation(args.emulation.as_deref());

    let Some(url) = args.url.clone() else {
        let (profile, platform) = select_profile(args.emulation.as_deref());
        banner(&args, &profile, platform);
        return Ok(());
    };

    let mut builder = Client::builder().emulation(emulation);

    if args.insecure {
        builder = builder
            .tls_cert_verification(false)
            .tls_verify_hostname(false);
    }

    for spec in &args.resolve {
        match parse_resolve(spec) {
            Some((host, addr)) => {
                builder = builder.resolve(host, addr);
            }
            None => {
                return Err(format!("invalid --resolve '{spec}', expected host:ip or host:port:ip").into());
            }
        }
    }

    if let Some(proxy_url) = &args.proxy {
        let proxy = Proxy::all(proxy_url.as_str())
            .map_err(|e| format!("invalid --proxy '{proxy_url}': {e}"))?;
        builder = builder.proxy(proxy);
    }

    builder = builder.redirect(if args.nofollow {
        Policy::none()
    } else {
        Policy::limited(10)
    });

    let client = builder.build()?;

    let mut req = match args.method.to_uppercase().as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        _ => client.get(&url),
    };

    for h in args.headers {
        if let Some((k, v)) = h.split_once(':') {
            req = req.header(k.trim(), v.trim());
        }
    }

    if !args.cookies.is_empty() {
        req = req.header("Cookie", args.cookies.join("; "));
    }

    if let Some(body) = args.data {
        req = req.body(body);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let version = resp.version();
    let headers = resp.headers().clone();

    if args.head_only || args.include_headers {
        eprintln!("{:?} {}", version, status);
        for (k, v) in headers.iter() {
            eprintln!("{}: {}", k, v.to_str().unwrap_or(""));
        }
        if args.head_only {
            return Ok(());
        }
        eprintln!();
    }

    let bytes = resp.bytes().await?;

    if let Some(out_path) = args.output {
        let mut file = File::create(&out_path)?;
        file.write_all(&bytes)?;
        eprintln!("Saved to {}", out_path);
    } else {
        std::io::stdout().write_all(&bytes)?;
    }

    Ok(())
}
