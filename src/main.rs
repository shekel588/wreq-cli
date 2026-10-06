use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use wreq::Client;
use wreq_util::{Emulation, Platform, Profile};

#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum BrowserTarget {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum OsTarget {
    Auto,
    Windows,
    Macos,
    Linux,
    Android,
    Ios,
}

#[derive(Deserialize, Default, Debug)]
struct Config {
    browser: Option<BrowserTarget>,
    os: Option<OsTarget>,
}

#[derive(Parser, Debug)]
#[command(name = "wreq", about = "Fast stealth HTTP client with host OS matching & browser TLS/HTTP2 impersonation")]
struct Args {
    /// URL to fetch
    #[arg(required = true)]
    url: String,

    /// HTTP method (GET, POST, PUT, DELETE, HEAD)
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Browser to impersonate: chrome, firefox, safari, edge
    #[arg(short = 'b', long = "browser", value_enum)]
    browser: Option<BrowserTarget>,

    /// Target OS fingerprint: auto, windows, macos, linux, android, ios (default: auto = host OS)
    #[arg(long = "os", value_enum)]
    os: Option<OsTarget>,

    /// Path to custom config file (default: ~/.wreq.toml or ./wreq.toml)
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

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
    #[arg(short = 'i', long = "include")]
    include_headers: bool,
}

fn load_config(custom_path: Option<&Path>) -> Config {
    let candidates = if let Some(p) = custom_path {
        vec![p.to_path_buf()]
    } else {
        let mut list = vec![PathBuf::from("wreq.toml")];
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            list.push(PathBuf::from(&home).join(".wreq.toml"));
            list.push(PathBuf::from(&home).join(".config").join("wreq").join("config.toml"));
        }
        list
    };

    for path in candidates {
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return cfg;
                }
            }
        }
    }

    Config::default()
}

fn detect_host_os() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "ios") {
        Platform::IOS
    } else {
        Platform::Windows
    }
}

fn resolve_platform(os: Option<OsTarget>, config_os: Option<OsTarget>) -> Platform {
    match os.or(config_os).unwrap_or(OsTarget::Auto) {
        OsTarget::Auto => detect_host_os(),
        OsTarget::Windows => Platform::Windows,
        OsTarget::Macos => Platform::MacOS,
        OsTarget::Linux => Platform::Linux,
        OsTarget::Android => Platform::Android,
        OsTarget::Ios => Platform::IOS,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref());

    let browser = args.browser.or(config.browser).unwrap_or(BrowserTarget::Chrome);
    let platform = resolve_platform(args.os, config.os);

    let profile = match browser {
        BrowserTarget::Chrome => Profile::Chrome137,
        BrowserTarget::Firefox => Profile::Firefox136,
        BrowserTarget::Safari => Profile::Safari26,
        BrowserTarget::Edge => Profile::Edge137,
    };

    let emulation = Emulation::builder()
        .profile(profile)
        .platform(platform)
        .build();

    let client = Client::builder()
        .emulation(emulation)
        .build()?;

    let mut req = match args.method.to_uppercase().as_str() {
        "POST" => client.post(&args.url),
        "PUT" => client.put(&args.url),
        "DELETE" => client.delete(&args.url),
        "HEAD" => client.head(&args.url),
        _ => client.get(&args.url),
    };

    for h in args.headers {
        if let Some((k, v)) = h.split_once(':') {
            req = req.header(k.trim(), v.trim());
        }
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
