use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use wreq::Client;
use wreq_util::{Emulation, Platform, Profile};

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
    emulation: Option<String>,
    os: Option<OsTarget>,
}

#[derive(Parser, Debug)]
#[command(name = "wreq", about = "Fast stealth HTTP client with browser TLS/HTTP2 impersonation")]
struct Args {
    /// URL to fetch
    #[arg(required = true)]
    url: String,

    /// HTTP method (GET, POST, PUT, DELETE, HEAD)
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Explicit browser/fingerprint override (e.g. chrome, firefox, safari, edge, chrome_137, safari_26)
    /// If not specified: latest Chrome for current host OS
    #[arg(short = 'e', long = "emulation", alias = "impersonate", short_alias = 'i')]
    emulation: Option<String>,

    /// Override target OS (auto, windows, macos, linux, android, ios). Default: host OS
    #[arg(long = "os", alias = "platform", value_enum)]
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
    #[arg(short = 'v', long = "verbose", alias = "include")]
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

fn resolve_profile(input: Option<&str>, config_val: Option<&str>) -> Profile {
    let name = input.or(config_val).unwrap_or("chrome");
    match name.to_lowercase().as_str() {
        "chrome" => Profile::Chrome137,
        "firefox" => Profile::Firefox136,
        "safari" => Profile::Safari26,
        "edge" => Profile::Edge137,
        "opera" => Profile::Opera126,
        custom => {
            serde_json::from_str::<Profile>(&format!("\"{}\"", custom))
                .or_else(|_| serde_json::from_str::<Profile>(&format!("\"{}\"", custom.to_lowercase())))
                .unwrap_or_else(|_| {
                    eprintln!("Warning: unknown profile '{}', falling back to default Chrome", custom);
                    Profile::Chrome137
                })
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref());

    let profile = resolve_profile(args.emulation.as_deref(), config.emulation.as_deref());
    let platform = resolve_platform(args.os, config.os);

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
