use clap::Parser;
use std::fs::File;
use std::io::Write;
use wreq::Client;
use wreq_util::{Emulation, Platform, Profile};

#[derive(Parser, Debug)]
#[command(name = "wreq", about = "Fast stealth HTTP client with browser TLS & HTTP/2 impersonation")]
struct Args {
    /// URL to fetch
    #[arg(required = true)]
    url: String,

    /// HTTP method (GET, POST, PUT, DELETE, HEAD)
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Fingerprint override (e.g. chrome, firefox, safari, safari_26, chrome_137)
    /// Default: latest Chrome matching the host OS
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

fn resolve_emulation(explicit: Option<&str>) -> Emulation {
    match explicit {
        None => Emulation::builder()
            .profile(Profile::Chrome137)
            .platform(host_platform())
            .build(),
        Some(name) => match name.to_lowercase().as_str() {
            "chrome" => Emulation::builder()
                .profile(Profile::Chrome137)
                .platform(host_platform())
                .build(),
            "firefox" => Emulation::builder()
                .profile(Profile::Firefox136)
                .platform(host_platform())
                .build(),
            "safari" => Emulation::builder()
                .profile(Profile::Safari26)
                .platform(Platform::MacOS)
                .build(),
            "edge" => Emulation::builder()
                .profile(Profile::Edge137)
                .platform(host_platform())
                .build(),
            custom => {
                let profile = serde_json::from_str::<Profile>(&format!("\"{}\"", custom))
                    .or_else(|_| serde_json::from_str::<Profile>(&format!("\"{}\"", custom.to_lowercase())))
                    .unwrap_or(Profile::Chrome137);

                Emulation::builder()
                    .profile(profile)
                    .platform(host_platform())
                    .build()
            }
        },
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let emulation = resolve_emulation(args.emulation.as_deref());

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
