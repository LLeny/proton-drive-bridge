use anyhow::{Context, Result};
use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use unftp_auth_jsonfile::JsonFileAuthenticator;
use unftp_sbe_pd::ext::with_pd;

/// FTP server for Proton Drive
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Proton account username
    #[arg(short, long, env = "PROTON_USERNAME")]
    username: Option<String>,

    /// Proton account password
    #[arg(short, long, env = "PROTON_PASSWORD")]
    password: Option<String>,

    /// Path to JSON file containing user credentials
    #[arg(long, default_value = "users.json")]
    auth_file: PathBuf,

    /// IP address to bind the FTP server to
    #[arg(long, default_value = "0.0.0.0")]
    bind: IpAddr,

    /// Port to listen on
    #[arg(long, default_value_t = 2121)]
    port: u16,

    /// Server greeting message
    #[arg(long, default_value = "Welcome to Proton Drive FTP Server")]
    greeting: String,

    /// Enable FTPS (FTP over TLS)
    #[arg(long)]
    tls: bool,

    /// Path to certificate file for FTPS (PEM format)
    #[arg(long, requires = "tls")]
    cert: Option<PathBuf>,

    /// Path to private key file for FTPS (PEM format)
    #[arg(long, requires = "tls")]
    key: Option<PathBuf>,
}

fn prompt_user(prompt: &str) -> Result<String> {
    println!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read user input")?;
    Ok(input.trim().to_string())
}

fn prompt_2fa_code() -> String {
    prompt_user("Enter your 2FA code: ").unwrap_or_else(|_| String::new())
}

async fn run_server(args: Args) -> Result<()> {
    env_logger::init();

    let authenticator = JsonFileAuthenticator::from_file(&args.auth_file)
        .map_err(|e| anyhow::anyhow!("Failed to load authenticator: {}", e))?;

    let username = if let Some(u) = args.username {
        u
    } else {
        prompt_user("Enter your Proton account username (email): ")?
    };

    let password = if let Some(p) = args.password {
        p
    } else {
        prompt_user("Enter your Proton account password: ")?
    };

    let greeting = if args.greeting.is_empty() {
        "Welcome to Proton Drive FTP Server".to_string()
    } else {
        args.greeting
    };

    let mut server_builder = with_pd(username.leak(), password.leak(), prompt_2fa_code)
        .authenticator(Arc::new(authenticator))
        .greeting(greeting.leak())
        .idle_session_timeout(86400) 
        .passive_ports(50000..=50100);

    if args.tls {
        let cert = args.cert.context("Certificate file is required for FTPS")?;
        let key = args.key.context("Private key file is required for FTPS")?;

        let cert_str = cert.to_str().context("Invalid certificate path encoding")?;
        let key_str = key.to_str().context("Invalid private key path encoding")?;

        server_builder = server_builder.ftps(cert_str, key_str);
    }

    let server = server_builder.build()?;
    let addr = SocketAddr::new(args.bind, args.port);

    println!("Starting FTP server on {}:{}", args.bind, args.port);
    if args.tls {
        println!("FTPS is enabled");
    }

    server.listen(addr.to_string()).await?;

    Ok(())
}

#[tokio::main]
#[allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
pub async fn main() -> Result<()> {
    let args = Args::parse();

    if let Err(e) = run_server(args).await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
