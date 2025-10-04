use crate::config::Config;
use crate::keyring::keyring;
use crate::vault::{LockedVault, UnlockedVault};
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use libunftp::ServerBuilder;
use log::error;
use pmapi::client::{
    authenticator::{AuthTokens, Authenticator, Password},
    crypto::Crypto,
    session_store::SessionStore,
};
use proton_crypto::srp::SRPProvider;
use rpassword::prompt_password;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use unftp_auth_jsonfile::JsonFileAuthenticator;
use unftp_sbe_pd::ProtonDriveStorage;

#[derive(Debug, Parser)]
#[command(
    name = "proton-drive-bridge",
    about = "Proton Drive FTP bridge",
    version
)]
pub struct Args {
    /// Run in CLI mode (no UI)
    #[arg(short = 'c', long = "cli")]
    pub cli: bool,

    /// Proton account email
    #[arg(short = 'u', long = "username", env = "PROTON_USERNAME")]
    pub username: Option<String>,

    /// Proton account password
    #[arg(short = 'p', long = "password", env = "PROTON_PASSWORD")]
    pub password: Option<String>,

    /// Path to JSON file containing user credentials (default: users.json)
    #[arg(long = "auth-file")]
    pub auth_file: Option<PathBuf>,

    /// Port to listen on
    #[arg(long = "port", default_value_t = 2121)]
    pub port: u16,

    /// Server greeting message
    #[arg(long = "greeting")]
    pub greeting: Option<String>,

    /// Enable FTPS (requires certificate and key)
    #[arg(long = "tls", default_value_t = false)]
    pub tls: bool,

    /// Path to TLS certificate (PEM)
    #[arg(long = "cert", requires = "tls")]
    pub cert: Option<PathBuf>,

    /// Path to TLS private key (PEM)
    #[arg(long = "key", requires = "tls")]
    pub key: Option<PathBuf>,

    /// Number of upload/download workers (default: 4)
    #[arg(long = "workercount", default_value_t = 4)]
    pub worker_count: usize,

    /// Passive mode port range (default: 49000-49100)
    #[arg(long = "passiveports", default_value = "49000-49100")]
    passive_ports: String,

    /// Session password (for bridge session unlock)
    #[arg(long = "sessionpassword", env = "PROTON_SESSION_PASSWORD")]
    pub session_password: Option<String>,
}

fn parse_port_range(range_str: &str) -> Result<std::ops::RangeInclusive<u16>> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid passive port range format"));
    }
    let start: u16 = parts[0]
        .parse()
        .map_err(|_| anyhow!("Invalid passive start port in range"))?;
    let end: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow!("Invalid passive end port in range"))?;
    if start >= end || start < 1024 {
        return Err(anyhow!("Passive port range must be between 1024 and 65535 and start < end"));
    }
    Ok(start..=end)
}

pub async fn run(args: Args) -> Result<()> {
    let mut cfg = Config::initialize().context("failed to load config")?;

    let salted_password: Password;
    let mut unlocked_vault: Option<UnlockedVault> = None;

    if keyring::get_key().is_err() {
        println!("[bridge] No existing session found. Creating a new bridge session...");
        salted_password = create_bridge_session_password(&cfg)?;
    } else {
        println!("[bridge] Unlocking existing bridge session...");
        let mut tried_password = false;
        loop {
            let pass = if !tried_password {
                if let Some(p) = args.session_password.clone() {
                    tried_password = true;
                    p
                } else {
                    prompt_password("Bridge session password: ")?
                }
            } else {
                prompt_password("Bridge session password: ")?
            };
            let srp = proton_crypto::new_srp_provider();
            let salted = srp
                .mailbox_password(pass.trim().as_bytes(), cfg.drive.salt)
                .map_err(|e| anyhow!(e.to_string()))?;
            let salted_vec = salted.as_ref().to_vec();

            if let Ok(u) = cfg.drive.vault.unlock(&salted_vec) {
                println!("[bridge] Session unlocked.");
                unlocked_vault = Some(u);
                salted_password = Password(salted_vec);
                break;
            }

            eprintln!("[bridge] Wrong session password.");
            print!("[bridge] Try again (t), Reset session (r), or Quit (q)? [t]: ");
            io::stdout().flush().ok();
            let mut choice = String::new();
            io::stdin().read_line(&mut choice).ok();
            match choice.trim().to_lowercase().as_str() {
                "r" | "reset" => {
                    println!("[bridge] Resetting bridge session...");
                    keyring::clear_key().ok();
                    cfg.drive.vault = LockedVault::default();
                    cfg.save().ok();
                    salted_password = create_bridge_session_password(&cfg)?;
                    unlocked_vault = None;
                    break;
                }
                "q" | "quit" | "n" | "no" => {
                    println!("[bridge] Aborting as requested.");
                    return Ok(());
                }
                _ => (),
            }
        }
    }

    let (tokens, session_store) = if let Some(unlocked) = unlocked_vault {
        println!("[bridge] Refreshing Proton session tokens...");
        match refresh_from_vault(&unlocked).await {
            Ok((t, s)) => {
                println!("[bridge] Token refresh successful.");
                save_to_vault(&mut cfg, &salted_password, &t, &s)?;
                (t, s)
            }
            Err(e) => {
                eprintln!("[bridge] Token refresh failed: {e}. Proceeding with full login.");
                login_and_initialize(&args, &salted_password, &mut cfg).await?
            }
        }
    } else {
        println!("[bridge] Logging into Proton...");
        login_and_initialize(&args, &salted_password, &mut cfg).await?
    };

    println!("[bridge] Starting FTP server on port {}...", args.port);
    run_server(tokens, session_store, args).await
}

fn create_bridge_session_password(cfg: &Config) -> Result<Password> {
    println!("[bridge] Create bridge session password (input hidden)");
    let pass1 = prompt_password("Create bridge session password: ")?;
    let pass2 = prompt_password("Confirm bridge session password: ")?;
    if pass1 != pass2 {
        return Err(anyhow!("Passwords do not match"));
    }
    let srp = proton_crypto::new_srp_provider();
    let salted = srp
        .mailbox_password(pass1.trim().as_bytes(), cfg.drive.salt)
        .map_err(|e| anyhow!(e.to_string()))?;
    let salted = salted.as_ref().to_vec();
    keyring::generate_new_key(&salted)?;
    Ok(Password(salted))
}

async fn refresh_from_vault(unlocked: &UnlockedVault) -> Result<(AuthTokens, SessionStore)> {
    let mut authenticator = Authenticator::new();
    let tokens_in = AuthTokens::from(unlocked.clone());
    authenticator.set_tokens(tokens_in.clone());

    let refreshed = authenticator
        .refresh_session(&tokens_in.refresh)
        .await
        .context("token refresh failed")?;

    Ok((refreshed, unlocked.session_store.clone()))
}

async fn login_and_initialize(
    args: &Args,
    salted_password: &Password,
    cfg: &mut Config,
) -> Result<(AuthTokens, SessionStore)> {
    println!("[bridge] Authenticating with Proton (username/password)");
    let username = if let Some(u) = args.username.clone() {
        u
    } else {
        prompt_stdin("Proton username: ")?.trim().to_string()
    };
    let password_str = if let Some(p) = args.password.clone() {
        p
    } else {
        prompt_password("Proton password: ")?.trim().to_string()
    };

    let mut authenticator = Authenticator::new();

    let (two_fa_required, tokens) = authenticator
        .login(&username, Password(password_str.clone().into_bytes()))
        .await
        .context("login failed")?;

    if two_fa_required {
        println!("[bridge] Two-factor authentication required.");
        let code = prompt_stdin("Enter 2FA code: ")?;
        let ok = authenticator
            .two_fa(code.trim())
            .await
            .context("2FA request failed")?;
        if !ok {
            return Err(anyhow!("2FA verification failed"));
        }
        println!("[bridge] 2FA verified.");
    }

    authenticator.set_tokens(tokens.clone());

    println!("[bridge] Preparing Proton Drive session (keys, addresses)...");
    let pgp = proton_crypto::new_pgp_provider();
    let srp = proton_crypto::new_srp_provider();
    let crypto = Crypto::new(pgp, srp);
    let session_store: SessionStore = authenticator
        .get_session_data(&crypto, &Password(password_str.into_bytes()))
        .await
        .context("failed to prepare session data")?;

    save_to_vault(cfg, salted_password, &tokens, &session_store)?;

    Ok((tokens, session_store))
}

fn save_to_vault(
    cfg: &mut Config,
    salted_password: &Password,
    tokens: &AuthTokens,
    session_store: &SessionStore,
) -> Result<()> {
    let unlocked = crate::vault::UnlockedVault {
        refresh: tokens.refresh.clone(),
        access: tokens.access.clone(),
        uid: tokens.uid.clone(),
        session_store: session_store.clone(),
    };

    let locked = unlocked
        .lock(salted_password.0.as_slice())
        .context("failed to lock session vault")?;

    cfg.drive.vault = locked;
    cfg.save()
}

async fn run_server(tokens: AuthTokens, session_store: SessionStore, args: Args) -> Result<()> {
    let greeting = args
        .greeting
        .clone()
        .unwrap_or_else(|| "Welcome to my Proton Drive FTP Server".to_owned());

    let greeting_static: &'static str = Box::leak(greeting.into_boxed_str());

    let port_range = parse_port_range(&args.passive_ports)
        .context("failed to parse passive ports range, expected format: start-end")?;

    let mut server_builder = ServerBuilder::new(Box::new(move || {
        let pgp = proton_crypto::new_pgp_provider();
        let srp = proton_crypto::new_srp_provider();
        ProtonDriveStorage::new(pgp, srp, tokens.clone(), session_store.clone(), args.worker_count)
            .expect("Couldn't initialize FTP Server")
    }))
    .passive_ports(port_range)
    .greeting(greeting_static)
    .idle_session_timeout(86400);

    if let Some(auth_file) = args.auth_file
        && auth_file.exists()
    {
        println!("[bridge] Using users file: {}", auth_file.display());
        match JsonFileAuthenticator::from_file(&auth_file) {
            Ok(a) => server_builder = server_builder.authenticator(Arc::new(a)),
            Err(e) => error!(
                "Couldn't initialize authentication from {}: {e}",
                auth_file.display()
            ),
        }
    }

    if args.tls {
        println!("[bridge] Enabling FTPS...");
        if let (Some(cert), Some(key)) = (args.cert, args.key) {
            server_builder = server_builder.ftps(cert, key);
        } else {
            anyhow::bail!("--tls requires both --cert and --key");
        }
    }

    let server = server_builder
        .build()
        .context("Couldn't build FTP server")?;

    println!("[bridge] FTP server listening on 0.0.0.0:{}", args.port);
    server
        .listen(format!("0.0.0.0:{}", args.port))
        .await
        .context("server listen failed")?;

    println!("[bridge] Server stopped.");
    Ok(())
}

fn prompt_stdin(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("failed to read from stdin")?;
    Ok(buf)
}
