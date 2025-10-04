mod config;
mod vault;
mod cli;
mod keyring;
#[cfg(feature = "desktop")]
mod app;

use clap::Parser;
use crate::cli::Args;
#[cfg(feature = "desktop")]
use crate::app::App;

const APP_NAME: &str = "pdrive-bridge";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    if args.cli {
        if let Err(e) = cli::run(args).await {
            eprintln!("error: {e:#}");
        }
        return Ok(());
    }

    #[cfg(not(feature = "desktop"))]
    {
        eprintln!("Desktop feature is not enabled, use --cli for command line mode");
        return Ok(());
    }
    #[cfg(feature = "desktop")]
    iced::application("Proton Drive FTP bridge", App::update, App::view)
        .antialiasing(true)
        .subscription(App::subscription)
        .theme(App::theme)
        .run_with(App::new)
        .map_err(anyhow::Error::msg)
}