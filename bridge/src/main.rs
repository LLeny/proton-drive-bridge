mod config;
mod keyring;
mod vault;
mod app;
mod cli;

use crate::app::App;

const APP_NAME: &str = "pdrive-bridge";

use clap::Parser;
use crate::cli::Args;

#[tokio::main]
async fn main() -> iced::Result {
    env_logger::init();

    let args = Args::parse();

    if args.cli {
        if let Err(e) = cli::run(args).await {
            eprintln!("error: {e:#}");
        }
        return Ok(());
    }

    iced::application("Proton Drive FTP bridge", App::update, App::view)
        .antialiasing(true)
        .subscription(App::subscription)
        .theme(App::theme)
        .run_with(App::new)
}