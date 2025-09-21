mod config;
mod keyring;
mod vault;
mod app;

use crate::app::App;

const APP_NAME: &str = "pdrive-bridge";

fn main() -> iced::Result {
    env_logger::init();

    iced::application("Proton Drive FTP bridge", App::update, App::view)
        .antialiasing(true)
        .subscription(App::subscription)
        .theme(App::theme)
        .run_with(App::new)
}
