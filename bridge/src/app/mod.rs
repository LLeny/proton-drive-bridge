mod none;
mod proton_login_page;
mod server_page;
mod session_page;

use crate::app::none::NonePage;
use crate::app::proton_login_page::{ProtonLoginPage, ProtonLoginPageMessage};
use crate::app::server_page::{ServerPage, ServerPageMessage};
use crate::app::session_page::{SessionPage, SessionPageMessage};
use crate::config::{Config, DriveConfig, ServerConfig};
use crate::keyring::keyring;
use crate::vault::UnlockedVault;
use std::fmt::Debug;
use iced::Color;
use iced::alignment::Vertical;
use iced::keyboard::Modifiers;
use iced::keyboard::key::Named;
use iced::widget::toggler;
use iced::{
    Element, Font, Length, Task,
    alignment::Horizontal,
    font::Weight,
    widget::{column, container, row, text},
};
use log::error;
use pmapi::client::authenticator::AuthTokens;
use pmapi::client::session_store::SessionStore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug)]
pub(crate) struct ZeroingVec(pub Vec<u8>);

#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug, Default)]
pub(crate) struct ZeroingString(pub String);

trait Page {
    fn update(&mut self, message: Message) -> Task<Message>;
    fn view(&'_ self) -> iced::Element<'_, Message>;
    fn subscription(&self) -> iced::Subscription<Message>;
}

#[derive(Clone)]
pub(crate) enum Message {
    SessionPage,
    SessionPageMsg(SessionPageMessage),
    SessionUnlocked(ZeroingVec),

    Login,
    ProtonLoginPage,
    ProtonLoginPageMsg(ProtonLoginPageMessage),
    ProtonLoggedIn(UnlockedVault),

    ServerPage(AuthTokens, SessionStore),
    ServerPageMsg(ServerPageMessage),
    ServerConfigChanged(ServerConfig),

    KeyPressed(Named, Modifiers),
    Error(String),
    SaveConfig,
    ResetConfig,
    SetDarkTheme(bool),
    None,
}

pub(crate) struct App {
    config: Config,
    page: Box<dyn Page>,
    theme: iced::Theme,
    status: String,
    error: String,
    salted_password: Option<ZeroingVec>,
}

impl App {
    pub(crate) fn new() -> (Self, Task<Message>) {
        let Ok(config) = Config::initialize() else {
            panic!("Couldn't initialize app config");
        };

        let mut slf = Self {
            config,
            status: String::default(),
            error: String::default(),
            page: Box::new(NonePage::new()),
            theme: iced::Theme::Light,
            salted_password: None,
        };

        slf.refresh_theme();

        (slf, Task::done(Message::SessionPage))
    }

    pub(crate) fn subscription(&self) -> iced::Subscription<Message> {
        self.page.subscription()
    }

    pub(crate) fn update(&mut self, message: Message) -> Task<Message> {
        match message.clone() {
            Message::SaveConfig => return self.save_config(Message::None),
            Message::SetDarkTheme(b) => return self.setting_theme_changed(b),
            Message::Error(s) => self.set_error(s),
            Message::SessionPage => self.page = Box::new(SessionPage::new(&self.config.drive.salt)),
            Message::SessionUnlocked(pwd) => return self.session_unlocked(pwd),
            Message::Login => return self.login(),
            Message::ProtonLoginPage => return self.login_page(),
            Message::ProtonLoggedIn(v) => return self.logged_in(v),
            Message::SessionPageMsg(_)
            | Message::ProtonLoginPageMsg(_)
            | Message::ServerPageMsg(_)
            | Message::None => {
                return self.page.update(message);
            }
            Message::ServerPage(a, s) => {
                self.page = Box::new(ServerPage::new(&self.config.server, s, a));
            }
            Message::ServerConfigChanged(c) => return self.server_config_changed(c),
            Message::KeyPressed(k, m) => return self.manage_key(k, m),
            Message::ResetConfig => return self.reset_session(),
        }

        Task::none()
    }

    #[allow(clippy::unused_self)]
    fn manage_key(&self, key: Named, modifiers: Modifiers) -> Task<Message> {
        match key {
            Named::Tab => {
                if modifiers.shift() {
                    iced::widget::focus_previous()
                } else {
                    iced::widget::focus_next()
                }
            }
            _ => Task::none(),
        }
    }

    pub(crate) fn refresh_theme(&mut self) {
        self.theme = if self.config.ui.dark_theme {
            iced::Theme::Dark
        } else {
            iced::Theme::Light
        };
    }

    fn server_config_changed(&mut self, config: ServerConfig) -> Task<Message> {
        self.config.server = config;
        Task::done(Message::SaveConfig)
    }

    fn setting_theme_changed(&mut self, dark: bool) -> Task<Message> {
        self.config.ui.dark_theme = dark;
        self.refresh_theme();
        Task::done(Message::SaveConfig)
    }

    pub(crate) fn theme(&self) -> iced::Theme {
        self.theme.clone()
    }

    fn session_unlocked(&mut self, salted_passwword: ZeroingVec) -> Task<Message> {
        self.salted_password = Some(salted_passwword);
        Task::done(Message::Login)
    }

    fn login_page(&mut self) -> Task<Message> {
        if keyring::get_key().is_err() {
            return Task::done(Message::SessionPage);
        }

        if let Some(salted_password) = &self.salted_password {
            let vault = self.config.drive.vault.unlock(&salted_password.0).ok();
            self.page = Box::new(ProtonLoginPage::new(vault));
            Task::done(Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Refresh))
        } else {
            Task::done(Message::SessionPage)
        }
    }

    fn logged_in(&mut self, vault: UnlockedVault) -> Task<Message> {
        let Some(sp) = &self.salted_password else {
            return Task::done(Message::Error(
                "No salted password, shouldn't happen".to_owned(),
            ));
        };

        let locked_vault = match vault.lock(&sp.0) {
            Ok(t) => t,
            Err(e) => {
                error!("{e}");
                return Task::done(Message::Error(format!("Couldn't lock vault, {e}")));
            }
        };

        self.config.drive.vault = locked_vault;

        let _ = self.save_config(Message::None);

        let session_store = vault.session_store.clone();

        self.status = "Logged in".to_string();

        Task::done(Message::ServerPage(vault.into(), session_store))
    }

    fn save_config(&self, message: Message) -> Task<Message> {
        if self.config.save().is_err() {
            return Task::done(Message::Error("Error while saving settings".to_owned()));
        }
        Task::done(message)
    }

    fn reset_session(&mut self) -> Task<Message> {
        self.config.drive = DriveConfig::default();
        Task::batch(vec![
            Task::done(Message::SaveConfig),
            Task::done(Message::SessionPage),
        ])
    }

    fn set_error(&mut self, error: String) {
        self.error = error;
    }

    #[allow(clippy::unused_self)]
    fn login(&self) -> Task<Message> {
        if keyring::get_key().is_err() {
            return Task::done(Message::SessionPage);
        }
        Task::done(Message::ProtonLoginPage)
    }

    pub(crate) fn view(&'_ self) -> iced::Element<'_, Message> {
        column![
            self.header_view(),
            container(self.main_page())
                .align_x(Horizontal::Center)
                .align_y(Vertical::Center)
                .height(Length::Fill)
                .width(Length::Fill),
            self.status_view()
        ]
        .into()
    }

    fn main_page(&'_ self) -> Element<'_, Message> {
        self.page.view()
    }

    fn header_view(&'_ self) -> iced::Element<'_, Message> {
        container(row![
            container(text("Proton Drive FTP bridge"))
                .padding(5)
                .width(Length::Fill),
            container(
                toggler(self.config.ui.dark_theme)
                    .label("Dark theme")
                    .on_toggle(Message::SetDarkTheme)
            )
            .padding(5)
            .width(Length::Fill)
            .align_x(Horizontal::Right)
        ])
        .height(Length::Shrink)
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
    }

    fn status_view(&'_ self) -> iced::Element<'_, Message> {
        container(row![
            text(self.status.as_str()).align_x(Horizontal::Left),
            text(self.error.as_str())
                .width(Length::Fill)
                .align_x(Horizontal::Right)
                .color(Color::from_rgb8(240, 0, 0))
                .font(Font {
                    weight: Weight::Bold,
                    ..Font::DEFAULT
                }),
        ])
        .padding(5)
        .height(Length::Shrink)
        .width(Length::Fill)
        .align_bottom(Length::Shrink)
        .style(container::bordered_box)
        .into()
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionPage => write!(f, "SessionPage"),
            Self::SessionPageMsg(arg0) => f.debug_tuple("SessionPageMsg").field(arg0).finish(),
            Self::SessionUnlocked(arg0) => f.debug_tuple("SessionUnlocked").field(arg0).finish(),
            Self::Login => write!(f, "Login"),
            Self::ProtonLoginPage => write!(f, "ProtonLoginPage"),
            Self::ProtonLoginPageMsg(arg0) => {
                f.debug_tuple("ProtonLoginPageMsg").field(arg0).finish()
            }
            Self::ProtonLoggedIn(_) => f.debug_tuple("ProtonLoggedIn").finish(),
            Self::ServerPage(arg0, _) => f.debug_tuple("ServerPage").field(arg0).finish(),
            Self::ServerPageMsg(arg0) => f.debug_tuple("ServerPageMsg").field(arg0).finish(),
            Self::ServerConfigChanged(arg0) => {
                f.debug_tuple("ServerConfigChanged").field(arg0).finish()
            }
            Self::Error(arg0) => f.debug_tuple("Error").field(arg0).finish(),
            Self::SaveConfig => write!(f, "SaveConfig"),
            Self::SetDarkTheme(arg0) => f.debug_tuple("SetDarkTheme").field(arg0).finish(),
            Self::None => write!(f, "None"),
            Self::KeyPressed(arg0, arg1) => {
                f.debug_tuple("KeyPressed").field(arg0).field(arg1).finish()
            }
            Self::ResetConfig => write!(f, "ResetConfig"),
        }
    }
}
