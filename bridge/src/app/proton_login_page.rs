use iced::{
    alignment::Horizontal, event::{self, Status}, keyboard::{self, key::Named, Key}, widget::{button, column, container, row, text, text_input}, Event, Length, Task
};
use log::error;
use pmapi::client::{
    authenticator::{AuthTokens, Authenticator, Password},
    crypto::Crypto,
    session_store::SessionStore,
};

use crate::{
    app::{Message, Page, ZeroingString},
    vault::UnlockedVault,
};

#[derive(Clone)]
pub(crate) enum ProtonLoginPageMessage {
    UserChanged(String),
    PasswordChanged(ZeroingString),
    TFAChanged(ZeroingString),
    Status(LoginStatus),
    Authentified((bool, AuthTokens)),
    Refreshed(AuthTokens),
    Initialized(Box<SessionStore>),
    TwoFa(bool),
    Refresh,
    Validate,
    None,
}

#[derive(Clone, Debug)]
pub(crate) enum LoginStatus {
    Refreshing,
    UserPass,
    TwoFA,
    InitializingSession,
}

pub(crate) struct ProtonLoginPage {
    vault: Option<UnlockedVault>,
    status: LoginStatus,
    can_validate: bool,
    user: String,
    password: ZeroingString,
    tfa_code: ZeroingString,
    auth_tokens: Option<AuthTokens>,
    session_store: Option<SessionStore>,
}

impl ProtonLoginPage {
    pub(crate) fn new(vault: Option<UnlockedVault>) -> Self {
        Self {
            vault,
            status: LoginStatus::Refreshing,
            can_validate: false,
            user: String::default(),
            password: ZeroingString::default(),
            tfa_code: ZeroingString::default(),
                        auth_tokens: None,
            session_store: None,
        }
    }

    fn update_can_validate(&mut self) {
        self.can_validate = match &self.status {
            LoginStatus::Refreshing | LoginStatus::InitializingSession => false,
            LoginStatus::UserPass => !self.user.is_empty() && !self.password.0.is_empty(),
            LoginStatus::TwoFA => !self.password.0.is_empty(),
        };
    }

    fn validate(&mut self) -> Task<Message> {
        self.can_validate = false;
        match &self.status {
            LoginStatus::Refreshing | LoginStatus::InitializingSession => {
                Task::done(Message::ProtonLoginPageMsg(ProtonLoginPageMessage::None))
            }
            LoginStatus::UserPass => self.validate_userpass(),
            LoginStatus::TwoFA => self.validate_2fa(),
        }
    }

    fn two_fa(&mut self, success: bool) -> Task<Message> {
        if success {
            self.initialize_session()
        } else {
            Task::done(Message::Error("Wrong 2FA code".to_owned()))
        }
    }

    fn authentified(&mut self, tfa: bool, tokens: AuthTokens) -> Task<Message> {
        self.auth_tokens = Some(tokens);
        if tfa {
            Task::done(Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Status(LoginStatus::TwoFA)))
        } else {
            self.initialize_session()
        }
    }

    fn initialize_session(&mut self) -> Task<Message> {
        self.status = LoginStatus::InitializingSession;

        let Some(auth) = &self.auth_tokens else {
            return Task::done(Message::Error("Couldn't get auth tokens".to_owned()));
        };

        let auth = auth.clone();
        let pwd = Password(self.password.0.as_bytes().to_vec());

        Task::future(async move {
            let mut authenticator = Authenticator::new();
            authenticator.set_tokens(auth);

            let pgp_provider = proton_crypto::new_pgp_provider();
            let srp_provider = proton_crypto::new_srp_provider();
            let crypto = Crypto::new(pgp_provider, srp_provider);

            match authenticator.get_session_data(&crypto, &pwd).await {
                Ok(s) => Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Initialized(Box::new(s))),
                Err(e) => {
                    error!("{e}");
                    Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Status(LoginStatus::UserPass))
                }
            }
        })
    }

    fn logged_in(&self) -> Task<Message> {
        let Some(tokens) = &self.auth_tokens else {
            return Task::done(Message::Error("Couldn't get auth tokens".to_owned()));
        };

        let Some(session_store) = &self.session_store else {
            return Task::done(Message::Error("Couldn't find session store".to_owned()));
        };

        Task::done(Message::ProtonLoggedIn(UnlockedVault {
            refresh: tokens.refresh.clone(),
            access: tokens.access.clone(),
            uid: tokens.uid.clone(),
            session_store: session_store.clone(),
        }))
    }

    fn initialized(&mut self, session_store: Box<SessionStore>) -> Task<Message> {
        self.session_store = Some(*session_store);
        self.logged_in()
    }

    fn refreshed(&mut self, tokens: AuthTokens) -> Task<Message> {
        let Some(vault) = &self.vault else {
            return Task::done(Message::Error("Unknown Proton login error".to_owned()));
        };

        self.auth_tokens = Some(tokens);
        self.session_store = Some(vault.session_store.clone());

        self.logged_in()
    }

    fn refresh(&mut self) -> Task<Message> {
        let Some(vault) = &self.vault else {
            return Task::done(Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Status(
                LoginStatus::UserPass,
            )));
        };

        let auth: AuthTokens = vault.into();

        Task::future(async move {
            let mut authenticator = Authenticator::new();
            authenticator.set_tokens(auth.clone());
            match authenticator.refresh_session(&auth.refresh).await {
                Ok(a) => Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Refreshed(a)),
                Err(e) => {
                    error!("{e}");
                    Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Status(LoginStatus::UserPass))
                }
            }
        })
    }

    fn validate_userpass(&mut self) -> Task<Message> {
        let user = self.user.clone();
        let pass = Password(self.password.0.as_bytes().to_vec());
        Task::future(async move {
            let mut authenticator = Authenticator::new();
            match authenticator.login(&user, pass.clone()).await {
                Ok(a) => Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Authentified(a)),
                Err(e) => {
                    error!("{e}");
                    Message::Error("Couldn't log in, verify your credentials.".to_owned())
                }
            }
        })
    }

    fn validate_2fa(&self) -> Task<Message> {
        let tfa = self.tfa_code.0.clone();
        let Some(tokens) = &self.auth_tokens else {
            return Task::done(Message::Error("Couldn't get auth tokens".to_owned()));
        };
        let tokens = tokens.clone();
        Task::future(async move {
            let mut authenticator = Authenticator::new();
            authenticator.set_tokens(tokens);
            match authenticator.two_fa(&tfa).await {
                Ok(a) => Message::ProtonLoginPageMsg(ProtonLoginPageMessage::TwoFa(a)),
                Err(e) => Message::Error(e.to_string()),
            }
        })
    }

    #[allow(clippy::unused_self)]
    fn refreshing_view(&'_ self) -> iced::Element<'_, Message> {
        text!("Refreshing Proton session...").into()
    }

    #[allow(clippy::unused_self)]
    fn initializing_session_view(&'_ self) -> iced::Element<'_, Message> {
        text!("Initializing Proton session...").into()
    }

    fn login_view(&'_ self) -> iced::Element<'_, Message> {
        let mut validate = button("Validate");
        if self.can_validate {
            validate = validate.on_press(Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Validate));
        }
        column![
            container(text("Login to proton:")),
            text_input("User", &self.user)
                .on_input(|s| Message::ProtonLoginPageMsg(ProtonLoginPageMessage::UserChanged(s))),
            text_input("Password", &self.password.0)
                .secure(true)
                .on_input(
                    |s| Message::ProtonLoginPageMsg(ProtonLoginPageMessage::PasswordChanged(ZeroingString(s.clone())))
                ),
            container(validate)
                .width(Length::Fill)
                .align_x(Horizontal::Right)
        ]
        .spacing(10)
        .width(Length::Fill)
        .into()
    }

    fn tfa_view(&'_ self) -> iced::Element<'_, Message> {
        let mut validate = button("Validate");
        if self.can_validate {
            validate = validate.on_press(Message::ProtonLoginPageMsg(ProtonLoginPageMessage::Validate));
        }
        column![
            container(text("Login to proton, enter your 2FA code:")),
            text_input("2FA", &self.tfa_code.0)
                .secure(true)
                .on_input(
                    |s| Message::ProtonLoginPageMsg(ProtonLoginPageMessage::TFAChanged(ZeroingString(s.clone())))
                ),
            container(validate)
                .width(Length::Fill)
                .align_x(Horizontal::Right)
        ]
        .spacing(10)
        .width(Length::Fill)
        .into()
    }
}

impl Page for ProtonLoginPage {
    fn update(&mut self, message: Message) -> Task<Message> {
        if let Message::ProtonLoginPageMsg(msg) = message {
            match msg {
                ProtonLoginPageMessage::Refresh => return self.refresh(),
                ProtonLoginPageMessage::Validate => return self.validate(),
                ProtonLoginPageMessage::UserChanged(u) => self.user = u,
                ProtonLoginPageMessage::PasswordChanged(p) => self.password = p,
                ProtonLoginPageMessage::TFAChanged(p) => self.tfa_code = p,
                ProtonLoginPageMessage::Status(s) => self.status = s,
                ProtonLoginPageMessage::Refreshed(a) => return self.refreshed(a),
                ProtonLoginPageMessage::Initialized(s) => return self.initialized(s),
                ProtonLoginPageMessage::None => (),
                ProtonLoginPageMessage::Authentified((tfa, tokens)) => {
                    return self.authentified(tfa, tokens);
                }
                ProtonLoginPageMessage::TwoFa(r) => return self.two_fa(r),
            }
            self.update_can_validate();
        }
        Task::none()
    }

    fn view(&'_ self) -> iced::Element<'_, Message> {
        row![
            text("").width(Length::FillPortion(1)),
            match self.status {
                LoginStatus::InitializingSession => self.initializing_session_view(),
                LoginStatus::Refreshing => self.refreshing_view(),
                LoginStatus::UserPass => self.login_view(),
                LoginStatus::TwoFA => self.tfa_view(),
            },
            text("").width(Length::FillPortion(1)),
        ]
        .into()
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        event::listen_with(|event, status, _| match (event, status) {
            (
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: Key::Named(Named::Enter),
                    modifiers,
                    ..
                }),
                Status::Ignored,
            ) => Some(Message::KeyPressed(Named::Enter, modifiers)),
            (
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: Key::Named(Named::Tab),
                    modifiers,
                    ..
                }),
                Status::Ignored,
            ) => Some(Message::KeyPressed(Named::Tab, modifiers)),
            _ => None,
        })
    }
}

impl std::fmt::Debug for ProtonLoginPageMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserChanged(arg0) => f.debug_tuple("UserChanged").field(arg0).finish(),
            Self::PasswordChanged(arg0) => f.debug_tuple("PasswordChanged").field(arg0).finish(),
            Self::TFAChanged(arg0) => f.debug_tuple("TFAChanged").field(arg0).finish(),
            Self::Status(arg0) => f.debug_tuple("Status").field(arg0).finish(),
            Self::Authentified(arg0) => f.debug_tuple("Authentified").field(arg0).finish(),
            Self::Refreshed(arg0) => f.debug_tuple("Refreshed").field(arg0).finish(),
            Self::Initialized(_) => f.debug_tuple("Initialized").finish(),
            Self::TwoFa(arg0) => f.debug_tuple("TwoFa").field(arg0).finish(),
            Self::Refresh => write!(f, "Refresh"),
            Self::Validate => write!(f, "Validate"),
            Self::None => write!(f, "None"),
        }
    }
}
