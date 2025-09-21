use crate::app::{Message, Page, ZeroingString, ZeroingVec};
use anyhow::Result;
use iced::{
    Color, Event, Length, Task,
    alignment::Horizontal,
    event::{self, Status},
    keyboard::{self, Key, key::Named},
    widget::{button, column, container, row, text, text_input},
};
use proton_crypto::srp::SRPProvider;

#[derive(Clone, Debug)]
pub enum SessionPageMessage {
    Pass1Changed(String),
    Pass2Changed(String),
    DeleteSession,
    Validate,
}

pub struct SessionPage {
    pass1: ZeroingString,
    pass2: ZeroingString,
    new_session: bool,
    can_validate: bool,
    salt: [u8; 16],
}

impl SessionPage {
    pub(crate) fn new(salt: &[u8; 16]) -> Self {
        Self {
            salt: *salt,
            pass1: ZeroingString::default(),
            pass2: ZeroingString::default(),
            can_validate: false,
            new_session: crate::keyring::get_key().is_err(),
        }
    }

    fn update_can_validate(&mut self) {
        self.can_validate =
            !self.pass1.0.is_empty() && (!self.new_session || self.pass1.0 == self.pass2.0);
    }

    fn get_salted_password(&self) -> Result<Vec<u8>> {
        Ok(proton_crypto::new_srp_provider()
            .mailbox_password(self.pass1.0.as_bytes(), self.salt)
            .map_err(anyhow::Error::from)?
            .as_ref()
            .to_vec())
    }

    fn create_session(&self) -> Task<super::Message> {
        let salted_password = match self.get_salted_password() {
            Ok(pwd) => pwd,
            Err(e) => return Task::done(Message::Error(e.to_string())),
        };

        if let Err(e) = crate::keyring::generate_new_key(&salted_password) {
            return Task::done(Message::Error(e.to_string()));
        }

        Self::unlock_session(&salted_password)
    }

    fn session_login(&mut self) -> Task<super::Message> {
        let salted_password = match self.get_salted_password() {
            Ok(pwd) => pwd,
            Err(e) => return Task::done(Message::Error(e.to_string())),
        };

        Self::unlock_session(&salted_password)
    }

    fn delete_session(&mut self) -> Task<Message> {

        match crate::keyring::clear_key() {
            Ok(()) => {
                self.new_session = true;
                Task::done(Message::ResetConfig)
            },
            Err(e) => Task::done(Message::Error(e.to_string())),
        }
    }

    fn unlock_session(salted_password: &[u8]) -> Task<super::Message> {
        Task::done(Message::SessionUnlocked(ZeroingVec(
            salted_password.to_vec(),
        )))
    }

    fn create_session_view(&self) -> iced::Element<'_, Message> {
        let mut validate = button("Validate");
        let mut dont_match = text("Passwords don't match.");
        if self.can_validate {
            validate = validate.on_press(Message::SessionPageMsg(SessionPageMessage::Validate));
            dont_match = text("");
        }
        column![
            container(text("Create your bridge session password")),
            text_input("Password", &self.pass1.0)
                .secure(true)
                .on_input(|s| Message::SessionPageMsg(SessionPageMessage::Pass1Changed(s))),
            text_input("Confirmation", &self.pass2.0)
                .secure(true)
                .on_input(|s| Message::SessionPageMsg(SessionPageMessage::Pass2Changed(s))),
            container(dont_match.color(Color::from_rgb8(240, 0, 0))),
            container(validate)
                .width(Length::Fill)
                .align_x(Horizontal::Right)
        ]
        .spacing(10)
        .width(Length::Fill)
        .into()
    }

    fn login_session_view(&self) -> iced::Element<'_, Message> {
        let mut validate = button("Validate");
        if self.can_validate {
            validate = validate.on_press(Message::SessionPageMsg(SessionPageMessage::Validate));
        }
        column![
            container(text("Login to your bridge session")),
            text_input("Password", &self.pass1.0)
                .secure(true)
                .on_input(|s| Message::SessionPageMsg(SessionPageMessage::Pass1Changed(s))),
            row![
                container(
                    button("Delete session")
                        .style(|_, _| button::Style {
                            background: Some(iced::Background::Color(Color::from_rgb8(240, 0, 0))),
                            ..Default::default()
                        })
                        .on_press(Message::SessionPageMsg(SessionPageMessage::DeleteSession))
                )
                .width(Length::Fill)
                .align_x(Horizontal::Left),
                container(validate)
                    .width(Length::Fill)
                    .align_x(Horizontal::Right),
            ]
        ]
        .spacing(10)
        .into()
    }

    fn validate(&mut self) -> Task<super::Message> {
        self.can_validate = false;
        if self.new_session {
            self.create_session()
        } else {
            self.session_login()
        }
    }
}

impl Page for SessionPage {
    fn update(&mut self, message: super::Message) -> Task<super::Message> {
        let Message::SessionPageMsg(msg) = message else {
            return Task::done(message);
        };

        match msg {
            SessionPageMessage::Pass1Changed(s) => self.pass1 = ZeroingString(s),
            SessionPageMessage::Pass2Changed(s) => self.pass2 = ZeroingString(s),
            SessionPageMessage::DeleteSession => return self.delete_session(),
            SessionPageMessage::Validate => return self.validate(),
        }

        self.update_can_validate();
        Task::none()
    }

    fn view(&'_ self) -> iced::Element<'_, Message> {
        row![
            text("").width(Length::FillPortion(1)),
            if self.new_session {
                self.create_session_view()
            } else {
                self.login_session_view()
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
