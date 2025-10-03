mod running;
mod settings;

use crate::{
    app::{
        Message, Page,
        server_page::running::{ServerThreadMessage, Table},
    },
    config::ServerConfig,
};
use iced::{
    Event, Task,
    event::{self, Status},
    futures::SinkExt,
    keyboard::{self, Key, key::Named},
};
use pmapi::client::{authenticator::AuthTokens, session_store::SessionStore};
use std::{any::TypeId, path::PathBuf, sync::Arc};
use tokio::{
    sync::{Mutex, mpsc::UnboundedReceiver},
    task::JoinHandle,
};

enum ServerStatus {
    Settings,
    Server,
}

#[derive(Clone, Debug)]
pub enum ServerPageMessage {
    PortChanged(u16),
    GreetingChanged(String),
    AuthJsonPick,
    AuthJsonChanged(PathBuf),
    TLSChanged(bool),
    TLSCertPick,
    TLSCertChanged(PathBuf),
    TLSKeyPick,
    TLSKeyChanged(PathBuf),
    Start,
    ServerEvent(ServerThreadMessage),
    WorkersChanged(usize),
}

pub(crate) struct ServerPage {
    status: ServerStatus,
    config: ServerConfig,
    server_events_rx: Option<Arc<Mutex<UnboundedReceiver<ServerThreadMessage>>>>,
    session: Option<SessionStore>,
    auth_tokens: Option<AuthTokens>,
    server_thread: Option<JoinHandle<()>>,

    table: Table,
}

impl ServerPage {
    pub(crate) fn new(config: &ServerConfig, session: SessionStore, auth: AuthTokens) -> Self {
        Self {
            status: ServerStatus::Settings,
            config: config.clone(),
            server_events_rx: None,
            session: Some(session),
            auth_tokens: Some(auth),
            server_thread: None,

            table: Table::new(),
        }
    }
}

impl Page for ServerPage {
    fn update(&mut self, message: Message) -> iced::Task<Message> {
        let Message::ServerPageMsg(msg) = message else {
            return Task::done(message);
        };

        match msg {
            ServerPageMessage::PortChanged(p) => {
                self.config.port = p;
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::WorkersChanged(w) => {
                self.config.worker_count = w;
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::Start => {
                self.status = ServerStatus::Server;
                self.start_server();
            }
            ServerPageMessage::GreetingChanged(g) => {
                self.config.greeting = g;
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::AuthJsonPick => return self.pick_auth_json(),
            ServerPageMessage::AuthJsonChanged(c) => {
                self.config.auth_json = Some(c);
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::TLSChanged(t) => {
                self.config.tls = t;
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::TLSCertPick => return self.pick_cert(),
            ServerPageMessage::TLSCertChanged(c) => {
                self.config.tls_cert = Some(c);
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::TLSKeyPick => return self.pick_key(),
            ServerPageMessage::TLSKeyChanged(k) => {
                self.config.tls_key = Some(k);
                return Task::done(Message::ServerConfigChanged(self.config.clone()));
            }
            ServerPageMessage::ServerEvent(evt) => self.add_event(evt.to_string()),
        }

        Task::none()
    }

    fn view(&'_ self) -> iced::Element<'_, Message> {
        match &self.status {
            ServerStatus::Settings => self.settings_view(),
            ServerStatus::Server => self.server_view(),
        }
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch([
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
            }),
            match &self.server_events_rx {
                Some(rx_mutex) => {
                    let rx_mutex = rx_mutex.clone();
                    iced::Subscription::run_with_id(
                        TypeId::of::<ServerPage>(),
                        iced::stream::channel(4, move |mut channel| async move {
                            let mut rx = rx_mutex.lock().await;
                            while let Some(msg) = rx.recv().await {
                                let _ = channel
                                    .send(Message::ServerPageMsg(
                                        ServerPageMessage::ServerEvent(msg),
                                    ))
                                    .await;
                            }
                        }),
                    )
                }
                _ => iced::Subscription::none(),
            },
        ])
    }
}
