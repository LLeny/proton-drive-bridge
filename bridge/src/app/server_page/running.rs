use crate::{
    app::{Message, server_page::ServerPage},
    config::ServerConfig,
};
use async_trait::async_trait;
use chrono::Utc;
use iced::{
    Element, Length, Renderer, Theme,
    widget::{column, container, responsive, scrollable, text},
};
use iced_table::table;
use libunftp::notification::{DataEvent, DataListener, EventMeta, PresenceEvent, PresenceListener};
use log::error;
use pmapi::client::{authenticator::AuthTokens, session_store::SessionStore};
use std::sync::Arc;
use tokio::sync::{
    Mutex,
    mpsc::{UnboundedSender, unbounded_channel},
};
use unftp_auth_jsonfile::JsonFileAuthenticator;
use unftp_sbe_pd::ProtonDriveStorage;

const MAX_ROW_COUNT: usize = 100;

#[derive(Clone, Debug, strum::Display)]
pub enum ServerThreadMessage {
    #[strum(to_string = "['{u}'] User logged in")]
    UserLoggedIn { u: String },
    #[strum(to_string = "['{u}'] User logged out")]
    UserLoggedOut { u: String },
    #[strum(to_string = "['{u}'] Got: '{path}' ({bytes} bytes)")]
    Got { u: String, path: String, bytes: u64 },
    #[strum(to_string = "['{u}'] Put: '{path}' ({bytes} bytes)")]
    Put { u: String, path: String, bytes: u64 },
    #[strum(to_string = "['{u}'] Deleted: '{path}'")]
    Deleted { u: String, path: String },
    #[strum(to_string = "['{u}'] Made dir: '{path}'")]
    MadeDir { u: String, path: String },
    #[strum(to_string = "['{u}'] Removed dir: '{path}'")]
    RemovedDir { u: String, path: String },
    #[strum(to_string = "['{u}'] Renamed: '{from}' -> '{to}'")]
    Renamed { u: String, from: String, to: String },
}

pub(super) struct Table {
    columns: Vec<Column>,
    rows: Vec<Row>,
    header: scrollable::Id,
    body: scrollable::Id,
}

impl Table {
    pub(super) fn new() -> Self {
        Self {
            columns: vec![
                Column::new(ColumnKind::Timestamp),
                Column::new(ColumnKind::Event),
            ],
            rows: vec![],
            header: scrollable::Id::unique(),
            body: scrollable::Id::unique(),
        }
    }
}

impl ServerPage {
    pub(super) fn start_server(&mut self) {
        let (tx, rx) = unbounded_channel::<ServerThreadMessage>();

        self.server_events_rx = Some(Arc::new(Mutex::new(rx)));

        let session_store = self.session.take().unwrap();
        let auth = self.auth_tokens.take().unwrap();
        let cfg = self.config.clone();

        self.server_thread = Some(tokio::spawn(run_ftp_server_worker(
            auth,
            session_store,
            tx,
            cfg,
        )));
    }

    pub(super) fn server_view(&self) -> iced::Element<'_, Message> {
        let table = responsive(|_size| {
            let table = table(
                self.table.header.clone(),
                self.table.body.clone(),
                &self.table.columns,
                &self.table.rows,
                |_| Message::None,
            );
            table.into()
        });

        let content = column![table].spacing(6);

        container(container(content).width(Length::Fill).height(Length::Fill))
            .padding(10)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    pub(super) fn add_event(&mut self, evt: String) {
        self.table.rows.push(Row {
            timestamp: chrono::Utc::now(),
            event: evt,
        });

        while self.table.rows.len() > MAX_ROW_COUNT {
            self.table.rows.remove(0);
        }
    }
}

struct Column {
    kind: ColumnKind,
    width: f32,
}

enum ColumnKind {
    Timestamp,
    Event,
}

impl Column {
    fn new(kind: ColumnKind) -> Self {
        let width = match kind {
            ColumnKind::Timestamp => 270.0,
            ColumnKind::Event => 700.0,
        };

        Self { kind, width }
    }
}

struct Row {
    timestamp: chrono::DateTime<Utc>,
    event: String,
}

impl<'a> table::Column<'a, Message, Theme, Renderer> for Column {
    type Row = Row;

    fn header(&'a self, _col_index: usize) -> Element<'a, Message> {
        let content = match self.kind {
            ColumnKind::Timestamp => "Timestamp",
            ColumnKind::Event => "Event",
        };

        container(text(content)).center_y(20).into()
    }

    fn cell(&'a self, _col_index: usize, _row_index: usize, row: &'a Row) -> Element<'a, Message> {
        let content: Element<_> = match self.kind {
            ColumnKind::Event => text(row.event.clone()).into(),
            ColumnKind::Timestamp => text(row.timestamp.to_rfc2822()).into(),
        };

        container(content).width(Length::Fill).center_y(18).into()
    }

    fn footer(&'a self, _col_index: usize, _rows: &'a [Row]) -> Option<Element<'a, Message>> {
        None
    }

    fn width(&self) -> f32 {
        self.width
    }

    fn resize_offset(&self) -> Option<f32> {
        None
    }
}

#[derive(Debug)]
struct PresenceNotifier {
    tx: UnboundedSender<ServerThreadMessage>,
}

impl PresenceNotifier {
    pub(crate) fn new(tx: UnboundedSender<ServerThreadMessage>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl PresenceListener for PresenceNotifier {
    async fn receive_presence_event(&self, e: PresenceEvent, m: EventMeta) {
        let evt = match e {
            PresenceEvent::LoggedIn => ServerThreadMessage::UserLoggedIn { u: m.username },
            PresenceEvent::LoggedOut => ServerThreadMessage::UserLoggedOut { u: m.username },
        };

        let _ = self.tx.send(evt);
    }
}

#[derive(Debug)]
struct DataNotifier {
    tx: UnboundedSender<ServerThreadMessage>,
}

impl DataNotifier {
    pub(crate) fn new(tx: UnboundedSender<ServerThreadMessage>) -> Self {
        Self { tx }
    }
}
#[async_trait]
impl DataListener for DataNotifier {
    async fn receive_data_event(&self, e: DataEvent, m: EventMeta) {
        let evt = match e {
            DataEvent::Got { path, bytes } => ServerThreadMessage::Got {
                u: m.username,
                path,
                bytes,
            },
            DataEvent::Put { path, bytes } => ServerThreadMessage::Put {
                u: m.username,
                path,
                bytes,
            },
            DataEvent::Deleted { path } => ServerThreadMessage::Deleted {
                u: m.username,
                path,
            },
            DataEvent::MadeDir { path } => ServerThreadMessage::MadeDir {
                u: m.username,
                path,
            },
            DataEvent::RemovedDir { path } => ServerThreadMessage::RemovedDir {
                u: m.username,
                path,
            },
            DataEvent::Renamed { from, to } => ServerThreadMessage::Renamed {
                u: m.username,
                from,
                to,
            },
        };

        let _ = self.tx.send(evt);
    }
}

async fn run_ftp_server_worker(
    auth: AuthTokens,
    session_store: SessionStore,
    tx: UnboundedSender<ServerThreadMessage>,
    config: ServerConfig,
) {
    let greeting: &'static str = Box::leak(config.greeting.clone().into_boxed_str());

    let presence_notif = PresenceNotifier::new(tx.clone());
    let data_notif = DataNotifier::new(tx.clone());

    let mut server_builder = libunftp::ServerBuilder::new(Box::new(move || {
        let pgp = proton_crypto::new_pgp_provider();
        let srp = proton_crypto::new_srp_provider();
        ProtonDriveStorage::new(pgp, srp, auth.clone(), session_store.clone())
            .expect("Couldn't initialize FTP Server")
    }))
    .greeting(greeting)
    .idle_session_timeout(86400)
    .notify_presence(presence_notif)
    .notify_data(data_notif);

    if let Some(auth_file) = config.auth_json {
        match JsonFileAuthenticator::from_file(&auth_file) {
            Ok(a) => server_builder = server_builder.authenticator(Arc::new(a)),
            Err(e) => error!("Couldn't initialize authentication: {e}"),
        }
    }

    if config.tls
        && let Some(cert) = config.tls_cert
        && let Some(key) = config.tls_key
    {
        server_builder = server_builder.ftps(cert, key);
    }

    let Ok(server) = server_builder.build() else {
        error!("Coudln't build FTP server");
        return;
    };

    let _ = server.listen(format!("0.0.0.0:{}", config.port)).await;
}
