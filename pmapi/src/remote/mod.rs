use crossbeam::channel;
use crate::remote::worker::WorkerTask;

pub mod downloader;

pub(crate) mod api_session;
pub(crate) mod auth;
pub(crate) mod nodes;
pub(crate) mod payloads;
pub(crate) mod shares;
pub(crate) mod upload;
pub(crate) mod photos;
pub(crate) mod worker;

#[derive(Debug)]
pub(crate) struct Client {
    api_session: api_session::APISession,
    workers_tx: Option<channel::Sender<WorkerTask>>,
}

impl Client {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            api_session: api_session::APISession::new(
                reqwest::Url::parse(crate::consts::URL_API_HOST).unwrap(),
            ),
            workers_tx: None,
        }
    }

    pub(crate) fn get_session(&self) -> &api_session::APISession {
        &self.api_session
    }
}
