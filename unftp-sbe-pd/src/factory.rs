use crate::{
    worker::{run_pdclient_worker, PDCommand}, ProtonDriveStorage
};
use pmapi::client::{authenticator::AuthTokens, session_store::SessionStore};
use tokio::{sync::mpsc, task::JoinHandle};

#[allow(dead_code)]
pub struct Factory {
    command_tx: mpsc::Sender<PDCommand>,
    worker: JoinHandle<()>,
}   

impl Factory {
    pub fn new(auth: AuthTokens, session_store: SessionStore, worker_count: usize) -> Self {
        let (command_tx, command_rx) = mpsc::channel(64);

        let worker = tokio::spawn(
            run_pdclient_worker(command_rx, auth, session_store, worker_count)
        );

        Self { command_tx, worker }
    }

    pub fn new_protondrive_storage_client(
        &self,
    ) -> Result<ProtonDriveStorage, libunftp::storage::Error> {
        ProtonDriveStorage::new(self.command_tx.clone())
    }
}
