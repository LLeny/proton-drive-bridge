use crate::UploadReader;
use libunftp::storage::{Error, ErrorKind, Result};
use log::error;
use pmapi::{
    client::{
        authenticator::AuthTokens,
        pdclient::{Node, PDClient},
        session_store::SessionStore,
    },
    remote::downloader::FileDownloader,
};
use proton_crypto::{new_pgp_provider, new_srp_provider};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

async fn send_and_wait<T>(
    tx: &Sender<PDCommand>,
    make_cmd: impl FnOnce(oneshot::Sender<std::result::Result<T, String>>) -> PDCommand,
) -> Result<T> {
    let (reply, rx) = oneshot::channel();
    tx.send(make_cmd(reply))
        .await
        .map_err(|e| Error::new(ErrorKind::LocalError, e.to_string()))?;
    rx.await
        .map_err(|e| Error::new(ErrorKind::LocalError, e.to_string()))?
        .map_err(log_pd_error)
}

pub enum PDCommand {
    GetPhotosRoot {
        reply: oneshot::Sender<std::result::Result<Node, String>>,
    },
    GetRoot {
        reply: oneshot::Sender<std::result::Result<Node, String>>,
    },
    FolderChildren {
        uid: String,
        reply: oneshot::Sender<std::result::Result<Vec<Node>, String>>,
    },
    GetDownloader {
        uid: String,
        reply: oneshot::Sender<std::result::Result<FileDownloader, String>>,
    },
    DeleteNodes {
        node_uids: Vec<String>,
        reply: oneshot::Sender<std::result::Result<Vec<(String, String)>, String>>,
    },
    RenameNode {
        uid: String,
        new_name: String,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    CreateFolder {
        parent_node_uid: String,
        folder_name: String,
        reply: oneshot::Sender<std::result::Result<Node, String>>,
    },
    UploadFile {
        parent_node_uid: String,
        file_name: String,
        reader: UploadReader,
        reply: oneshot::Sender<std::result::Result<usize, String>>,
    },
}

pub(crate) async fn run_pdclient_worker(
    mut command_rx: Receiver<PDCommand>,
    auth: AuthTokens,
    session_store: SessionStore,
    worker_count: usize,
) {
    let pgp_provider = new_pgp_provider();
    let srp_provider = new_srp_provider();
    let mut pm_client = PDClient::new(
        pgp_provider,
        srp_provider,
        auth,
        session_store,
        worker_count,
    );
    while let Some(cmd) = command_rx.recv().await {
        match cmd {
            PDCommand::GetPhotosRoot { reply } => {
                let res = pm_client
                    .get_photos_root_folder()
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::GetRoot { reply } => {
                let res = pm_client
                    .get_myfiles_root_folder()
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::FolderChildren { uid, reply } => {
                let res = pm_client
                    .folder_children(&uid)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::GetDownloader { uid, reply } => {
                let res = pm_client
                    .get_node_downloader(&uid)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::DeleteNodes { node_uids, reply } => {
                let res = pm_client
                    .delete_nodes(node_uids)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::RenameNode {
                uid,
                new_name,
                reply,
            } => {
                let res = pm_client
                    .rename_node(&uid, &new_name)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::CreateFolder {
                parent_node_uid,
                folder_name,
                reply,
            } => {
                let res = pm_client
                    .create_folder(parent_node_uid, &folder_name)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
            PDCommand::UploadFile {
                parent_node_uid,
                file_name,
                reader,

                reply,
            } => {
                let res = pm_client
                    .upload_file(parent_node_uid, &file_name, reader)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply.send(res);
            }
        }
    }
}

pub(crate) async fn send_upload_file(
    tx: &Sender<PDCommand>,
    parent_node_uid: String,
    file_name: String,
    reader: UploadReader,
) -> Result<usize> {
    send_and_wait(tx, |reply| PDCommand::UploadFile {
        parent_node_uid,
        file_name,
        reader,
        reply,
    })
    .await
}

pub(crate) async fn send_create_folder(
    tx: &Sender<PDCommand>,
    parent_node_uid: String,
    folder_name: String,
) -> Result<Node> {
    send_and_wait(tx, |reply| PDCommand::CreateFolder {
        parent_node_uid,
        folder_name,
        reply,
    })
    .await
}

pub(crate) async fn send_delete_nodes(
    tx: &Sender<PDCommand>,
    node_uids: Vec<String>,
) -> Result<Vec<(String, String)>> {
    send_and_wait(tx, |reply| PDCommand::DeleteNodes { node_uids, reply }).await
}

pub(crate) async fn send_rename_node(
    tx: &Sender<PDCommand>,
    node_uid: String,
    new_name: String,
) -> Result<()> {
    send_and_wait(tx, |reply| PDCommand::RenameNode {
        uid: node_uid,
        new_name,
        reply,
    })
    .await
}

pub(crate) async fn send_get_root(tx: &Sender<PDCommand>) -> Result<Node> {
    send_and_wait(tx, |reply| PDCommand::GetRoot { reply }).await
}

pub(crate) async fn send_get_photos_root(tx: &Sender<PDCommand>) -> Result<Node> {
    send_and_wait(tx, |reply| PDCommand::GetPhotosRoot { reply }).await
}

pub(crate) async fn send_folder_children(
    tx: &Sender<PDCommand>,
    uid: impl Into<String>,
) -> Result<Vec<Node>> {
    let uid = uid.into();
    send_and_wait(tx, |reply| PDCommand::FolderChildren { uid, reply }).await
}

pub(crate) async fn send_get_downloader(
    tx: &Sender<PDCommand>,
    uid: impl Into<String>,
) -> Result<FileDownloader> {
    let uid = uid.into();
    send_and_wait(tx, |reply| PDCommand::GetDownloader { uid, reply }).await
}

fn log_pd_error(err: String) -> Error {
    error!("Proton Drive error: {err}");
    Error::new(ErrorKind::LocalError, err)
}
