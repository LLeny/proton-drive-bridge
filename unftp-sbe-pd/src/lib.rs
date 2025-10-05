use async_trait::async_trait;
use libunftp::auth::UserDetail;
use libunftp::storage::{Error, ErrorKind, Fileinfo, Metadata, Result, StorageBackend};
use log::info;
use pmapi::client::pdclient::{Node, TypeNode};
use pmapi::remote::downloader::FileDownloader;
use std::path::PathBuf;
use std::{fmt::Debug, path::Path};
use tokio::sync::mpsc;

use crate::worker::{
    PDCommand, send_create_folder, send_delete_nodes, send_folder_children, send_get_downloader,
    send_get_photos_root, send_get_root, send_rename_node, send_upload_file,
};

pub mod factory;
mod worker;

const ROOT_PATH: &str = "/";
const PHOTOS_FOLDER: &str = "drive_photos";
const PHOTOS_PATH: &str = "/drive_photos";
const READONLY_PATHS: [&str; 2] = [ROOT_PATH, PHOTOS_PATH];

type UploadReader = Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin + 'static>;

#[derive(Clone, Debug)]
pub struct Meta {
    inner: Node,
}

pub struct ProtonDriveStorage {
    pm_tx: mpsc::Sender<PDCommand>,
}

#[async_trait]
impl<User> StorageBackend<User> for ProtonDriveStorage
where
    User: UserDetail,
{
    type Metadata = Meta;

    fn supported_features(&self) -> u32 {
        libunftp::storage::FEATURE_SITEMD5 | libunftp::storage::FEATURE_RESTART
    }

    async fn metadata<P>(&self, _user: &User, path: P) -> Result<Self::Metadata>
    where
        P: AsRef<Path> + Send + Debug,
    {
        info!("Metadata: {:?}", &path);
        let node = self.get_node_from_path(path, false).await?;
        Ok(node.into())
    }

    async fn list<P>(&self, _user: &User, path: P) -> Result<Vec<Fileinfo<PathBuf, Self::Metadata>>>
    where
        P: AsRef<Path> + Send + Debug,
        <Self as StorageBackend<User>>::Metadata: Metadata,
    {
        info!("List: {:?}", &path);
        let node = self.get_node_from_path(path.as_ref(), false).await?;

        if !matches!(node.node_type, TypeNode::Folder(_))
            && !matches!(node.node_type, TypeNode::Album)
        {
            return Err(Error::new(
                ErrorKind::PermanentDirectoryNotAvailable,
                "Not a directory.",
            ));
        }

        let path_buf = path.as_ref().to_path_buf();

        let mut children: Vec<Fileinfo<PathBuf, Self::Metadata>> =
            send_folder_children(&self.pm_tx, node.uid)
                .await?
                .into_iter()
                .map(|c| {
                    let mut local_path = path_buf.clone();
                    local_path.push(&c.name);
                    Fileinfo {
                        path: local_path,
                        metadata: c.into(),
                    }
                })
                .collect();

        if path_string(path.as_ref()) == ROOT_PATH
            && let Ok(photos) = send_get_photos_root(&self.pm_tx).await
        {
            children.push(Fileinfo {
                path: PathBuf::from(PHOTOS_PATH),
                metadata: photos.into(),
            });
        }

        Ok(children)
    }

    async fn get_into<'a, P, W: ?Sized>(
        &self,
        user: &User,
        path: P,
        start_pos: u64,
        output: &'a mut W,
    ) -> Result<u64>
    where
        W: tokio::io::AsyncWrite + Unpin + Sync + Send,
        P: AsRef<Path> + Send + Debug,
    {
        let mut reader = self.get(user, path, start_pos).await?;
        Ok(tokio::io::copy(&mut reader, output).await?)
    }

    async fn get<P>(
        &self,
        _user: &User,
        path: P,
        start_pos: u64,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>>
    where
        P: AsRef<Path> + Send + Debug,
    {
        if start_pos != 0 {
            return Err(Error::new(
                ErrorKind::LocalError,
                "Download resuming not supported.",
            ));
        }
        info!("Get: {:?}", &path);
        let downloader = self.get_downloader(path).await?;
        Ok(Box::new(downloader))
    }

    async fn del<P>(&self, _user: &User, path: P) -> Result<()>
    where
        P: AsRef<Path> + Send + Debug,
    {
        info!("Delete: {:?}", &path);
        if is_readonly(path.as_ref()) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("Path '{path:?}' is readonly"),
            ));
        }

        self.delete_by_path(path).await
    }

    async fn rmd<P>(&self, _user: &User, path: P) -> Result<()>
    where
        P: AsRef<Path> + Send + Debug,
    {
        info!("Delete directory: {:?}", &path);
        if is_readonly(path.as_ref()) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("Path '{path:?}' is readonly"),
            ));
        }

        self.delete_by_path(path).await
    }

    async fn cwd<P>(&self, _user: &User, _path: P) -> Result<()>
    where
        P: AsRef<Path> + Send + Debug,
    {
        Ok(())
    }

    async fn rename<P>(&self, _user: &User, from: P, to: P) -> Result<()>
    where
        P: AsRef<Path> + Send + Debug,
    {
        info!("Rename {from:?} to {to:?}");
        if is_readonly(from.as_ref()) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("Path '{from:?}' is readonly"),
            ));
        }

        let node = self.get_node_from_path(from.as_ref(), false).await?;
        let new_name = to
            .as_ref()
            .file_name()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::FileNameNotAllowedError,
                    "Missing destination file name",
                )
            })?
            .to_string_lossy()
            .into_owned();
        send_rename_node(&self.pm_tx, node.uid, new_name).await
    }

    async fn mkd<P>(&self, _user: &User, path: P) -> Result<()>
    where
        P: AsRef<Path> + Send + Debug,
    {
        info!("Creating folder: '{path:?}'");

        let path = path.as_ref();

        let folder_name = path
            .file_name()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::FileNameNotAllowedError,
                    "Missing destination folder",
                )
            })?
            .to_string_lossy()
            .into_owned();

        let parent_folder = path
            .parent()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::FileNameNotAllowedError,
                    "Couldn't idenfity parent destination folder",
                )
            })?
            .to_string_lossy()
            .into_owned();

        let parent_node = self.get_node_from_path(parent_folder, true).await?;

        let _ = send_create_folder(&self.pm_tx, parent_node.uid, folder_name).await?;
        Ok(())
    }

    async fn put<P, B>(&self, _user: &User, reader: B, path: P, start_pos: u64) -> Result<u64>
    where
        P: AsRef<Path> + Send + Debug,
        B: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    {
        if start_pos != 0 {
            return Err(Error::new(
                ErrorKind::LocalError,
                "Upload resuming not supported.",
            ));
        }
        info!("Uploading file: '{path:?}'");

        let path = path.as_ref();

        let file_name = path
            .file_name()
            .ok_or(Error::new(
                ErrorKind::FileNameNotAllowedError,
                "Couldn't identify file name",
            ))?
            .to_string_lossy()
            .into_owned();

        let parent_folder = path
            .parent()
            .ok_or(Error::new(
                ErrorKind::FileNameNotAllowedError,
                "Couldn't identify parent folder name",
            ))?
            .to_string_lossy()
            .into_owned();

        let parent_node = self.get_node_from_path(parent_folder, true).await?;

        let sent =
            send_upload_file(&self.pm_tx, parent_node.uid, file_name, Box::new(reader)).await?;

        Ok(sent as u64)
    }
}

impl ProtonDriveStorage {
    /// Creates a new storage backend connected to Proton Drive.
    ///
    /// Spawns a background worker thread to drive the Proton Drive client and
    /// returns a handle that implements `StorageBackend` for libunftp.
    ///
    /// # Errors
    ///
    /// Currently this function always returns `Ok`. The `Result` is reserved for
    /// potential initialization failures in the future.
    ///
    /// # Panics
    ///
    /// Panics if spawning the background worker thread fails.
    pub fn new(pm_tx: mpsc::Sender<PDCommand>) -> Result<Self> {
        Ok(Self { pm_tx })
    }

    async fn get_child(&self, parent_uid: &str, node_name: &str) -> Result<Node> {
        info!("get_child: {parent_uid:?} {node_name:?}");
        let child = send_folder_children(&self.pm_tx, parent_uid.to_owned())
            .await?
            .into_iter()
            .find(|c| c.name == node_name)
            .ok_or(Error::new(
                ErrorKind::LocalError,
                format!("Couldn't find node '{node_name}'."),
            ))?;
        Ok(child)
    }

    pub(crate) async fn get_node_from_path<P>(
        &self,
        path: P,
        create_if_inexistent: bool,
    ) -> Result<Node>
    where
        P: AsRef<Path> + Send + Debug,
    {
        info!("get_node_from_path: {path:?}");
        let split_path: Vec<String> = path
            .as_ref()
            .components()
            .skip(1)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();

        let path_string = path_string(path.as_ref());

        let mut current_node = send_get_root(&self.pm_tx).await?;

        if path_string == ROOT_PATH {
            return Ok(current_node);
        }

        for next_node_name in &split_path {
            info!("split path: {next_node_name:?}");

            if next_node_name == PHOTOS_FOLDER {
                current_node = send_get_photos_root(&self.pm_tx).await?;
                continue;
            }

            current_node = match self.get_child(&current_node.uid, next_node_name).await {
                Ok(n) => n,
                Err(e) => {
                    if create_if_inexistent {
                        send_create_folder(
                            &self.pm_tx,
                            current_node.uid.clone(),
                            next_node_name.clone(),
                        )
                        .await?
                    } else {
                        return Err(e);
                    }
                }
            };
            info!("child: {current_node:?}");
        }

        Ok(current_node)
    }

    pub(crate) async fn get_downloader<P>(&self, path: P) -> Result<FileDownloader>
    where
        P: AsRef<Path> + Send + Debug,
    {
        let node = self.get_node_from_path(path.as_ref(), false).await?;

        if !matches!(node.node_type, TypeNode::File(_)) {
            return Err(Error::new(
                ErrorKind::LocalError,
                format!("Not a file: '{path:?}'"),
            ));
        }

        send_get_downloader(&self.pm_tx, &node.uid).await
    }

    async fn delete_by_path<P>(&self, path: P) -> Result<()>
    where
        P: AsRef<Path> + Send + Debug,
    {
        if is_readonly(path.as_ref()) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("Path '{path:?}' is readonly"),
            ));
        }

        let node = self.get_node_from_path(path.as_ref(), false).await?;
        let failed = send_delete_nodes(&self.pm_tx, vec![node.uid]).await?;
        if failed.is_empty() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::LocalError, failed[0].1.clone()))
        }
    }
}

fn is_readonly<P>(path: P) -> bool
where
    P: AsRef<Path>,
{
    path.as_ref()
        //.canonicalize() //TODO: without hitting local FS...
        .to_str()
        .map(str::to_lowercase)
        .is_none_or(|lower| READONLY_PATHS.contains(&lower.as_str()))
}

impl From<Node> for Meta {
    fn from(value: Node) -> Self {
        Self { inner: value }
    }
}

impl Metadata for Meta {
    fn len(&self) -> u64 {
        match &self.inner.node_type {
            TypeNode::File(props) => props.size as u64,
            _ => 0,
        }
    }

    fn is_dir(&self) -> bool {
        matches!(&self.inner.node_type, TypeNode::Folder(_))
            || matches!(&self.inner.node_type, TypeNode::Album)
    }

    fn is_file(&self) -> bool {
        matches!(&self.inner.node_type, TypeNode::File(_))
    }

    fn is_symlink(&self) -> bool {
        false
    }

    fn modified(&self) -> libunftp::storage::Result<std::time::SystemTime> {
        Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(self.inner.creation_time))
    }

    fn gid(&self) -> u32 {
        0
    }

    fn uid(&self) -> u32 {
        0
    }
}

impl std::fmt::Debug for ProtonDriveStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtonDriveStorage").finish()
    }
}

fn path_string(path: &Path) -> String {
    path.to_str().unwrap_or(ROOT_PATH).to_owned()
}
