use crate::client::authenticator::AuthTokens;
use crate::client::photos::Photos;
use crate::client::session_store::SessionStore;
use crate::errors::Result;
use crate::remote::payloads::{DecryptedNode, NodeType};
use crate::uids::split_node_revision_uid;
use crate::{
    client::{cache::Cache, crypto::Crypto, nodes::Nodes, shares::Shares},
    errors::APIError,
    remote::{self, downloader::FileDownloader},
    uids::make_node_uid,
};
use proton_crypto::crypto::PGPProviderSync;

#[derive(Debug)]
pub struct PDClient<
    PGPProv: proton_crypto::crypto::PGPProviderSync,
    SRPProv: proton_crypto::srp::SRPProvider,
> {
    remote_client: remote::Client,
    crypto: Crypto<PGPProv, SRPProv>,
    cache: Cache<PGPProv>,
    nodes: Nodes<PGPProv, SRPProv>,
    shares: Shares<PGPProv, SRPProv>,
    photos: Photos<PGPProv, SRPProv>,
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync, SRPProv: proton_crypto::srp::SRPProvider>
    PDClient<PGPProv, SRPProv>
{
    /// Creates a new Proton Drive client bound to the given authenticated session.
    ///
    /// Initializes the remote client with the provided `auth` tokens and prepares
    /// cryptographic helpers and caches to interact with Proton Drive.
    ///
    /// # Errors
    ///
    /// This constructor does not return errors.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn new(
        pgp_provider: PGPProv,
        srp_provider: SRPProv,
        auth: AuthTokens,
        session_store: SessionStore,
        worker_count: usize,
    ) -> Self {
       
        let mut remote_client = remote::Client::new();
        remote_client.set_tokens(auth);
        remote_client.start_workers(worker_count);

        Self {
            remote_client,
            crypto: Crypto::new(pgp_provider, srp_provider),
            cache: Cache::new(session_store),
            nodes: Nodes::new(),
            shares: Shares::new(),
            photos: Photos::new(),
        }
    }

    /// Retrieves the decrypted metadata for the user's My Files root folder.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching identifiers, nodes, or decrypting metadata fails,
    /// or if the remote API returns an error.
    pub async fn get_myfiles_root_folder(&self) -> Result<Node> {
        let ids = self
            .shares
            .get_myfiles_ids(&self.cache, &self.crypto, &self.remote_client)
            .await?;
        let node_uid = make_node_uid(&ids.VolumeID, &ids.RootNodeId);
        let nodes = self
            .nodes
            .get_nodes(
                vec![node_uid],
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        nodes
            .into_iter()
            .next()
            .map(std::convert::Into::into)
            .ok_or(APIError::Node("Node not found.".to_owned()))
    }

    pub async fn get_photos_root_folder(&self) -> Result<Node> {
        let ids = self
            .shares
            .get_photos_share_ids(&self.cache, &self.crypto, &self.remote_client)
            .await?;
        let node_uid = make_node_uid(&ids.VolumeID, &ids.RootNodeId);
        let nodes = self
            .nodes
            .get_nodes(
                vec![node_uid],
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        nodes
            .into_iter()
            .next()
            .map(std::convert::Into::into)
            .ok_or(APIError::Node("Node not found.".to_owned()))
    }

    /// Retrieves the decrypted metadata for a specific node.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching the node from the API fails or if decryption fails.
    pub async fn get_node(&self, node_uid: &str) -> Result<Node> {
        let node = self
            .nodes
            .get_single_node(
                node_uid.to_owned(),
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        Ok(node.into())
    }

    /// Renames a node to `new_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the rename operation fails remotely or if the node cannot
    /// be re-fetched/decrypted after the rename.
    pub async fn rename_node(&mut self, node_uid: &str, new_name: &str) -> Result<()> {
        self.nodes
            .rename_single_node(
                node_uid.to_owned(),
                new_name,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        let node = self.remote_client.get_node(node_uid).await?;
        let decrypted_node = self.crypto.decrypt_node(&node, &self.cache)?;
        self.cache.node_updated(decrypted_node);
        Ok(())
    }

    /// Creates a new folder with `folder_name` inside the folder identified by `parent_node_uid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent node cannot be retrieved, if creating the folder fails,
    /// or if the new folder cannot be fetched/decrypted.
    pub async fn create_folder(&self, parent_node_uid: String, folder_name: &str) -> Result<Node> {
        if let Ok(ids) = self
            .shares
            .get_photos_share_ids(&self.cache, &self.crypto, &self.remote_client)
            .await
            && parent_node_uid == make_node_uid(&ids.VolumeID, &ids.RootNodeId)
        {
            return self.create_album(folder_name).await;
        }

        let parent = self
            .nodes
            .get_single_node(
                parent_node_uid,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;

        if matches!(parent.encrypted.Type, NodeType::Album) {
            return Err(APIError::Node(
                "Can't create an album within an album.".to_string(),
            ));
        }

        let folder_uid = self
            .nodes
            .create_folder_node(
                parent,
                folder_name,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        let folder = self.get_node(&folder_uid).await?;
        Ok(folder)
    }

    async fn create_album(&self, album_name: &str) -> Result<Node> {
        let ids = self
            .shares
            .get_photos_share_ids(&self.cache, &self.crypto, &self.remote_client)
            .await?;
        let node_uid = make_node_uid(&ids.VolumeID, &ids.RootNodeId);
        let nodes = self
            .nodes
            .get_nodes(
                vec![node_uid],
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        let photos_root = nodes
            .first()
            .ok_or(APIError::Node("Couldn't find Photos share.".to_owned()))?;

        let uid = self
            .photos
            .create_album(
                photos_root,
                album_name,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        let folder = self.get_node(&uid).await?;
        Ok(folder)
    }

    /// Lists children of the specified folder.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching or decrypting child nodes fails.
    pub async fn folder_children(&self, parent_uid: &str) -> Result<Vec<Node>> {
        Ok(self
            .nodes
            .get_node_children(parent_uid, &self.cache, &self.crypto, &self.remote_client)
            .await?
            .into_iter()
            .map(std::convert::Into::into)
            .collect())
    }

    /// Builds a downloader for the specified file node.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The node is not a file.
    /// - The node has no active revision or session key.
    /// - Exporting cryptographic material fails.
    /// - Any remote API call fails.
    pub async fn get_node_downloader(&self, node_uid: &str) -> Result<FileDownloader> {
        let node = self
            .nodes
            .get_single_node(
                node_uid.to_owned(),
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;

        if node.encrypted.Type != NodeType::File {
            return Err(APIError::Node(format!("Not a file '{node_uid}'")));
        }

        let node_revision = node
            .encrypted
            .EncryptedCrypto
            .ActiveRevision
            .as_ref()
            .ok_or_else(|| {
                APIError::Node(format!(
                    "Node '{}' has no ActiveRevision.",
                    node.encrypted.Uid
                ))
            })?;

        if node.content_session_key.is_none() {
            return Err(APIError::Node(format!(
                "Node '{}' has no session key.",
                node.encrypted.Uid
            )));
        }

        let session_key = node
            .content_session_key
            .as_ref()
            .ok_or(APIError::Node("Couldn't find session key.".to_owned()))?;
        let session_key = self.crypto.export_session_key(session_key)?;
        let pgp_verification_key = node
            .name_verification_key
            .to_pgp(self.crypto.get_pgp_provider())?;
        let verification_key = self.crypto.export_public_key(&pgp_verification_key)?;

        let mut buff: Vec<u8> = vec![];
        buff.extend(session_key.as_ref());
        let session_key = buff.clone();

        buff.clear();
        buff.extend(verification_key.as_ref());
        let verification_key = buff.clone();

        let downloader = FileDownloader::new(
            self.remote_client.get_session(),
            node_revision.UID.clone(),
            session_key,
            verification_key,
        );

        Ok(downloader)
    }

    /// Uploads a file into the given parent folder, streaming from `reader`.
    ///
    /// # Errors
    ///
    /// Returns an error if preparing the upload, encrypting blocks, or any remote API
    /// operation fails.
    pub async fn upload_file<R>(
        &self,
        parent_node_uid: String,
        file_name: &str,
        reader: R,
    ) -> Result<usize>
    where
        R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    {
        let parent_node = self.get_node(&parent_node_uid).await?;

        if matches!(parent_node.node_type, TypeNode::Album) {
            return self
                .upload_photo_to_album(parent_node_uid, file_name, reader)
                .await;
        }
        
        let photos_root_ids = self
            .shares
            .get_photos_share_ids(&self.cache, &self.crypto, &self.remote_client)
            .await?;

        let is_in_photo_share = make_node_uid(&photos_root_ids.VolumeID, &photos_root_ids.RootNodeId) == parent_node_uid;

        let (len, _) = self
            .nodes
            .upload_file(
                parent_node_uid,
                file_name,
                is_in_photo_share,
                reader,
                &self.cache,
                &self.crypto,
                &self.photos,
                &self.remote_client,
            )
            .await?;

        Ok(len)
    }

    async fn upload_photo_to_album<R>(
        &self,
        parent_node_uid: String,
        file_name: &str,
        reader: R,
    ) -> Result<usize>
    where
        R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    {
        let photos_root_ids = self
            .shares
            .get_photos_share_ids(&self.cache, &self.crypto, &self.remote_client)
            .await?;

        let (len, node_revision_uid) = self
            .nodes
            .upload_file(
                make_node_uid(&photos_root_ids.VolumeID, &photos_root_ids.RootNodeId),
                file_name,
                reader,
                &self.cache,
                &self.crypto,
                &self.photos,
                &self.remote_client,
            )
            .await?;

        let (photo_volume_id, photo_node_id, _) = split_node_revision_uid(&node_revision_uid)?;
        let photo_node_uid = make_node_uid(&photo_volume_id, &photo_node_id);

        let photo_node = self
            .nodes
            .get_single_node(
                photo_node_uid,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;

        let album_node = self
            .nodes
            .get_single_node(
                parent_node_uid.clone(),
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;

        if self
            .photos
            .add_photo_to_album(
                &album_node,
                photo_node,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await
            .is_ok()
        {
            return Ok(len);
        }
        Err(APIError::Upload("Couldn't add photo to album.".to_string()))
    }

    /// Deletes the nodes identified by `node_uids` and updates the cache accordingly.
    ///
    /// Returns the list of failures as `(uid, error_message)` tuples.
    ///
    /// # Errors
    ///
    /// Returns an error if the deletion request fails remotely.
    pub async fn delete_nodes(&mut self, node_uids: Vec<String>) -> Result<Vec<(String, String)>> {
        let failed = self.remote_client.delete_nodes(&node_uids).await?;

        node_uids
            .iter()
            .filter(|uid| !failed.iter().any(|f| f.0 == **uid))
            .for_each(|uid| self.cache.remove_node(uid));

        Ok(failed)
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub creation_time: u64,
    pub author_name: String,
    pub node_type: TypeNode,
    pub uid: String,
}

impl<PGPProv> From<&DecryptedNode<PGPProv>> for Node
where
    PGPProv: PGPProviderSync,
{
    fn from(value: &DecryptedNode<PGPProv>) -> Self {
        Node {
            name: value.name.clone(),
            creation_time: value.encrypted.CreationTime,
            author_name: value.author_name.clone(),
            uid: value.encrypted.Uid.clone(),
            node_type: match value.encrypted.Type {
                NodeType::None => TypeNode::None,
                NodeType::File => TypeNode::File(TypeFileProperties {
                    size: usize::try_from(value.encrypted.TotalStorageSize.unwrap_or_default())
                        .unwrap_or_default(),
                }),
                NodeType::Folder => TypeNode::Folder(TypeFolderProperties {}),
                NodeType::Album => TypeNode::Album,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeFileProperties {
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeFolderProperties {}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeNode {
    None,
    File(TypeFileProperties),
    Folder(TypeFolderProperties),
    Photo,
    Album,
}
