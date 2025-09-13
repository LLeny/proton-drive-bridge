use crate::errors::Result;
use crate::remote::payloads::{DecryptedNode, NodeType};
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
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync, SRPProv: proton_crypto::srp::SRPProvider>
    PDClient<PGPProv, SRPProv>
{
    /// Create a new `PDClient` instance.
    ///
    /// Initializes the remote client, cryptographic helpers and local caches using
    /// the provided PGP and SRP providers.
    ///
    /// Arguments:
    /// - `pgp_provider`: Implementation of `PGPProviderSync` used to handle `OpenPGP` operations.
    /// - `srp_provider`: Implementation of `SRPProvider` used for SRP authentication.
    pub fn new(pgp_provider: PGPProv, srp_provider: SRPProv) -> Self {
        Self {
            remote_client: remote::Client::new(),
            crypto: Crypto::new(pgp_provider, srp_provider),
            cache: Cache::new(),
            nodes: Nodes::new(),
            shares: Shares::new(),
        }
    }

    /// Log in to Proton Drive and initialize crypto context and caches.
    ///
    /// Performs authentication (with optional 2FA), fetches user profile, salts and
    /// addresses, and unlocks user and address keys needed to decrypt metadata.
    ///
    /// Arguments:
    /// - `username`: Proton username (email or identifier).
    /// - `password`: Proton mailbox password as a secret vector.
    /// - `two_fa`: Optional callback invoked to retrieve a 2FA code when required.
    ///
    /// Returns `Ok(())` on success, or an error if authentication or initialization fails.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Authentication fails (invalid credentials or 2FA),
    /// - Network or API requests fail while fetching user, salts, or addresses,
    /// - The user cannot be retrieved after authentication,
    /// - User or address keys cannot be unlocked/decrypted with the provided password.
    pub async fn login(
        &mut self,
        username: &str,
        password: Vec<u8>,
        two_fa: Option<fn() -> String>,
    ) -> Result<()> {
        self.remote_client
            .login_auth(username, &password, two_fa)
            .await?;

        self.crypto.set_password(password);

        let user = self
            .remote_client
            .get_user()
            .await?
            .ok_or(APIError::Account("Couldn't retrieve user.".into()))?;

        self.cache.set_user(user);

        self.cache.set_salt(self.remote_client.get_salts().await?);
        self.remote_client
            .get_addresses()
            .await?
            .into_iter()
            .for_each(|a| self.cache.add_address(a));

        self.crypto.unlock_user_keys(&self.cache)?;
        self.crypto.unlock_address_keys(&self.cache)?;

        Ok(())
    }

    /// Get the root folder node of "My files".
    ///
    /// Resolves the "My files" share and returns its root as a high-level `Node`.
    ///
    /// Returns the root node on success or an error if it cannot be resolved or decrypted.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The "My files" share IDs cannot be retrieved (network/API error),
    /// - The root node cannot be fetched or decrypted.
    pub async fn get_myfiles_root_folder(&self) -> Result<Node> {
        let ids = self
            .shares
            .get_myfiles_ids(&self.cache, &self.crypto, &self.remote_client)
            .await?;
        let node_uid = make_node_uid(&ids.VolumeID, &ids.RootNodeId);
        let mut nodes = self
            .nodes
            .get_nodes(
                vec![node_uid],
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        Ok(nodes.remove(0).into())
    }

    /// Fetch a single node by its UID.
    ///
    /// Decrypts the node metadata and returns a high-level `Node` wrapper.
    ///
    /// Arguments:
    /// - `node_uid`: Combined UID of the node (volume ID + node ID).
    ///
    /// # Errors
    /// Returns an error if the node cannot be fetched or its metadata cannot be decrypted.
    pub async fn get_node(&self, node_uid: &str) -> Result<Node> {
        let node = self
            .nodes
            .get_single_node(
                node_uid.to_string(),
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
        Ok(node.into())
    }

    /// Rename a node.
    ///
    /// Updates the node name server-side and refreshes the local cache with the
    /// newly decrypted node metadata.
    ///
    /// Arguments:
    /// - `node_uid`: UID of the node to rename.
    /// - `new_name`: The new display name for the node.
    ///
    /// # Errors
    /// Returns an error if the rename request fails, or if the updated node cannot be
    /// fetched or decrypted to refresh the cache.
    pub async fn rename_node(&mut self, node_uid: &str, new_name: &str) -> Result<()> {
        self.nodes
            .rename_single_node(
                node_uid.to_string(),
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

    /// Create a folder under a parent node.
    ///
    /// Arguments:
    /// - `parent_node_uid`: UID of the parent folder.
    /// - `folder_name`: Name of the new folder.
    ///
    /// Returns the created folder as a `Node`.
    ///
    /// # Errors
    /// Returns an error if the parent cannot be fetched/decrypted, if folder creation
    /// fails on the server, or if the created folder cannot be fetched/decrypted.
    pub async fn create_folder(&self, parent_node_uid: String, folder_name: &str) -> Result<Node> {
        let parent = self
            .nodes
            .get_single_node(
                parent_node_uid,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await?;
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

    /// List the children of a folder.
    ///
    /// Arguments:
    /// - `parent_uid`: UID of the parent folder.
    ///
    /// Returns all direct child nodes (files and subfolders).
    ///
    /// # Errors
    /// Returns an error if the children cannot be listed or their metadata cannot be
    /// decrypted.
    pub async fn folder_children(&self, parent_uid: &str) -> Result<Vec<Node>> {
        Ok(self
            .nodes
            .get_node_children(parent_uid, &self.cache, &self.crypto, &self.remote_client)
            .await?
            .into_iter()
            .map(std::convert::Into::into)
            .collect())
    }

    /// Create a downloader for a file node.
    ///
    /// Validates that the referenced node is a file with an active revision and a
    /// session key, then prepares a `FileDownloader` configured with the proper
    /// session and verification keys for streaming the file contents.
    ///
    /// Arguments:
    /// - `node_uid`: UID of the file node to download.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The node cannot be fetched or decrypted,
    /// - The node is not a file,
    /// - The node has no active revision,
    /// - The node has no session key,
    /// - Session or verification keys cannot be exported by the crypto provider.
    pub async fn get_node_downloader(&self, node_uid: &str) -> Result<FileDownloader> {
        let node = self
            .nodes
            .get_single_node(
                node_uid.to_string(),
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
            .ok_or(APIError::Node("Couldn't find session key.".to_string()))?;
        let session_key = self.crypto.export_session_key(session_key)?;
        let verification_key = self.crypto.export_public_key(&node.name_verification_key)?;

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

    /// Upload a file into a folder.
    ///
    /// Encrypts and uploads the data from the provided async reader to the remote
    /// service as a new file under the given parent folder.
    ///
    /// Arguments:
    /// - `parent_node_uid`: UID of the parent folder.
    /// - `file_name`: Destination file name.
    /// - `reader`: Async reader providing the file's bytes.
    ///
    /// Returns the number of bytes successfully uploaded.
    ///
    /// # Errors
    /// Returns an error if the upload fails due to network/API issues, encryption
    /// or key-handling errors, or if the parent folder is invalid/inaccessible.
    pub async fn upload_file<R>(
        &self,
        parent_node_uid: String,
        file_name: &str,
        reader: R,
    ) -> Result<usize>
    where
        R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    {
        self.nodes
            .upload_file(
                parent_node_uid,
                file_name,
                reader,
                &self.cache,
                &self.crypto,
                &self.remote_client,
            )
            .await
    }

    /// Delete multiple nodes by UID.
    ///
    /// Arguments:
    /// - `node_uids`: UIDs of nodes to delete.
    ///
    /// Returns a list of failures as `(uid, reason)` tuples. Any node not listed
    /// in the returned vector was successfully deleted and is pruned from the cache.
    ///
    /// # Errors
    /// Returns an error if the delete request fails.
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
}
