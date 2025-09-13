use crate::errors::Result;
use crate::remote::payloads::{DecryptedNode, EncryptedNodeFile, NodeType};
use crate::{
    client::{cache::Cache, crypto::Crypto},
    errors::APIError,
    uids::{make_node_uid, split_node_uid},
};
use proton_crypto::{crypto::PGPProviderSync, srp::SRPProvider};
use std::{fmt::Debug, marker::PhantomData};

pub(crate) struct Nodes<PGPProv: PGPProviderSync, SRPPRov: SRPProvider> {
    _pgp: PhantomData<PGPProv>,
    _srp: PhantomData<SRPPRov>,
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync, SRPProv: proton_crypto::srp::SRPProvider>
    Nodes<PGPProv, SRPProv>
{
    pub(crate) fn new() -> Self {
        Self {
            _pgp: PhantomData,
            _srp: PhantomData,
        }
    }

    pub(crate) async fn get_nodes<'c>(
        &'c self,
        node_uids: impl AsRef<[String]>,
        cache: &'c Cache<PGPProv>,
        crypto: &'c Crypto<PGPProv, SRPProv>,
        remote_client: &'c crate::remote::Client,
    ) -> Result<Vec<&'c DecryptedNode<PGPProv>>> {
        let to_query: Vec<String> = node_uids
            .as_ref()
            .iter()
            .filter(|n| !cache.contains_encrypted_node(n))
            .cloned()
            .collect();

        if !to_query.is_empty() {
            for node in remote_client.get_nodes(&to_query).await? {
                let decrypted_node = crypto.decrypt_node(&node, cache)?;
                cache.add_decrypted_node(decrypted_node.encrypted.Uid.clone(), decrypted_node);
            }
        }

        let nodes = node_uids
            .as_ref()
            .iter()
            .map(|uid| {
                cache.get_decrypted_node(uid).ok_or(APIError::Node(format!(
                    "Node not found '{uid}'"
                )))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(nodes)
    }

    pub(crate) async fn get_single_node<'c>(
        &'c self,
        node_uid: String,
        cache: &'c Cache<PGPProv>,
        crypto: &'c Crypto<PGPProv, SRPProv>,
        remote_client: &'c crate::remote::Client,
    ) -> Result<&'c DecryptedNode<PGPProv>> {
        Ok(self
            .get_nodes(vec![node_uid], cache, crypto, remote_client)
            .await?
            .remove(0))
    }

    pub(crate) async fn get_node_children<'c>(
        &'c self,
        node_uid: &'c str,
        cache: &'c Cache<PGPProv>,
        crypto: &'c Crypto<PGPProv, SRPProv>,
        remote_client: &'c crate::remote::Client,
    ) -> Result<Vec<&'c DecryptedNode<PGPProv>>> {
        let (volume_id, node_id) = split_node_uid(node_uid)?;
        let ids = remote_client
            .get_node_children_link_ids(volume_id.as_str(), node_id.as_str())
            .await?;
        let uids: Vec<String> = ids.iter().map(|id| make_node_uid(&volume_id, id)).collect();
        self.get_nodes(uids, cache, crypto, remote_client).await
    }

    pub async fn rename_single_node(
        &self,
        node_uid: String,
        new_name: &str,
        cache: &Cache<PGPProv>,
        crypto: &Crypto<PGPProv, SRPProv>,
        remote_client: &crate::remote::Client,
    ) -> Result<()> {
        let node = self
            .get_single_node(node_uid.clone(), cache, crypto, remote_client)
            .await?;

        let parent_uid = node
            .encrypted
            .ParentUid
            .as_ref()
            .ok_or(APIError::Node(format!(
                "Coudln't find parent of '{node_uid}'"
            )))?;

        let parent = self
            .get_single_node(parent_uid.to_string(), cache, crypto, remote_client)
            .await?;
        let parent_folder = parent
            .encrypted
            .EncryptedCrypto
            .Folder
            .as_ref()
            .ok_or(APIError::Node("Parent should be a folder.".into()))?;
        let parent_hashkey = &parent_folder.ArmoredHashKey;

        let params = crypto.encrypt_new_node_name(
            parent,
            &node.encrypted.Type,
            node.encrypted.Hash.as_deref(),
            parent_hashkey,
            new_name,
            cache,
        )?;
        remote_client.rename_node(&node_uid, &params).await
    }

    pub async fn create_folder_node(
        &self,
        parent_node: &DecryptedNode<PGPProv>,
        name: &str,
        cache: &Cache<PGPProv>,
        crypto: &Crypto<PGPProv, SRPProv>,
        remote_client: &crate::remote::Client,
    ) -> Result<String> {
        let user = cache
            .get_user()
            .ok_or(APIError::Node("Coudln't retrieve user".into()))?;

        let verification_key = cache
            .get_unlocked_address_key(&user.Email)
            .ok_or(APIError::Account(
                "Couldn't retrieve user address keys".into(),
            ))?
            .into_iter()
            .next() //TODO: pick first for now
            .ok_or(APIError::Account(
                "No unlocked address keys available".into(),
            ))?;

        let (node_crypto, node_private_key) = crypto.create_new_node_encrypted_crypto(
            user,
            &parent_node.keys.public_key,
            &verification_key.private_key,
        )?;

        let parent_hash_key = parent_node
            .hash_key
            .as_ref()
            .ok_or(APIError::Node("hash_key required.".into()))?;

        let node_hash_key = crypto.encrypt_hash_key(
            Crypto::<PGPProv, SRPProv>::generate_hashkey().as_ref(),
            &node_private_key,
            &verification_key.private_key,
        )?;

        let params = crypto.encrypt_new_node_name(
            parent_node,
            &NodeType::Folder,
            None,
            parent_hash_key,
            name,
            cache,
        )?;
        let node_id = remote_client
            .create_node(
                &parent_node.encrypted.Uid,
                params.Name,
                node_hash_key,
                params.Hash,
                &node_crypto,
            )
            .await?;

        let (volume_id, _) = split_node_uid(&parent_node.encrypted.Uid)?;
        Ok(make_node_uid(&volume_id, &node_id))
    }

    pub(crate) async fn upload_file<'c, R>(
        &'c self,
        parent_node_uid: String,
        file_name: &str,
        reader: R,
        cache: &'c Cache<PGPProv>,
        crypto: &'c Crypto<PGPProv, SRPProv>,
        remote_client: &'c crate::remote::Client,
    ) -> Result<usize>
    where
        R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static,
    {
        let parent_node = self
            .get_single_node(parent_node_uid, cache, crypto, remote_client)
            .await?;

        let user = cache
            .get_user()
            .ok_or(APIError::Account("User not loaded".into()))?;

        let address_id = cache
            .addresses()
            .iter()
            .find(|a| a.Email == user.Email)
            .map(|a| a.ID.clone())
            .ok_or(APIError::Account(
                "Couldn't retrieve user's address.".into(),
            ))?;

        let verification_key = cache
            .get_unlocked_address_key(&user.Email)
            .ok_or(APIError::Account(
                "Couldn't retrieve user address keys".into(),
            ))?
            .into_iter()
            .next() //TODO: pick first for now
            .ok_or(APIError::Account(
                "No unlocked address keys available".into(),
            ))?;

        let (mut node_crypto, node_private_key) = crypto.create_new_node_encrypted_crypto(
            user,
            &parent_node.keys.public_key,
            &verification_key.private_key,
        )?;

        let content_keys = crypto.generate_node_file_content_key(&node_private_key)?;

        node_crypto.File = Some(EncryptedNodeFile {
            ContentKeyPacket: content_keys.encrypted_session_key,
            ArmoredContentKeyPacketSignature: Some(
                String::from_utf8(content_keys.armored_session_key_signature)
                    .map_err(|e| APIError::PGP(format!(
                        "Couldn't parse armored session key signature as UTF-8: {e}"
                    )))?,
            ),
        });

        let parent_hash_key = parent_node
            .hash_key
            .as_ref()
            .ok_or(APIError::Node("hash_key required.".into()))?;

        let name_params = crypto.encrypt_new_node_name(
            parent_node,
            &NodeType::File,
            None,
            parent_hash_key,
            file_name,
            cache,
        )?;

        let intended_upload_size = None; //TODO

        let node_draft = remote_client
            .create_node_draft(
                &node_crypto,
                &parent_node.encrypted.Uid,
                &name_params,
                intended_upload_size,
            )
            .await?;

        let uploaded = remote_client
            .upload_node_blocks(
                &node_draft.node_revision_uid,
                user.Email.clone(),
                &node_private_key,
                &content_keys.content_key_packet_session_key,
                &verification_key.private_key,
                address_id,
                reader,
                crypto,
            )
            .await;

        if uploaded.is_err() {
            remote_client.delete_draft(&node_draft.node_uid).await?;
        }

        uploaded
    }
}

impl<PGPPRov: PGPProviderSync, SRPPRov: SRPProvider> Debug for Nodes<PGPPRov, SRPPRov> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nodes").finish()
    }
}
