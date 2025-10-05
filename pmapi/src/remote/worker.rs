use crate::{
    client::authenticator::AuthTokens,
    consts::{DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT, DRIVE_BLOCK_VERIFICATION_DATA_ENDPOINT},
    errors::{APIError, Result},
    remote::{
        api_session::{APISession, RequestType},
        payloads::{
            BlockUpload, BlockUploadRequest, BlockUploadResponse, BlockUploadVerifier,
            BlockVerificationData, CommitBlock, NodeBlock,
        },
    },
};
use base64::Engine;
use log::{error, info};
use proton_crypto::crypto::{Decryptor, DecryptorSync, PGPProviderSync, VerifiedData};
use sha1::Digest;
use tokio::sync::oneshot;

pub(crate) struct APIWorker {
    api_session: APISession,
    worker_rx: async_channel::Receiver<WorkerTask>,
}

pub(crate) enum WorkerTask {
    UploadBlock {
        reply: oneshot::Sender<Result<CommitBlock>>,
        revision_uid: String,
        block_index: usize,
        encrypted_data: Vec<u8>,
        hash: Vec<u8>,
        address_id: String,
        armored_signature: String,
    },
    DownloadBlock {
        reply: oneshot::Sender<Result<Vec<u8>>>,
        block: NodeBlock,
        session_key: Vec<u8>,
        verification_key: Vec<u8>,
    },
}

impl APIWorker {
    pub(crate) fn new(tokens: AuthTokens, worker_rx: async_channel::Receiver<WorkerTask>) -> Self {
        let mut api_session =
            APISession::new(reqwest::Url::parse(crate::consts::URL_API_HOST).unwrap());
        api_session.set_tokens(tokens);
        Self {
            api_session,
            worker_rx,
        }
    }

    pub(crate) async fn run(&self) {
        loop {
            match self.worker_rx.recv().await {
                Ok(task) => match task {
                    WorkerTask::UploadBlock {
                        reply,
                        revision_uid,
                        block_index,
                        encrypted_data,
                        hash,
                        address_id,
                        armored_signature,
                    } => {
                        let a = self
                            .upload_block(
                                &revision_uid,
                                block_index,
                                encrypted_data,
                                hash,
                                address_id,
                                armored_signature,
                            )
                            .await;
                        let _ = reply.send(a);
                    }
                    WorkerTask::DownloadBlock {
                        reply,
                        block,
                        session_key,
                        verification_key,
                    } => {
                        let a = self
                            .download_and_decrypt_block(block, &session_key, &verification_key)
                            .await;
                        let _ = reply.send(a);
                    }
                },
                Err(_) => {
                    error!("APIWorker channel closed.");
                    break;
                }
            }
        }
    }

    async fn download_and_decrypt_block(
        &self,
        block: NodeBlock,
        session_key: &[u8],
        verification_key: &[u8],
    ) -> Result<Vec<u8>> {
        let url = block
            .URL
            .as_ref()
            .ok_or_else(|| APIError::Download("Missing block URL".to_owned()))?;

        info!("Downloading block {} from {}", block.Index, url);

        let encrypted_block = self
            .api_session
            .request::<()>(RequestType::Get, url, None)
            .await?
            .bytes()
            .await
            .map_err(APIError::Reqwest)?
            .to_vec();

        let sha = sha2::Sha256::digest(&encrypted_block);
        let integrity = base64::prelude::BASE64_STANDARD.encode(sha) == block.Hash;
        if !integrity {
            return Err(APIError::Download(
                "Block integrity check failed".to_owned(),
            ));
        }

        let pgp_provider = proton_crypto::new_pgp_provider();

        let session_key = pgp_provider
            .session_key_import(
                session_key,
                proton_crypto::crypto::SessionKeyAlgorithm::Unknown,
            )
            .map_err(|e| APIError::PGP(format!("Couldn't import session key: {e}")))?;

        let verification_key = pgp_provider
            .public_key_import(verification_key, proton_crypto::crypto::DataEncoding::Armor)
            .map_err(|e| APIError::PGP(format!("Couldn't import public key: {e}")))?;

        let decryptor = pgp_provider
            .new_decryptor()
            .with_session_key_ref(&session_key)
            .with_verification_key(&verification_key);

        let decrypted_data = decryptor
            .decrypt(encrypted_block, proton_crypto::crypto::DataEncoding::Bytes)
            .map_err(|e| APIError::PGP(format!("Error decrypting block {}: {e}", block.Index)))?;

        if !decrypted_data.is_verified() {
            return Err(APIError::PGP(format!(
                "Couldn't verify block {}",
                block.Index
            )));
        }

        info!("Downloaded block {}", block.Index);

        Ok(decrypted_data.to_vec())
    }

    async fn upload_block(
        &self,
        revision_uid: &str,
        block_index: usize,
        encrypted_data: Vec<u8>,
        hash: Vec<u8>,
        address_id: String,
        armored_signature: String,
    ) -> Result<CommitBlock> {
        let verification_data = self.get_verification_data(revision_uid).await?;
        let verification_token: Vec<u8> = verification_data
            .VerificationCode
            .into_iter()
            .enumerate()
            .map(|(i, value)| value ^ encrypted_data.get(i).unwrap_or(&0))
            .collect();

        let url = self
            .get_block_upload_url(
                revision_uid,
                address_id,
                block_index,
                encrypted_data.len(),
                hash,
                armored_signature,
                verification_token,
            )
            .await?;

        let upload_link = url
            .UploadLinks
            .first()
            .ok_or(APIError::Upload("Couldn't retrieve upload url.".to_owned()))?;

        info!("Uploading block {} to {}", block_index, &upload_link.URL);
        self.api_session
            .post_multipart_form_data(&upload_link.URL, &upload_link.Token, &encrypted_data)
            .await?;
        info!("Uploaded block {}", block_index);

        Ok(CommitBlock {
            Index: block_index,
            Token: upload_link.Token.to_owned(),
            Size: encrypted_data.len(),
        })
    }

    async fn get_verification_data(
        &self,
        node_revision_uid: &str,
    ) -> Result<BlockVerificationData> {
        let (volume_id, node_id, revision_id) =
            crate::uids::split_node_revision_uid(node_revision_uid)?;

        let endpoint = DRIVE_BLOCK_VERIFICATION_DATA_ENDPOINT
            .replace("{volume_id}", &volume_id)
            .replace("{node_id}", &node_id)
            .replace("{revision_id}", &revision_id);

        let resp: BlockVerificationData = self
            .api_session
            .request_with_json_response(RequestType::Get, &endpoint, None::<&u8>)
            .await?;

        Ok(resp)
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_block_upload_url(
        &self,
        node_revision_uid: &str,
        address_id: String,
        block_index: usize,
        size: usize,
        hash: Vec<u8>,
        encrypted_signature: String,
        verification_token: Vec<u8>,
    ) -> Result<BlockUploadResponse> {
        let (volume_id, node_id, revision_id) =
            crate::uids::split_node_revision_uid(node_revision_uid)?;

        let endpoint = DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT;

        let payload = BlockUploadRequest {
            AddressID: address_id,
            VolumeID: volume_id,
            LinkID: node_id,
            RevisionID: revision_id,
            BlockList: vec![BlockUpload {
                Index: block_index,
                Hash: hash,
                EncSignature: encrypted_signature,
                Size: size,
                Verifier: BlockUploadVerifier {
                    Token: verification_token,
                },
            }],
            ThumbnailList: vec![],
        };

        let resp: BlockUploadResponse = self
            .api_session
            .request_with_json_response(RequestType::Post, endpoint, Some(&payload))
            .await?;

        Ok(resp)
    }
}
