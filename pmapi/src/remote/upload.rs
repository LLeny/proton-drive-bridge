use crate::client::photos::Photos;
use crate::consts::{MAX_THUMBNAIL_BORDER_LEN, MAX_THUMBNAIL_SIZE};
use crate::errors::Result;
use crate::remote::api_session::RequestType;
use crate::remote::payloads::{
    BlockUploadRequest, BlockUploadResponse, CommitBlock, CommitDraftPhoto, CommitDraftRequest,
    CommitDraftResponse, FileExtendedAttributesSchema, FileExtendedAttributesSchemaCommon,
    FileExtendedAttributesSchemaDigest, PrivateKey, ThumbnailType, ThumbnailUpload,
};
use crate::remote::worker::{APIWorker, WorkerTask};
use crate::{
    client::crypto::Crypto,
    consts::{
        DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT, DRIVE_COMMIT_REVISION_ENDPOINT, FILE_CHUNK_SIZE,
    },
    errors::APIError,
    remote::Client,
};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use futures::{Stream, StreamExt, TryFutureExt};
use itertools::Itertools;
use proton_crypto::crypto::PGPProviderSync;
use proton_crypto::srp::SRPProvider;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::oneshot;

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn upload_node_blocks<Reader, PGPProv, SRPProv>(
        &self,
        revision_uid: &str,
        signature_email: String,
        is_image: bool,
        node_key: &PGPProv::PrivateKey,
        session_key: &PGPProv::SessionKey,
        address_key: &PrivateKey,
        address_id: String,
        reader: Reader,
        crypto: &Crypto<PGPProv, SRPProv>,
        photo: &Photos<PGPProv, SRPProv>,
    ) -> Result<usize>
    where
        PGPProv: PGPProviderSync,
        SRPProv: SRPProvider,
        Reader: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let address_key = address_key.to_pgp(crypto.get_pgp_provider())?;

        let (blocks, manifest, total_read, blocks_sha1, image_data) = self
            .process_blocks(
                reader,
                is_image,
                session_key,
                node_key,
                &address_key,
                revision_uid,
                address_id.clone(),
                crypto,
            )
            .await?;

        let blocks: Vec<CommitBlock> = join_all(blocks)
            .await
            .into_iter()
            .map(|r| r.map_err(|e| APIError::Upload(e.to_string()))?)
            .collect::<Result<Vec<_>>>()
            .map_err(|e| APIError::Upload(e.to_string()))?;

        let mut final_manifest = manifest;
        if is_image {
            let thumbnail_hash = self
                .handle_thumbnail_upload(
                    revision_uid,
                    &image_data,
                    photo,
                    crypto,
                    session_key,
                    &address_key,
                    address_id,
                )
                .await?;
            final_manifest.splice(0..0, thumbnail_hash);
        }

        self.commit_upload(
            revision_uid,
            signature_email,
            &final_manifest,
            &blocks,
            total_read,
            &blocks_sha1,
            is_image,
            crypto,
            node_key,
            &address_key,
        )
        .await?;

        Ok(blocks.iter().map(|b| b.Size).sum())
    }

    async fn process_blocks<Reader, PGPProv, SRPProv>(
        &self,
        mut reader: Reader,
        is_image: bool,
        session_key: &PGPProv::SessionKey,
        node_key: &PGPProv::PrivateKey,
        address_key: &PGPProv::PrivateKey,
        revision_uid: &str,
        address_id: String,
        crypto: &Crypto<PGPProv, SRPProv>,
    ) -> Result<(
        Vec<oneshot::Receiver<Result<CommitBlock>>>,
        Vec<u8>,
        usize,
        Sha1,
        Vec<u8>,
    )>
    where
        PGPProv: PGPProviderSync,
        SRPProv: SRPProvider,
        Reader: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let mut block_index = 1;
        let mut manifest = Vec::new();
        let mut total_read = 0;
        let mut blocks_sha1 = Sha1::new();
        let mut image_data = Vec::new();
        let mut commit_rxs = Vec::new();

        while let Some(chunk) = Box::pin(Self::read_chunks(&mut reader, FILE_CHUNK_SIZE))
            .next()
            .await
        {
            let buf = chunk?;
            let n = buf.len();

            if is_image {
                image_data.extend_from_slice(&buf);
            }

            total_read += n;
            blocks_sha1.update(&buf);

            let (encrypted, armored_signature) =
                crypto.encrypt_block(session_key, node_key, address_key, &buf)?;

            let hash = Sha256::digest(&encrypted);
            manifest.extend(hash);

            let commit_rx = self
                .send_upload_work(
                    revision_uid.to_owned(),
                    block_index,
                    encrypted,
                    hash.to_vec(),
                    address_id.clone(),
                    armored_signature,
                )
                .await?;

            commit_rxs.push(commit_rx);
            block_index += 1;
        }

        Ok((commit_rxs, manifest, total_read, blocks_sha1, image_data))
    }

    async fn handle_thumbnail_upload<PGPProv, SRPProv>(
        &self,
        revision_uid: &str,
        image_data: &[u8],
        photo: &Photos<PGPProv, SRPProv>,
        crypto: &Crypto<PGPProv, SRPProv>,
        session_key: &PGPProv::SessionKey,
        address_key: &PGPProv::PrivateKey,
        address_id: String,
    ) -> Result<Vec<u8>>
    where
        PGPProv: PGPProviderSync,
        SRPProv: SRPProvider,
    {
        let mut border_len = MAX_THUMBNAIL_BORDER_LEN;
        let thumbnail = loop {
            let thumb = photo.create_thumbnail(image_data, border_len);
            match thumb {
                Ok(t) if t.len() >= MAX_THUMBNAIL_SIZE => {
                    border_len = border_len * 9 / 10;
                    continue;
                }
                Ok(t) => break t,
                Err(e) => return Err(e),
            }
        };

        let encrypted_thumbnail =
            crypto.encrypted_thumbnail(session_key, address_key, &thumbnail)?;
        let hash = Sha256::digest(&encrypted_thumbnail);

        self.upload_thumbnail(
            revision_uid,
            address_id,
            encrypted_thumbnail.as_slice(),
            hash.to_vec(),
        )
        .await?;

        Ok(hash.to_vec())
    }

    async fn commit_upload<PGPProv, SRPProv>(
        &self,
        revision_uid: &str,
        signature_email: String,
        manifest: &[u8],
        blocks: &[CommitBlock],
        total_read: usize,
        blocks_sha1: &Sha1,
        is_image: bool,
        crypto: &Crypto<PGPProv, SRPProv>,
        node_key: &PGPProv::PrivateKey,
        address_key: &PGPProv::PrivateKey,
    ) -> Result<()>
    where
        PGPProv: PGPProviderSync,
        SRPProv: SRPProvider,
    {
        let manifest_signature = crypto.sign_manifest(manifest, address_key)?;
        let sha1 = hex::encode(blocks_sha1.clone().finalize());

        let xattr = Self::generate_and_encrypt_xattr(
            crypto,
            total_read,
            blocks,
            &sha1,
            node_key,
            address_key,
        )?;

        self.commit_revision(
            revision_uid,
            signature_email,
            manifest_signature,
            xattr,
            is_image,
            &sha1,
        )
        .await
    }

    fn read_chunks<Reader>(
        reader: &mut Reader,
        chunk_size: usize,
    ) -> impl Stream<Item = Result<Vec<u8>>>
    where
        Reader: AsyncRead + Send + Sync + Unpin + 'static,
    {
        async_stream::try_stream! {
            let mut buf = vec![0u8; chunk_size];

            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| APIError::Upload(e.to_string()))
                    .await?;

                if n == 0 {
                    break;
                }

                yield buf[..n].to_vec();
            }
        }
    }

    pub(crate) async fn upload_thumbnail(
        &self,
        node_revision_uid: &str,
        address_id: String,
        encrypted_thumbnail: impl AsRef<[u8]>,
        hash: Vec<u8>,
    ) -> Result<String> {
        let url = self
            .get_thumbnail_upload_url(
                node_revision_uid,
                address_id,
                encrypted_thumbnail.as_ref().len(),
                hash,
            )
            .await?;

        let upload_link = url
            .ThumbnailLinks
            .first()
            .ok_or(APIError::Upload("Coudln't retrieve upload url.".to_owned()))?;

        self.api_session
            .post_multipart_form_data(
                &upload_link.URL,
                &upload_link.Token,
                encrypted_thumbnail.as_ref(),
            )
            .await?;

        Ok(upload_link.Token.clone())
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_thumbnail_upload_url(
        &self,
        node_revision_uid: &str,
        address_id: String,
        size: usize,
        hash: Vec<u8>,
    ) -> Result<BlockUploadResponse> {
        let (volume_id, node_id, revision_id) =
            crate::uids::split_node_revision_uid(node_revision_uid)?;

        let endpoint = DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT;

        let payload = BlockUploadRequest {
            AddressID: address_id,
            VolumeID: volume_id,
            LinkID: node_id,
            RevisionID: revision_id,
            ThumbnailList: vec![ThumbnailUpload {
                Type: ThumbnailType::Type1,
                Size: size,
                Hash: hash,
            }],
            BlockList: vec![],
        };

        let resp: BlockUploadResponse = self
            .api_session
            .request_with_json_response(RequestType::Post, endpoint, Some(&payload))
            .await?;

        Ok(resp)
    }

    fn generate_and_encrypt_xattr<PGPProv, SRPProv>(
        crypto: &Crypto<PGPProv, SRPProv>,
        original_size: usize,
        blocks: impl AsRef<[CommitBlock]>,
        sha1: &String,
        node_private_key: &PGPProv::PrivateKey,
        address_key: &PGPProv::PrivateKey,
    ) -> Result<String>
    where
        PGPProv: PGPProviderSync,
        SRPProv: SRPProvider,
    {
        let now = SystemTime::now();
        let now: DateTime<Utc> = now.into();
        let modification_time = now.to_rfc3339();

        let extended_attributes = FileExtendedAttributesSchema {
            Common: Some(FileExtendedAttributesSchemaCommon {
                ModificationTime: modification_time, // TODO from server
                Size: original_size,
                BlockSizes: blocks
                    .as_ref()
                    .iter()
                    .sorted_by_key(|b| b.Index)
                    .map(|b| b.Size)
                    .collect(),
                Digests: FileExtendedAttributesSchemaDigest { SHA1: sha1.clone() },
            }),
        };

        let serialized = serde_json::to_string(&extended_attributes).map_err(|e| {
            APIError::DeserializeJSON(format!("Couldn't serialize extended attributes: {e:?}"))
        })?;

        crypto.encrypt_extended_attributes(serialized, node_private_key, address_key)
    }

    async fn commit_revision(
        &self,
        revision_uid: &str,
        signature_email: String,
        manifest_signature: String,
        armored_xattr: String,
        is_image: bool,
        content_hash: &String,
    ) -> Result<()> {
        let (volume_id, node_id, revision_id) = crate::uids::split_node_revision_uid(revision_uid)?;

        let endpoint = DRIVE_COMMIT_REVISION_ENDPOINT
            .replace("{volume_id}", &volume_id)
            .replace("{node_id}", &node_id)
            .replace("{revision_id}", &revision_id);

        let photo = if is_image {
            Some(CommitDraftPhoto {
                CaptureTime: chrono::Utc::now().timestamp(),
                ContentHash: content_hash.clone(),
                MainPhotoLinkID: None,
                Tags: vec![],
            })
        } else {
            None
        };

        let payload = CommitDraftRequest {
            ManifestSignature: manifest_signature,
            SignatureAddress: signature_email,
            XAttr: Some(armored_xattr),
            Photo: photo,
        };

        let response: CommitDraftResponse = self
            .api_session
            .request_with_json_response(RequestType::Put, &endpoint, Some(&payload))
            .await?;

        if response.Code.is_ok() {
            Ok(())
        } else {
            Err(APIError::Upload(
                "Failed to commit draft revision".to_owned(),
            ))
        }
    }

    async fn send_upload_work(
        &self,
        revision_uid: String,
        block_index: usize,
        encrypted_data: Vec<u8>,
        hash: Vec<u8>,
        address_id: String,
        armored_signature: String,
    ) -> Result<oneshot::Receiver<Result<CommitBlock>>> {
        if let Some(tx) = &self.workers_tx {
            let (reply, commit_rx) = oneshot::channel();
            let work = WorkerTask::UploadBlock {
                reply,
                revision_uid,
                block_index,
                encrypted_data,
                hash,
                address_id,
                armored_signature,
            };
            tx.send(work)
                .await
                .map_err(|e| APIError::Upload(e.to_string()))?;
            Ok(commit_rx)
        } else {
            Err(APIError::Upload(
                "Workers not started. Can't send upload work.".to_owned(),
            ))
        }
    }

    pub(crate) fn start_workers(&mut self, worker_count: usize) {
        let tokens = self
            .api_session
            .get_tokens()
            .cloned()
            .expect("API tokens must be set before starting workers");

        let (workers_tx, rx) = async_channel::bounded(worker_count / 2);
        for _ in 0..worker_count {
            let worker = APIWorker::new(tokens.clone(), rx.clone());
            tokio::spawn(async move { worker.run().await });
        }
        self.workers_tx = Some(workers_tx);
    }
}
