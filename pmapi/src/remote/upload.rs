use crate::client::photos::Photos;
use crate::consts::{MAX_THUMBNAIL_BORDER_LEN, MAX_THUMBNAIL_SIZE};
use crate::errors::Result;
use crate::remote::api_session::RequestType;
use crate::remote::payloads::{
    BlockUpload, BlockUploadRequest, BlockUploadResponse, BlockUploadVerifier,
    BlockVerificationData, CommitBlock, CommitDraftPhoto, CommitDraftRequest, CommitDraftResponse,
    FileExtendedAttributesSchema, FileExtendedAttributesSchemaCommon,
    FileExtendedAttributesSchemaDigest, PrivateKey, ThumbnailType, ThumbnailUpload,
};
use crate::{
    client::crypto::Crypto,
    consts::{
        DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT, DRIVE_BLOCK_VERIFICATION_DATA_ENDPOINT,
        DRIVE_COMMIT_REVISION_ENDPOINT, FILE_CHUNK_SIZE,
    },
    errors::APIError,
    remote::Client,
};
use chrono::{DateTime, Utc};
use futures::TryFutureExt;
use proton_crypto::crypto::PGPProviderSync;
use proton_crypto::srp::SRPProvider;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt};

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn upload_node_blocks<Reader, PGPProv, SRPProv>(
        &self,
        revision_uid: &str,
        signature_email: String,
        media_type: Option<String>,
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
        let mut total_uploaded: usize = 0;
        let mut block_index: usize = 1;
        let mut blocks: Vec<CommitBlock> = Vec::new();
        let mut reader = reader;
        let mut manifest: Vec<u8> = vec![];
        let mut total_read: usize = 0;
        let mut blocks_sha1 = Sha1::new();
        let address_key = address_key.to_pgp(crypto.get_pgp_provider())?;
        let is_image: bool = media_type.as_ref().is_some_and(|m| m.starts_with("image/"));
        let mut image_data: Vec<u8> = vec![];

        loop {
            let buf = Self::read_n(&mut reader, FILE_CHUNK_SIZE).await?;
            let n = buf.len();

            if n == 0 {
                break;
            }

            if is_image {
                image_data.extend_from_slice(&buf[..n]);
            }

            total_read += n;
            blocks_sha1.update(&buf[..n]);

            let (encrypted, armored_signature) =
                crypto.encrypt_block(session_key, node_key, &address_key, &buf[..n])?;

            let hash = Sha256::digest(&encrypted);

            manifest.extend(hash);

            let block_token = self
                .upload_block(
                    revision_uid,
                    block_index,
                    encrypted.as_slice(),
                    hash.to_vec(),
                    address_id.clone(),
                    armored_signature,
                )
                .await?;

            total_uploaded += encrypted.len();
            blocks.push(CommitBlock {
                Index: block_index,
                Token: block_token,
                Size: encrypted.len(),
            });
            block_index += 1;
        }

        if is_image {
            let mut border_len = MAX_THUMBNAIL_BORDER_LEN;
            let thumbnail = loop {
                let thumb = photo.create_thumbnail(&image_data, border_len);
                match thumb {
                    Ok(t) if t.len() >= MAX_THUMBNAIL_SIZE => {
                        border_len *= 9 / 10;
                        continue;
                    }
                    Ok(t) => break Ok(t),
                    Err(e) => break Err(e),
                }
            }?;

            let encrypted_thumbnail =
                crypto.encrypted_thumbnail(session_key, &address_key, &thumbnail)?;

            let hash = Sha256::digest(&encrypted_thumbnail);

            let _ = self
                .upload_thumbnail(
                    revision_uid,
                    address_id.clone(),
                    encrypted_thumbnail.as_slice(),
                    hash.to_vec(),
                )
                .await?;

            manifest.splice(0..0, hash);
        }

        let manifest_signature = crypto.sign_manifest(&manifest, &address_key)?;
        let sha1 = hex::encode(blocks_sha1.finalize());

        let xattr = Self::generate_and_encrypt_xattr(
            crypto,
            total_read,
            &blocks,
            &sha1,
            node_key,
            &address_key,
        )?;

        self.commit_revision(
            revision_uid,
            signature_email,
            manifest_signature,
            xattr,
            media_type,
            &sha1,
        )
        .await?;

        Ok(total_uploaded)
    }

    async fn read_n<Reader>(reader: &mut Reader, bytes_to_read: usize) -> Result<Vec<u8>>
    where
        Reader: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let mut buf = vec![0u8; bytes_to_read];
        let mut filled = 0;

        while filled < bytes_to_read {
            let n = reader
                .read(&mut buf[filled..])
                .map_err(|e| APIError::Upload(e.to_string()))
                .await?;
            if n == 0 {
                break;
            }
            filled += n;
        }

        buf.truncate(filled);
        Ok(buf)
    }

    async fn upload_block(
        &self,
        revision_uid: &str,
        block_index: usize,
        encrypted_data: impl AsRef<[u8]>,
        hash: Vec<u8>,
        address_id: String,
        armored_signature: String,
    ) -> Result<String> {
        let verification_data = self.get_verification_data(revision_uid).await?;
        let verification_token: Vec<u8> = verification_data
            .VerificationCode
            .into_iter()
            .enumerate()
            .map(|(i, value)| value ^ encrypted_data.as_ref().get(i).unwrap_or(&0))
            .collect();

        let url = self
            .get_block_upload_url(
                revision_uid,
                address_id,
                block_index,
                encrypted_data.as_ref().len(),
                hash,
                armored_signature,
                verification_token,
            )
            .await?;

        let upload_link = url
            .UploadLinks
            .first()
            .ok_or(APIError::Upload("Coudln't retrieve upload url.".to_owned()))?;

        self.api_session
            .post_multipart_form_data(
                &upload_link.URL,
                &upload_link.Token,
                encrypted_data.as_ref(),
            )
            .await?;

        Ok(upload_link.Token.clone())
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
                BlockSizes: blocks.as_ref().iter().map(|b| b.Size).collect(),
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
        media_type: Option<String>,
        content_hash: &String,
    ) -> Result<()> {
        let (volume_id, node_id, revision_id) = crate::uids::split_node_revision_uid(revision_uid)?;

        let endpoint = DRIVE_COMMIT_REVISION_ENDPOINT
            .replace("{volume_id}", &volume_id)
            .replace("{node_id}", &node_id)
            .replace("{revision_id}", &revision_id);

        let photo = media_type
            .filter(|mt| mt.starts_with("image/"))
            .map(|_| CommitDraftPhoto {
                CaptureTime: chrono::Utc::now().timestamp(),
                ContentHash: content_hash.clone(),
                MainPhotoLinkID: None,
                Tags: vec![],
            });

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
}
