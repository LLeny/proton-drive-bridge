use crate::errors::Result;
use crate::remote::payloads::{GetRevisionResponse, NodeBlock, RevisionResponse};
use crate::{
    consts::{BLOCKS_PAGE_SIZE, DRIVE_NODE_REVISION},
    errors::APIError,
    remote::api_session::{APISession, RequestType},
    uids::split_node_revision_uid,
};
use base64::Engine;
use futures::future::BoxFuture;
use log::error;
use proton_crypto::crypto::{Decryptor, DecryptorSync, PGPProviderSync, VerifiedData};
use sha2::Digest;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pub struct FileDownloader {
    status: StreamStatus,
    api_session: APISession,
    node_revision_uid: String,
    fetch_block_list: Option<BoxFuture<'static, Result<RevisionResponse>>>,
    fetch_and_decrypt_block: Option<BoxFuture<'static, Result<Vec<u8>>>>,
    session_key: Vec<u8>,
    verification_key: Vec<u8>,
}

struct StreamStatus {
    revision: Option<RevisionResponse>,
    next_block_index: usize,
    current_block_data: Vec<u8>,
    current_block_pos: usize,
}

impl FileDownloader {
    pub(crate) fn new(
        api_session: &APISession,
        node_revision_uid: String,
        session_key: Vec<u8>,
        verification_key: Vec<u8>,
    ) -> Self {
        Self {
            status: StreamStatus::new(),
            api_session: api_session.clone(),
            fetch_block_list: None,
            fetch_and_decrypt_block: None,
            session_key,
            verification_key,
            node_revision_uid,
        }
    }
}

async fn fetch_and_decrypt_block(
    session: APISession,
    block: NodeBlock,
    session_key: Vec<u8>,
    verification_key: Vec<u8>,
) -> Result<Vec<u8>> {
    let url = block
        .URL
        .as_ref()
        .ok_or_else(|| APIError::Download("Missing block URL".to_owned()))?;

    let encrypted_block = session
        .request::<()>(RequestType::Get, url, None)
        .await?
        .bytes()
        .await
        .map_err(APIError::Reqwest)?
        .to_vec();

    let sha = sha2::Sha256::digest(&encrypted_block);
    let integrity = base64::prelude::BASE64_STANDARD.encode(sha) == block.Hash;
    if !integrity {
        return Err(APIError::Download("Block integrity check failed".to_owned()));
    }

    let pgp_provider = proton_crypto::new_pgp_provider();

    let session_key = pgp_provider
        .session_key_import(
            session_key,
            proton_crypto::crypto::SessionKeyAlgorithm::Unknown,
        )
        .map_err(|e| APIError::PGP(format!("Couldn't import session key: {e}")))?;

    let verification_key = pgp_provider
        .public_key_import(
            verification_key,
            proton_crypto::crypto::DataEncoding::Armor,
        )
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

    Ok(decrypted_data.to_vec())
}

async fn fetch_all_revision_blocks(
    session: APISession,
    node_revision_uid: String,
) -> Result<RevisionResponse> {
    let mut results: Option<RevisionResponse> = None;
    let mut from_block_index: usize = 1;

    let (volume_id, node_id, revision_id) = split_node_revision_uid(&node_revision_uid)?;
    let url = build_revision_url(&volume_id, &node_id, &revision_id);

    loop {
        let page_url = url.replace("{from_block_index}", &from_block_index.to_string());
        let response = session
            .request_with_json_response::<(), GetRevisionResponse>(
                RequestType::Get,
                &page_url,
                None,
            )
            .await?
            .Revision;

        let blocks_len = response.Blocks.len();

        if blocks_len == 0 {
            break;
        }

        match &mut results {
            Some(revision) => revision.Blocks.extend(response.Blocks),
            None => results = Some(response),
        }

        if blocks_len < BLOCKS_PAGE_SIZE.into() {
            break;
        }

        from_block_index += blocks_len;
    }

    results.ok_or_else(|| APIError::Download("No revision found".to_owned()))
}

fn build_revision_url(volume_id: &str, node_id: &str, revision_id: &str) -> String {
    DRIVE_NODE_REVISION
        .replace("{volume_id}", volume_id)
        .replace("{node_id}", node_id)
        .replace("{revision_id}", revision_id)
        .replace("{BLOCKS_PAGE_SIZE}", &BLOCKS_PAGE_SIZE.to_string())
}

impl StreamStatus {
    fn new() -> Self {
        Self {
            revision: None,
            next_block_index: 0,
            current_block_data: Vec::new(),
            current_block_pos: 0,
        }
    }

    pub(crate) fn set_revision(&mut self, revision: RevisionResponse) {
        self.revision = Some(revision);
        self.next_block_index = 0;
        self.current_block_data.clear();
        self.current_block_pos = 0;
    }

    pub(crate) fn set_data(&mut self, data: &[u8]) {
        self.current_block_data.clear();
        self.current_block_data.extend_from_slice(data);
        self.current_block_pos = 0;
        self.next_block_index += 1;
    }

    fn has_data_available(&self) -> bool {
        self.current_block_pos < self.current_block_data.len()
    }

    fn copy_to_buffer(&mut self, buf: &mut tokio::io::ReadBuf<'_>) -> usize {
        let remaining_in_block = self.current_block_data.len() - self.current_block_pos;
        let to_copy = remaining_in_block.min(buf.remaining());

        if to_copy > 0 {
            let start = self.current_block_pos;
            let end = start + to_copy;
            buf.put_slice(&self.current_block_data[start..end]);
            self.current_block_pos += to_copy;
        }

        to_copy
    }

    fn has_more_blocks(&self) -> bool {
        if let Some(rev) = &self.revision {
            self.next_block_index < rev.Blocks.len()
        } else {
            false
        }
    }

    fn get_next_block(&self) -> Option<&NodeBlock> {
        self.revision
            .as_ref()
            .and_then(|rev| rev.Blocks.get(self.next_block_index))
    }
}

// TODO: Retry on error
impl tokio::io::AsyncRead for FileDownloader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.status.revision.is_none() {
            if this.fetch_block_list.is_none() {
                this.fetch_block_list = Some(Box::pin(fetch_all_revision_blocks(
                    this.api_session.clone(),
                    this.node_revision_uid.clone(),
                )));
            }

            if let Some(f) = &mut this.fetch_block_list {
                match f.as_mut().poll(cx) {
                    Poll::Ready(Ok(rev)) => this.status.set_revision(rev),
                    Poll::Ready(Err(e)) => {
                        error!("Failed to get revision: {e}");
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        }

        loop {
            if this.status.has_data_available() {
                let copied = this.status.copy_to_buffer(buf);
                if copied > 0 && buf.remaining() == 0 {
                    break;
                }
            }

            if !this.status.has_more_blocks() {
                break;
            }

            if let Some(block) = this.status.get_next_block() {
                if this.fetch_and_decrypt_block.is_none() {
                    this.fetch_and_decrypt_block = Some(Box::pin(fetch_and_decrypt_block(
                        this.api_session.clone(),
                        block.clone(),
                        this.session_key.clone(),
                        this.verification_key.clone(),
                    )));
                }

                if let Some(f) = &mut this.fetch_and_decrypt_block {
                    match f.as_mut().poll(cx) {
                        Poll::Ready(Ok(data)) => {
                            this.status.set_data(&data);
                            this.fetch_and_decrypt_block = None;
                        }
                        Poll::Ready(Err(e)) => {
                            error!("Failed to get block: {e}");
                            return Poll::Ready(Err(io::Error::other(e.to_string())));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

unsafe impl Sync for FileDownloader {}