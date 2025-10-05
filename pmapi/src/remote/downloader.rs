use crate::errors::Result;
use crate::remote::Client;
use crate::remote::payloads::{GetRevisionResponse, NodeBlock, RevisionResponse};
use crate::remote::worker::WorkerTask;
use crate::{
    consts::{BLOCKS_PAGE_SIZE, DRIVE_NODE_REVISION},
    errors::APIError,
    remote::api_session::{APISession, RequestType},
    uids::split_node_revision_uid,
};
use futures::FutureExt;
use futures::future::BoxFuture;
use log::error;
use std::collections::HashMap;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::oneshot;

pub struct FileDownloader {
    status: StreamStatus,
    api_session: APISession,
    node_revision_uid: String,
    fetch_block_list: Option<BoxFuture<'static, Result<RevisionResponse>>>,
    session_key: Vec<u8>,
    verification_key: Vec<u8>,

    workers_tx: async_channel::Sender<WorkerTask>,
    pending_block_rxs: HashMap<usize, oneshot::Receiver<Result<Vec<u8>>>>,
    pending_block_data: HashMap<usize, Vec<u8>>,
    next_expected_block_id: usize,
}

struct StreamStatus {
    revision: Option<RevisionResponse>,
    next_block_index: usize,
    to_send_data: Vec<u8>,
    current_data_pos: usize,
}

impl FileDownloader {
    pub(crate) fn new(
        api_session: &APISession,
        node_revision_uid: String,
        session_key: Vec<u8>,
        verification_key: Vec<u8>,
        workers_tx: async_channel::Sender<WorkerTask>,
    ) -> Self {
        Self {
            status: StreamStatus::new(),
            api_session: api_session.clone(),
            fetch_block_list: None,
            session_key,
            verification_key,
            node_revision_uid,
            workers_tx,
            pending_block_rxs: HashMap::new(),
            pending_block_data: HashMap::new(),
            next_expected_block_id: 0,
        }
    }

    fn start_next_block_download_if_possible(&mut self) {
        if self.workers_tx.is_full() || !self.status.has_more_blocks() {
            return;
        }

        if let Some(block) = self.status.get_next_block() {
            let block_index = self.status.next_block_index;
            let block = block.clone();

            let (reply, rx) = oneshot::channel();

            let _ = self.workers_tx.send_blocking(WorkerTask::DownloadBlock {
                reply,
                block,
                session_key: self.session_key.clone(),
                verification_key: self.verification_key.clone(),
            });

            self.pending_block_rxs.insert(block_index, rx);
            self.status.next_block_index += 1;
        }
    }

    fn process_completed_downloads(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let mut received_blocks = Vec::new();

        self.pending_block_rxs
            .retain(|&block_index, rx| match rx.poll_unpin(cx) {
                Poll::Ready(result) => {
                    received_blocks.push((block_index, result));
                    false
                }
                Poll::Pending => true,
            });

        for (id, res) in received_blocks {
            let data = res
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("Worker task cancelled: {e}"))
                })?
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to download/decrypt block: {e}"),
                    )
                })?;
            self.pending_block_data.insert(id, data);
        }

        while let Some(data) = self.pending_block_data.remove(&self.next_expected_block_id) {
            self.status.push_data(&data);
            self.next_expected_block_id += 1;
        }

        Ok(())
    }
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
            to_send_data: Vec::new(),
            current_data_pos: 0,
        }
    }

    pub(crate) fn set_revision(&mut self, revision: RevisionResponse) {
        self.revision = Some(revision);
        self.next_block_index = 0;
        self.to_send_data.clear();
        self.current_data_pos = 0;
    }

    fn remove_sent_data(&mut self) {
        self.to_send_data.drain(0..self.current_data_pos);
        self.current_data_pos = 0;
    }

    pub(crate) fn push_data(&mut self, data: &[u8]) {
        self.remove_sent_data();
        self.to_send_data.extend_from_slice(data);
    }

    fn has_data_available(&self) -> bool {
        self.current_data_pos < self.to_send_data.len()
    }

    fn copy_to_buffer(&mut self, buf: &mut tokio::io::ReadBuf<'_>) -> usize {
        let remaining_in_block = self.to_send_data.len() - self.current_data_pos;
        let to_copy = remaining_in_block.min(buf.remaining());

        if to_copy > 0 {
            let start = self.current_data_pos;
            let end = start + to_copy;
            buf.put_slice(&self.to_send_data[start..end]);
            self.current_data_pos += to_copy;
        }

        to_copy
    }

    pub(crate) fn get_next_block(&self) -> Option<&NodeBlock> {
        self.revision
            .as_ref()
            .and_then(|rev| rev.Blocks.get(self.next_block_index))
    }

    pub(crate) fn has_more_blocks(&self) -> bool {
        if let Some(rev) = &self.revision {
            self.next_block_index < rev.Blocks.len()
        } else {
            false
        }
    }
}

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
                    Poll::Ready(Ok(rev)) => {
                        this.status.set_revision(rev);
                        this.start_next_block_download_if_possible();
                    }
                    Poll::Ready(Err(e)) => {
                        error!("Failed to get revision: {e}");
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        let _ = this.process_completed_downloads(cx)?;

        this.start_next_block_download_if_possible();

        if this.status.has_data_available() {
            let copied = this.status.copy_to_buffer(buf);
            if copied > 0 {
                return Poll::Ready(Ok(()));
            }
        }

        if this.status.has_more_blocks()
            || !this.pending_block_data.is_empty()
            || !this.pending_block_rxs.is_empty()
        {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

unsafe impl Sync for FileDownloader {}

impl Client {
    pub fn new_downloader(
        &self,
        node_revision_uid: String,
        session_key: Vec<u8>,
        verification_key: Vec<u8>,
    ) -> FileDownloader {
        FileDownloader::new(
            &self.api_session,
            node_revision_uid,
            session_key,
            verification_key,
            self.workers_tx.clone().expect("Worker channel closed"),
        )
    }
}
