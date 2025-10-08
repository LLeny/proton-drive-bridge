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
use std::collections::{HashMap, VecDeque};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::oneshot;

pub struct FileDownloader {
    api_session: APISession,
    node_revision_uid: String,
    fetch_block_list: Option<BoxFuture<'static, Result<RevisionResponse>>>,
    session_key: Vec<u8>,
    verification_key: Vec<u8>,

    workers_tx: async_channel::Sender<WorkerTask>,

    revision: Option<RevisionResponse>,
    next_block_index: usize,
    pending_downloads: HashMap<usize, oneshot::Receiver<Result<Vec<u8>>>>,
    ready_blocks: HashMap<usize, Vec<u8>>,
    next_expected_block: usize,

    buffer: VecDeque<u8>,
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
            api_session: api_session.clone(),
            node_revision_uid,
            fetch_block_list: None,
            session_key,
            verification_key,
            workers_tx,
            revision: None,
            next_block_index: 0,
            pending_downloads: HashMap::new(),
            ready_blocks: HashMap::new(),
            next_expected_block: 0,
            buffer: VecDeque::new(),
        }
    }

    fn start_block_downloads(&mut self) {
        while self.has_more_blocks() {
            if let Some(block) = self.get_next_block() {
                let block_index = self.next_block_index;
                let (reply, rx) = oneshot::channel();

                match self.workers_tx.try_send(WorkerTask::DownloadBlock {
                    reply,
                    block: block.clone(),
                    session_key: self.session_key.clone(),
                    verification_key: self.verification_key.clone(),
                }) {
                    Ok(_) => {
                        self.pending_downloads.insert(block_index, rx);
                        self.next_block_index += 1;
                    }
                    Err(_) => {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn process_completed_downloads(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        self.pending_downloads
            .retain(|&block_index, rx| match rx.poll_unpin(cx) {
                Poll::Ready(Ok(Ok(data))) => {
                    self.ready_blocks.insert(block_index, data);
                    false
                }
                Poll::Ready(Ok(Err(e))) => {
                    error!("Block download failed: {e}");
                    false
                }
                Poll::Ready(Err(e)) => {
                    error!("Worker task cancelled: {e}");
                    false
                }
                Poll::Pending => true,
            });

        while let Some(data) = self.ready_blocks.remove(&self.next_expected_block) {
            self.buffer.extend(&data);
            self.next_expected_block += 1;
        }

        Ok(())
    }

    fn has_more_blocks(&self) -> bool {
        self.revision
            .as_ref()
            .map_or(false, |rev| self.next_block_index < rev.Blocks.len())
    }

    fn get_next_block(&self) -> Option<&NodeBlock> {
        self.revision
            .as_ref()
            .and_then(|rev| rev.Blocks.get(self.next_block_index))
    }

    fn has_data_available(&self) -> bool {
        !self.buffer.is_empty()
    }

    fn copy_to_buffer(&mut self, buf: &mut tokio::io::ReadBuf<'_>) -> usize {
        let to_copy = self.buffer.len().min(buf.remaining());

        if to_copy > 0 {
            self.buffer.make_contiguous();
            let (front, _) = self.buffer.as_slices();
            let copy_len = front.len().min(to_copy);
            buf.put_slice(&front[..copy_len]);
            self.buffer.drain(0..copy_len);
        }

        to_copy
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

impl tokio::io::AsyncRead for FileDownloader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.revision.is_none() {
            if this.fetch_block_list.is_none() {
                this.fetch_block_list = Some(Box::pin(fetch_all_revision_blocks(
                    this.api_session.clone(),
                    this.node_revision_uid.clone(),
                )));
            }

            if let Some(f) = &mut this.fetch_block_list {
                match f.as_mut().poll(cx) {
                    Poll::Ready(Ok(rev)) => {
                        this.revision = Some(rev);
                        this.start_block_downloads();
                    }
                    Poll::Ready(Err(e)) => {
                        error!("Failed to get revision: {e}");
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        this.process_completed_downloads(cx)?;

        this.start_block_downloads();

        if this.has_data_available() {
            let copied = this.copy_to_buffer(buf);
            if copied > 0 {
                return Poll::Ready(Ok(()));
            }
        }

        if this.has_more_blocks()
            || !this.pending_downloads.is_empty()
            || !this.ready_blocks.is_empty()
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
