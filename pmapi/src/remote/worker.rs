use crate::{
    client::authenticator::AuthTokens,
    consts::{DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT, DRIVE_BLOCK_VERIFICATION_DATA_ENDPOINT},
    errors::{APIError, Result},
    remote::{
        api_session::{APISession, RequestType},
        payloads::{
            BlockUpload, BlockUploadRequest, BlockUploadResponse, BlockUploadVerifier,
            BlockVerificationData, CommitBlock,
        },
    },
};
use crossbeam::channel;
use log::info;
use tokio::sync::oneshot;

pub(crate) struct APIWorker {
    api_session: APISession,
    work_rx: channel::Receiver<WorkerTask>,
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
}

impl APIWorker {
    pub(crate) fn new(tokens: AuthTokens, work_rx: channel::Receiver<WorkerTask>) -> Self {
        let mut api_session =
            APISession::new(reqwest::Url::parse(crate::consts::URL_API_HOST).unwrap());
        api_session.set_tokens(tokens);
        Self {
            api_session,
            work_rx,
        }
    }

    pub(crate) async fn run(&self) {
        loop {
            match self.work_rx.recv() {
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
                        let _ = reply.send(
                            self.upload_block(
                                &revision_uid,
                                block_index,
                                encrypted_data,
                                hash,
                                address_id,
                                armored_signature,
                            )
                            .await,
                        );
                    }
                },
                Err(_) => break,
            }
        }
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
            .ok_or(APIError::Upload("Coudln't retrieve upload url.".to_owned()))?;

        info!("Uploading block {} to {}", block_index, &upload_link.URL);
        self.api_session
            .post_multipart_form_data(&upload_link.URL, &upload_link.Token, &encrypted_data)
            .await?;

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
