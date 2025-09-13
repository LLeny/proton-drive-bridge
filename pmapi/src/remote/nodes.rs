use crate::consts::{
    DRIVE_CHECKHASH_LINK_ENDPOINT, DRIVE_CREATE_DRAFT_ENDPOINT, DRIVE_CREATE_FOLDER_ENDPOINT,
    DRIVE_DELETE_DRAFT_ENDPOINT, DRIVE_DELETE_LINKS_ENDPOINT, DRIVE_NODE_CHILDREN,
    DRIVE_RENAME_LINK_ENDPOINT, DRIVE_TRASH_LINKS_ENDPOINT,
};
use crate::errors::ErrorCode;
use crate::errors::Result;
use crate::remote::api_session::RequestType;
use crate::remote::payloads::{
    CheckAvailableHashesRequest, CheckAvailableHashesResponse, CreateDraftRequest,
    CreateDraftResponse, CreateFolderRequest, CreateFolderResponse, DeleteDraftRequestPayload,
    DeleteDraftResponse, DeleteLinksRequestPayload, DeleteLinksResponse, DraftRequestResult,
    EncryptedNode, EncryptedNodeCrypto, EncryptedNodeFile, EncryptedNodeFolder, EncryptedRevision,
    LinkResponse, LinkType, LinksRequestPayload, LinksResponse, MemberRole, NodeChildrenResponse,
    NodeType, RenameLinkParameters, RenameLinkResponse, RevisionState,
};
use crate::uids::{make_node_revision_uid, make_node_uid};
use crate::{consts::DRIVE_LINKS_ENDPOINT, errors::APIError, remote::Client, uids::split_node_uid};
use itertools::Itertools;
use log::{error, info};

impl Client {
    pub(crate) async fn get_nodes(
        &self,
        node_uids: impl AsRef<[String]>,
    ) -> Result<Vec<EncryptedNode>> {
        let mut nodes: Vec<EncryptedNode> = vec![];

        let pairs: Vec<(String, String)> = node_uids
            .as_ref()
            .iter()
            .map(|uid| split_node_uid(uid))
            .collect::<Result<Vec<_>>>()?;
        let node_map = pairs.into_iter().into_group_map();

        for (volumeid, node_ids) in node_map {
            let payload = LinksRequestPayload { LinkIDs: node_ids };

            let links: LinksResponse = self
                .api_session
                .request_with_json_response(
                    RequestType::Post,
                    DRIVE_LINKS_ENDPOINT
                        .replace("{volume_id}", volumeid.as_str())
                        .as_str(),
                    Some(&payload),
                )
                .await?;

            let ns: Vec<EncryptedNode> = links
                .Links
                .iter()
                .map(|link| {
                    EncryptedNode::from(link, &volumeid)
                })
                .collect();

            nodes.extend(ns);
        }

        Ok(nodes)
    }

    pub(crate) async fn rename_node(
        &self,
        node_uid: &str,
        params: &RenameLinkParameters,
    ) -> Result<()> {
        let (volume_id, node_id) = split_node_uid(node_uid)?;
        info!("{params:?}");
        let response: RenameLinkResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Put,
                DRIVE_RENAME_LINK_ENDPOINT
                    .replace("{volume_id}", volume_id.as_str())
                    .replace("{node_id}", node_id.as_str())
                    .as_str(),
                Some(params),
            )
            .await?;

        if response.Code.is_ok() {
            Ok(())
        } else {
            Err(APIError::Node(format!(
                "Couldn't rename node: '{node_uid}'"
            )))
        }
    }

    pub(crate) async fn delete_draft(&self, draft_node_uid: &str) -> Result<()> {
        let (volume_id, node_id) = split_node_uid(draft_node_uid)?;

        let response: DeleteDraftResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                DRIVE_DELETE_DRAFT_ENDPOINT
                    .replace("{volume_id}", volume_id.as_str())
                    .as_str(),
                Some(&DeleteDraftRequestPayload {
                    LinkIDs: vec![node_id],
                }),
            )
            .await?;

        if response.Code.is_ok() {
            return Ok(());
        }

        Err(APIError::Node("Error deleting draft".into()))
    }

    pub(crate) async fn delete_nodes(
        &self,
        node_uids: impl AsRef<[String]>,
    ) -> Result<Vec<(String, String)>> {
        let pairs: Vec<(String, String)> = node_uids
            .as_ref()
            .iter()
            .map(|uid| split_node_uid(uid))
            .collect::<Result<Vec<_>>>()?;
        let node_map = pairs.into_iter().into_group_map();

        let mut errors: Vec<(String, String)> = vec![];

        for (volumeid, node_ids) in node_map {
            let payload = DeleteLinksRequestPayload { LinkIDs: node_ids };

            // TODO: check for trash success first
            let _response: DeleteLinksResponse = self
                .api_session
                .request_with_json_response(
                    RequestType::Post,
                    DRIVE_TRASH_LINKS_ENDPOINT
                        .replace("{volume_id}", volumeid.as_str())
                        .as_str(),
                    Some(&payload),
                )
                .await?;

            let response: DeleteLinksResponse = self
                .api_session
                .request_with_json_response(
                    RequestType::Post,
                    DRIVE_DELETE_LINKS_ENDPOINT
                        .replace("{volume_id}", volumeid.as_str())
                        .as_str(),
                    Some(&payload),
                )
                .await?;

            if let Some(reponses) = response.Responses {
                let failed: Vec<(String, String)> = reponses
                    .iter()
                    .filter(|r| {
                        r.Response
                            .Code
                            .as_ref()
                            .is_none_or(super::super::errors::ErrorCode::is_error)
                            || r.Response.Error.is_some()
                    })
                    .map(|r| {
                        (
                            make_node_uid(&volumeid, &r.LinkID),
                            r.Response
                                .Error
                                .as_ref()
                                .map_or("Unknown".to_string(), std::string::ToString::to_string),
                        )
                    })
                    .collect();

                if !failed.is_empty() {
                    errors.extend(failed);
                    error!("Failed deleting: {errors:?}");
                }
            }
        }

        Ok(errors)
    }

    pub(crate) async fn get_node(&self, node_uid: &str) -> Result<EncryptedNode> {
        let mut nodes = self.get_nodes(&vec![node_uid.to_string()]).await?;
        Ok(nodes.remove(0))
    }

    pub(crate) async fn get_node_children_link_ids(
        &self,
        volume_id: &str,
        node_id: &str,
    ) -> Result<Vec<String>> {
        let mut results: Vec<String> = vec![];
        let mut more = true;
        let mut anchor = None;

        while more {
            let links: NodeChildrenResponse = self
                .api_session
                .request_with_json_response(
                    RequestType::Get,
                    {
                        let mut url = DRIVE_NODE_CHILDREN
                            .replace("{volume_id}", volume_id)
                            .replace("{node_id}", node_id);
                        if let Some(anchor) = anchor {
                            url += format!("?AnchorID={anchor}").as_str();
                        }
                        url
                    }
                    .as_str(),
                    None::<&()>,
                )
                .await?;

            results.extend(links.LinkIDs);
            more = links.More;
            anchor = links.AnchorID;
        }

        Ok(results)
    }

    pub(crate) async fn create_node(
        &self,
        parent_uid: &str,
        encrypted_name: String,
        hash_key: String,
        hash: String,
        crypto: &EncryptedNodeCrypto,
    ) -> Result<String> {
        let (volume_id, parent_id) = split_node_uid(parent_uid)?;

        let payload = CreateFolderRequest {
            NodeHashKey: hash_key,
            XAttr: None,
            Name: encrypted_name,
            Hash: hash,
            ParentLinkID: parent_id,
            NodePassphrase: crypto.ArmoredNodePassphrase.clone(),
            NodePassphraseSignature: crypto.ArmoredNodePassphraseSignature.clone(),
            SignatureEmail: crypto
                .SignatureEmail
                .clone()
                .ok_or(APIError::Node("Missing SignatureEmail when creating node".into()))?,
            NodeKey: crypto.ArmoredKey.clone(),
        };

        let response: CreateFolderResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                DRIVE_CREATE_FOLDER_ENDPOINT
                    .replace("{volume_id}", &volume_id)
                    .as_str(),
                Some(&payload),
            )
            .await?;

        if response.Code.is_ok() {
            Ok(response.Folder.ID)
        } else {
            Err(APIError::Node("Couldn't create node".into()))
        }
    }

    pub(crate) async fn create_node_draft(
        &self,
        node_crypto: &EncryptedNodeCrypto,
        parent_uid: &str,
        naming_params: &RenameLinkParameters,
        intended_upload_size: Option<u64>,
    ) -> Result<DraftRequestResult> {
        let (volume_id, node_id) = crate::uids::split_node_uid(parent_uid)?;
        let endpoint = DRIVE_CREATE_DRAFT_ENDPOINT
            .replace("{volume_id}", &volume_id)
            .replace("{node_id}", &node_id);

        let file_properties = node_crypto
            .File
            .clone()
            .ok_or(APIError::Node("Missing File properties for draft".into()))?;

        let draft_request = CreateDraftRequest {
            IntendedUploadSize: intended_upload_size,
            MIMEType: naming_params.MediaType.clone().unwrap_or_default(),
            ContentKeyPacket: file_properties.ContentKeyPacket,
            ContentKeyPacketSignature: file_properties.ArmoredContentKeyPacketSignature,
            Name: naming_params.Name.clone(),
            Hash: naming_params.Hash.clone(),
            ParentLinkID: node_id.clone(),
            NodePassphrase: node_crypto.ArmoredNodePassphrase.clone(),
            NodePassphraseSignature: node_crypto.ArmoredNodePassphraseSignature.clone(),
            SignatureAddress: node_crypto
                .SignatureEmail
                .clone()
                .ok_or(APIError::Node("Missing SignatureEmail for draft".into()))?,
            NodeKey: node_crypto.ArmoredKey.clone(),
        };

        let mut response: CreateDraftResponse = self
            .api_session
            .request_with_json_response(RequestType::Post, &endpoint, Some(&draft_request))
            .await?;

        if response.Code.is_ok()
            && let Some(file) = response.File
        {
            return Ok(DraftRequestResult {
                node_uid: crate::uids::make_node_uid(&volume_id, &file.ID),
                node_revision_uid: crate::uids::make_node_revision_uid(
                    &volume_id,
                    &file.ID,
                    &file.RevisionID,
                ),
            });
        }

        if response.Code == ErrorCode::ALREADY_EXISTS
            && let Some(temp_node_uid) = self
                .check_used_hash(parent_uid, naming_params.Hash.clone())
                .await?
        {
            self.delete_draft(&temp_node_uid).await?;
            // TODO don't repeat code
            response = self
                .api_session
                .request_with_json_response(RequestType::Post, &endpoint, Some(&draft_request))
                .await?;
            if response.Code.is_ok()
                && let Some(file) = response.File
            {
                return Ok(DraftRequestResult {
                    node_uid: crate::uids::make_node_uid(&volume_id, &file.ID),
                    node_revision_uid: crate::uids::make_node_revision_uid(
                        &volume_id,
                        &file.ID,
                        &file.RevisionID,
                    ),
                });
            }
        }

        Err(APIError::Node(
            response
                .Error
                .unwrap_or("Failed to create draft revision".into()),
        ))
    }

    async fn check_used_hash(
        &self,
        parent_node_uid: &str,
        hash: String,
    ) -> Result<Option<String>> {
        let (volume_id, node_id) = crate::uids::split_node_uid(parent_node_uid)?;

        let endpoint = DRIVE_CHECKHASH_LINK_ENDPOINT
            .replace("{volume_id}", &volume_id)
            .replace("{node_id}", &node_id);

        let response: CheckAvailableHashesResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                &endpoint,
                Some(&CheckAvailableHashesRequest {
                    Hashes: vec![hash.clone()],
                    ClientUID: None,
                }),
            )
            .await?;

        let temp_node_uid = response
            .PendingHashes
            .iter()
            .find(|h| h.Hash == hash)
            .map(|h| crate::uids::make_node_uid(&volume_id, &h.LinkID));

        if let Some(found) = &temp_node_uid {
            info!("Found pending hash with node id: '{found}'");
        }

        Ok(temp_node_uid)
    }
}

impl EncryptedNode {
    pub(crate) fn from(link: &LinkResponse, volume_id: &str) -> Self {
        Self {
            Hash: link.Link.NameHash.clone(),
            EncryptedName: link.Link.Name.clone(),

            Uid: make_node_uid(volume_id, &link.Link.LinkID),
            ParentUid: link
                .Link
                .ParentLinkID
                .as_ref()
                .map(|pid| make_node_uid(volume_id, pid)),
            Type: match link.Link.Type {
                LinkType::None => NodeType::None,
                LinkType::Folder => NodeType::Folder,
                LinkType::File => NodeType::File,
            },
            CreationTime: link.Link.CreateTime,
            TrashTime: link.Link.TrashTime.unwrap_or(0),

            ShareId: link.Sharing.as_ref().map(|s| s.ShareID.clone()),
            IsShared: link.Sharing.is_some(),
            DirectMemberRole: match &link.Membership {
                None => MemberRole::Inherited,
                Some(num) => match num.Permissions {
                    6 => MemberRole::Editor,
                    22 => MemberRole::Admin,
                    _ => MemberRole::Viewer,
                },
            },

            MediaType: if let Some(f) = &link.File {
                f.MediaType.clone()
            } else {
                None
            },
            TotalStorageSize: link.File.as_ref().map(|f| f.TotalEncryptedSize),
            EncryptedCrypto: EncryptedNodeCrypto {
                SignatureEmail: link.Link.SignatureEmail.clone(),
                NameSignatureEmail: link.Link.NameSignatureEmail.clone(),
                ArmoredKey: link.Link.NodeKey.clone(),
                ArmoredNodePassphrase: link.Link.NodePassphrase.clone(),
                ArmoredNodePassphraseSignature: link.Link.NodePassphraseSignature.clone(),
                File: if link.Link.Type == LinkType::File
                    && let Some(file) = &link.File
                {
                    Some(EncryptedNodeFile {
                        ContentKeyPacket: file.ContentKeyPacket.clone(),
                        ArmoredContentKeyPacketSignature: file.ContentKeyPacketSignature.clone(),
                    })
                } else {
                    None
                },
                ActiveRevision: if link.Link.Type == LinkType::File
                    && let Some(file) = &link.File
                {
                    Some(EncryptedRevision {
                        UID: make_node_revision_uid(
                            volume_id,
                            &link.Link.LinkID,
                            &file.ActiveRevision.RevisionID,
                        ),
                        State: RevisionState::Active,
                        CreationTime: file.ActiveRevision.CreateTime,
                        storageSize: file.ActiveRevision.EncryptedSize,
                        SignatureEmail: file.ActiveRevision.SignatureEmail.clone(),
                        ArmoredExtendedAttributes: file.ActiveRevision.XAttr.clone(),
                    })
                } else {
                    None
                },
                Folder: if link.Link.Type == LinkType::Folder
                    && let Some(folder) = &link.Folder
                {
                    Some(EncryptedNodeFolder {
                        ArmoredExtendedAttributes: folder.XAttr.clone(),
                        ArmoredHashKey: folder.NodeHashKey.clone(),
                    })
                } else {
                    None
                },
            },
        }
    }
}
