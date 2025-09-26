use crate::consts::{
    DRIVE_ALBUM, DRIVE_ALBUM_ADD_TO, DRIVE_ALBUM_CHILDREN, DRIVE_PHOTOS_ENDPOINT, PHOTOS_PAGE_SIZE,
};
use crate::errors::{APIError, Result};
use crate::remote::Client;
use crate::remote::api_session::RequestType;
use crate::remote::payloads::{
    AddPhotoToAlbumData, AddPhotoToAlbumRequest, AddPhotoToAlbumResponse, AlbumLinksResponse,
    CreateAlbumLink, CreateAlbumRequest, CreateAlbumResponse, EncryptedNodeCrypto,
    PhotoLinksResponse,
};
use crate::uids::{make_node_uid, split_node_uid};

impl Client {
    #[allow(dead_code)]
    pub(crate) async fn get_photo_uids(&self, volume_id: &str) -> Result<Vec<String>> {
        let mut photo_uids: Vec<String> = Vec::new();
        let mut last_link: Option<String> = None;

        loop {
            let mut endpoint = DRIVE_PHOTOS_ENDPOINT
                .replace("{volume_id}", volume_id)
                .replace("{page_size}", &PHOTOS_PAGE_SIZE.to_string());
            if let Some(last) = &last_link {
                endpoint = format!("{endpoint}&PreviousPageLastLinkID={last}");
            }

            let photos: PhotoLinksResponse = self
                .api_session
                .request_with_json_response(RequestType::Get, &endpoint, None::<&u8>)
                .await?;

            if photos.Photos.is_empty() {
                break;
            }

            photo_uids.extend(
                photos
                    .Photos
                    .iter()
                    .map(|p| make_node_uid(volume_id, &p.LinkID)),
            );

            last_link = photos.Photos.last().map(|p| p.LinkID.clone());
        }

        Ok(photo_uids)
    }

    pub(crate) async fn get_album_children_link_ids(
        &self,
        volume_id: &str,
        album_id: &str,
    ) -> Result<Vec<String>> {
        let mut results: Vec<String> = vec![];
        let mut more = true;
        let mut anchor = None;

        while more {
            let links: AlbumLinksResponse = self
                .api_session
                .request_with_json_response(
                    RequestType::Get,
                    {
                        let mut url = DRIVE_ALBUM_CHILDREN
                            .replace("{volume_id}", volume_id)
                            .replace("{album_id}", album_id);
                        if let Some(anchor) = anchor {
                            url += format!("?AnchorID={anchor}").as_str();
                        }
                        url
                    }
                    .as_str(),
                    None::<&()>,
                )
                .await?;

            results.extend(links.Photos.iter().map(|p| p.LinkID.clone()));
            more = links.More;
            anchor = links.AnchorID;
        }

        Ok(results)
    }

    pub(crate) async fn create_album(
        &self,
        parent_uid: &str,
        encrypted_name: String,
        hash_key: String,
        hash: String,
        crypto: &EncryptedNodeCrypto,
    ) -> Result<String> {
        let (volume_id, _) = split_node_uid(parent_uid)?;

        let payload = CreateAlbumRequest {
            Locked: false,
            Link: CreateAlbumLink {
                Name: encrypted_name,
                Hash: hash,
                NodePassphrase: crypto.ArmoredNodePassphrase.clone(),
                NodePassphraseSignature: crypto.ArmoredNodePassphraseSignature.clone(),
                SignatureEmail: crypto.SignatureEmail.clone().ok_or(APIError::Node(
                    "Missing SignatureEmail when creating node".to_owned(),
                ))?,
                NodeKey: crypto.ArmoredKey.clone(),
                NodeHashKey: hash_key,
                XAttr: None,
            },
        };

        let response: CreateAlbumResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                DRIVE_ALBUM.replace("{volume_id}", &volume_id).as_str(),
                Some(&payload),
            )
            .await?;

        if response.Code.is_ok() {
            Ok(response.Album.map(|a| a.Link.LinkID).unwrap())
        } else {
            Err(APIError::Node("Couldn't create album".to_owned()))
        }
    }

    pub(crate) async fn add_photo_to_album(
        &self,
        data: &AddPhotoToAlbumData,
        parent_uid: &str,
    ) -> Result<()> {
        let (volume_id, link_id) = split_node_uid(parent_uid)?;

        let endpoint = DRIVE_ALBUM_ADD_TO
            .replace("{volume_id}", &volume_id)
            .replace("{album_id}", &link_id);

        let payload = AddPhotoToAlbumRequest {
            AlbumData: vec![data.clone()],
        };

        let response: AddPhotoToAlbumResponse = self
            .api_session
            .request_with_json_response(RequestType::Post, &endpoint, Some(&payload))
            .await?;

        if response.Code.is_ok() {
            Ok(())
        } else {
            Err(APIError::Upload("Unknown".to_string()))
        }
    }
}
