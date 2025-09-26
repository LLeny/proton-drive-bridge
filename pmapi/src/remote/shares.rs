use crate::consts::{SHARES_GET_ENDPOINT, SHARE_GET_ENDPOINT};
use crate::errors::Result;
use crate::remote::api_session::RequestType;
use crate::remote::payloads::{
    EncryptedRootShare, EncryptedShareCrypto, GetMyFilesResponse, ShareListItem, ShareListResponse, ShareResponse, ShareState, ShareType
};
use crate::{consts::DRIVE_SHARES_MYFILES_ENDPOINT, remote::Client};
use log::info;

impl Client {
    pub(crate) async fn get_myfiles(&self) -> Result<EncryptedRootShare> {
        info!("Fetching MyFiles");
        let response: GetMyFilesResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Get,
                DRIVE_SHARES_MYFILES_ENDPOINT,
                None::<&()>,
            )
            .await?;

        let encrypted_root_share = EncryptedRootShare {
            ShareID: response.Share.ShareID,
            VolumeID: response.Volume.VolumeID,
            RootNodeId: response.Link.Link.LinkID,
            AddressID: response.Share.AddressID,
            CreationTime: None,
            Type: ShareType::Main,
            CreatorEmail: response.Share.CreatorEmail,
            EncryptedCrypto: EncryptedShareCrypto {
                ArmoredKey: response.Share.Key,
                ArmoredPassphrase: response.Share.Passphrase,
                ArmoredPassphraseSignature: response.Share.PassphraseSignature,
            },
        };

        Ok(encrypted_root_share)
    }

    pub(crate) async fn get_shares(&self) -> Result<Vec<ShareListItem>> {
        info!("get_shares");
        let response: ShareListResponse = self
            .api_session
            .request_with_json_response(RequestType::Get, SHARES_GET_ENDPOINT, None::<&u8>)
            .await?;

        Ok(response.Shares)
    }

    pub(crate) async fn get_share(&self, share_id: &String) -> Result<EncryptedRootShare> {
        info!("get_share: '{share_id}'");

        let response: ShareResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Get,
                &SHARE_GET_ENDPOINT.replace("{share_id}", share_id),
                None::<&()>,
            )
            .await?;

        let encrypted_root_share = EncryptedRootShare {
            ShareID: response.ShareID.clone(),
            VolumeID: response.VolumeID.clone(),
            RootNodeId: response.LinkID.clone(),
            AddressID: response.AddressID.clone().unwrap_or_default(),
            CreationTime: None,
            Type: ShareType::Photos,
            CreatorEmail: response.Creator.clone().unwrap_or_default(),
            EncryptedCrypto: EncryptedShareCrypto {
                ArmoredKey: response.Key.clone(),
                ArmoredPassphrase: response.Passphrase.clone(),
                ArmoredPassphraseSignature: response.PassphraseSignature.clone(),
            },
        };

        Ok(encrypted_root_share)

    }

    pub(crate) async fn get_photos_share(&self) -> Result<EncryptedRootShare> {
        info!("get_photos_share");
        let shares = self.get_shares().await?;

        let Some(photo_share_short) = shares.iter().find(|s| s.State == ShareState::Active && s.Type == ShareType::Photos) else {
            return Err(crate::errors::APIError::Share("Couldn't find Photos Share.".to_string()));
        };

        self.get_share(&photo_share_short.ShareID).await
    }
}
