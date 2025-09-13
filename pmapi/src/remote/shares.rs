use crate::errors::Result;
use crate::remote::api_session::RequestType;
use crate::remote::payloads::{
    EncryptedRootShare, EncryptedShareCrypto, GetMyFilesResponse, ShareType,
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
}
