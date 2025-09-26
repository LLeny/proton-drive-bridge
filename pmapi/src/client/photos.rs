use crate::{
    client::{cache::Cache, crypto::Crypto},
    errors::{APIError, Result},
    remote::payloads::{AddPhotoToAlbumData, DecryptedNode, NodeType},
    uids::{make_node_uid, split_node_uid},
};
use image::ImageReader;
use proton_crypto::{crypto::PGPProviderSync, srp::SRPProvider};
use std::{io::Cursor, marker::PhantomData};

#[derive(Debug)]
pub(crate) struct Photos<PGPProv: PGPProviderSync, SRPPRov: SRPProvider> {
    _pgp: PhantomData<PGPProv>,
    _srp: PhantomData<SRPPRov>,
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync, SRPProv: proton_crypto::srp::SRPProvider>
    Photos<PGPProv, SRPProv>
{
    pub(crate) fn new() -> Self {
        Self {
            _pgp: PhantomData,
            _srp: PhantomData,
        }
    }

    pub async fn create_album(
        &self,
        parent_node: &DecryptedNode<PGPProv>,
        name: &str,
        cache: &Cache<PGPProv>,
        crypto: &Crypto<PGPProv, SRPProv>,
        remote_client: &crate::remote::Client,
    ) -> Result<String> {
        let user = cache
            .get_user()
            .ok_or(APIError::Node("Coudln't retrieve user".to_owned()))?;

        let verification_key = cache
            .get_unlocked_address_key(&user.Email)
            .ok_or(APIError::Account(
                "Couldn't retrieve user address keys".to_owned(),
            ))?
            .into_iter()
            .next() //TODO: pick first for now
            .ok_or(APIError::Account(
                "No unlocked address keys available".to_owned(),
            ))?;

        let (node_crypto, node_private_key) = crypto.create_new_node_encrypted_crypto(
            user,
            &parent_node.keys.public,
            &verification_key.private,
        )?;

        let parent_hash_key = parent_node
            .hash_key
            .as_ref()
            .ok_or(APIError::Node("hash_key required.".to_owned()))?;

        let node_hash_key = crypto.encrypt_hash_key(
            Crypto::<PGPProv, SRPProv>::generate_hashkey().as_ref(),
            &node_private_key,
            &verification_key.private,
        )?;

        let params = crypto.encrypt_new_node_name(
            parent_node,
            &NodeType::Folder,
            None,
            parent_hash_key,
            name,
            cache,
        )?;

        let node_id = remote_client
            .create_album(
                &parent_node.encrypted.Uid,
                params.Name,
                node_hash_key,
                params.Hash,
                &node_crypto,
            )
            .await?;

        let (volume_id, _) = split_node_uid(&parent_node.encrypted.Uid)?;
        Ok(make_node_uid(&volume_id, &node_id))
    }

    pub(crate) async fn add_photo_to_album(
        &self,
        album_node: &DecryptedNode<PGPProv>,
        photo_node: &DecryptedNode<PGPProv>,
        cache: &Cache<PGPProv>,
        crypto: &Crypto<PGPProv, SRPProv>,
        remote_client: &crate::remote::Client,
    ) -> Result<()> {
        let (_, photo_link_id) = split_node_uid(&photo_node.encrypted.Uid)?;

        let user = cache
            .get_user()
            .ok_or(APIError::Node("Coudln't retrieve user".to_owned()))?;

        let verification_key = cache
            .get_unlocked_address_key(&user.Email)
            .ok_or(APIError::Account(
                "Couldn't retrieve user address keys".to_owned(),
            ))?
            .into_iter()
            .next() //TODO: pick first for now
            .ok_or(APIError::Account(
                "No unlocked address keys available".to_owned(),
            ))?;

        let (node_crypto, _) = crypto.create_new_node_encrypted_crypto(
            user,
            &album_node.keys.public,
            &verification_key.private,
        )?;

        let parent_hash_key = album_node
            .hash_key
            .as_ref()
            .ok_or(APIError::Node("hash_key required.".to_owned()))?;

        let name_params = crypto.encrypt_new_node_name(
            album_node,
            &NodeType::Folder,
            None,
            parent_hash_key,
            &photo_node.name,
            cache,
        )?;

        let payload = AddPhotoToAlbumData {
            LinkID: photo_link_id,
            Hash: name_params.Hash,
            Name: name_params.Name,
            NameSignatureEmail: photo_node
                .encrypted
                .EncryptedCrypto
                .NameSignatureEmail
                .clone()
                .unwrap(),
            NodePassphrase: node_crypto.ArmoredNodePassphrase.clone(),
            ContentHash: photo_node.encrypted.Hash.clone().unwrap_or_default(),

            NodePassphraseSignature: None,
            SignatureEmail: None,
        };

        remote_client
            .add_photo_to_album(&payload, &album_node.encrypted.Uid)
            .await
    }

    pub(crate) fn create_thumbnail(&self, image_data: &[u8], max_border_len: u32) -> Result<Vec<u8>> {
        let src_img = ImageReader::new(Cursor::new(image_data))
            .with_guessed_format()
            .map_err(|e| APIError::Image(e.to_string()))?
            .decode()
            .map_err(|e| APIError::Image(e.to_string()))?;

        let thumbnail = src_img.thumbnail(max_border_len, max_border_len);

        let mut thumbnail_jpeg = Vec::<u8>::new();

        let mut writer = Cursor::new(&mut thumbnail_jpeg);

        thumbnail
            .write_to(&mut writer, image::ImageFormat::Jpeg)
            .map_err(|e| APIError::Image(e.to_string()))?;

        Ok(thumbnail_jpeg)
    }
}
