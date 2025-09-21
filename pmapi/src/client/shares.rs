use std::{fmt::Debug, marker::PhantomData};

use crate::errors::Result;
use crate::remote::payloads::UnlockedUserKey;
use crate::{
    client::{cache::Cache, crypto::Crypto},
    remote::payloads::{DecryptedRootShare, EncryptedRootShare, Volume, VolumeShareNodeIDs},
};
use proton_crypto::{crypto::PGPProviderSync, srp::SRPProvider};

pub(crate) struct Shares<PGPProv: PGPProviderSync, SRPPRov: SRPProvider> {
    _pgp: PhantomData<PGPProv>,
    _srp: PhantomData<SRPPRov>,
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync, SRPProv: proton_crypto::srp::SRPProvider>
    Shares<PGPProv, SRPProv>
{
    pub(crate) fn new() -> Self {
        Self {
            _pgp: PhantomData,
            _srp: PhantomData,
        }
    }

    fn insert_share_cache(
        encrypted_share: &EncryptedRootShare,
        share: &DecryptedRootShare,
        key: UnlockedUserKey,
        cache: &Cache<PGPProv>,
    ) {
        cache.add_share_key(share.ShareID.clone(), key);

        cache.add_volume(
            share.VolumeID.clone(),
            Volume {
                ShareID: share.ShareID.clone(),
                VolumeID: share.VolumeID.clone(),
                RootNodeId: share.RootNodeId.clone(),
                CreatorEmail: encrypted_share.CreatorEmail.clone(),
                AddressID: encrypted_share.AddressID.clone(),
            },
        );

        cache.set_myfile_ids(VolumeShareNodeIDs {
            ShareID: share.ShareID.clone(),
            VolumeID: share.VolumeID.clone(),
            RootNodeId: share.RootNodeId.clone(),
        });
    }

    pub(crate) async fn get_myfiles_ids<'c>(
        &'c self,
        cache: &'c Cache<PGPProv>,
        crypto: &'c Crypto<PGPProv, SRPProv>,
        remote_client: &'c crate::remote::Client,
    ) -> Result<&'c VolumeShareNodeIDs> {
        if cache.myfiles_ids().is_none() {
            let encrypted_share = remote_client.get_myfiles().await?;
            let (share, key) = crypto.decrypt_root_share(&encrypted_share, cache)?;
            Self::insert_share_cache(&encrypted_share, &share, key, cache);
        }

        cache
            .myfiles_ids()
            .ok_or(crate::errors::APIError::Account(
                "My files IDs not initialized".to_owned(),
            ))
    }
}

impl<PGPPRov: PGPProviderSync, SRPPRov: SRPProvider> Debug for Shares<PGPPRov, SRPPRov> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shares").finish()
    }
}
