use crate::client::session_store::SessionStore;
use crate::errors::APIError;
use crate::errors::Result;
use crate::remote::payloads::PrivateKey;
use crate::remote::payloads::UnlockedUserKey;
use crate::remote::payloads::User;
use crate::remote::payloads::{AddressResponse, DecryptedNode, Volume, VolumeShareNodeIDs};
use elsa::sync::FrozenMap;
use once_cell::sync::OnceCell;

pub(crate) struct Cache<PGPProv: proton_crypto::crypto::PGPProviderSync> {
    myfiles_ids: OnceCell<VolumeShareNodeIDs>,
    photos_ids: OnceCell<VolumeShareNodeIDs>,
    share_keys: FrozenMap<String, Box<UnlockedUserKey>>,
    volumes: FrozenMap<String, Box<Volume>>,
    nodes: FrozenMap<String, Box<DecryptedNode<PGPProv>>>,
    session_store: SessionStore,
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync> std::fmt::Debug for Cache<PGPProv> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache").finish()
    }
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync> Cache<PGPProv> {
    pub(crate) fn new(session_store: SessionStore) -> Self {
        Self {
            myfiles_ids: OnceCell::new(),
            photos_ids: OnceCell::new(),
            share_keys: FrozenMap::new(),
            volumes: FrozenMap::new(),
            nodes: FrozenMap::new(),
            session_store,
        }
    }

    pub(crate) fn set_photos_share_ids(&self, myfiles: VolumeShareNodeIDs) {
        let _ = self.photos_ids.set(myfiles);
    }

    pub(crate) fn set_myfile_ids(&self, myfiles: VolumeShareNodeIDs) {
        let _ = self.myfiles_ids.set(myfiles);
    }

    pub(crate) fn add_share_key(&self, id: String, key: UnlockedUserKey) {
        self.share_keys.insert(id, Box::new(key));
    }

    pub(crate) fn add_volume(&self, id: String, volume: Volume) {
        self.volumes.insert(id, Box::new(volume));
    }

    pub(crate) fn add_decrypted_node(&self, id: String, node: DecryptedNode<PGPProv>) {
        self.nodes.insert(id, Box::new(node));
    }

    pub(crate) fn myfiles_ids(&self) -> Option<&VolumeShareNodeIDs> {
        self.myfiles_ids.get()
    }

    pub(crate) fn photos_share_ids(&self) -> Option<&VolumeShareNodeIDs> {
        self.photos_ids.get()
    }

    pub(crate) fn get_share_key(&self, id: &str) -> Option<&UnlockedUserKey> {
        self.share_keys.get(id)
    }

    pub(crate) fn contains_encrypted_node(&self, id: &str) -> bool {
        self.nodes.get(id).is_some()
    }

    pub(crate) fn get_decrypted_node(&self, id: &str) -> Option<&DecryptedNode<PGPProv>> {
        self.nodes.get(id)
    }

    pub(crate) fn get_node_private_key(&self, node_uid: &str) -> Result<&PrivateKey> {
        Ok(&self
            .get_decrypted_node(node_uid)
            .ok_or(APIError::Account(format!(
                "Couldn't find private key for node '{node_uid}'"
            )))?
            .keys
            .private)
    }

    pub(crate) fn get_share_private_key(&self, share_id: &str) -> Result<&UnlockedUserKey> {
        self.get_share_key(share_id)
            .ok_or(APIError::Account(format!(
                "Couldn't find private key for share '{share_id}'"
            )))
    }

    pub(crate) fn remove_node(&mut self, node_uid: &str) {
        self.nodes.as_mut().remove(node_uid);
    }

    pub(crate) fn node_updated(&mut self, node: DecryptedNode<PGPProv>) {
        self.remove_node(&node.encrypted.Uid);
        self.add_decrypted_node(node.encrypted.Uid.clone(), node);
    }

    pub(crate) fn get_user(&self) -> Option<&User> {
        self.session_store.get_user()
    }

    pub(crate) fn get_unlocked_address_key(&self, id: &str) -> Option<Vec<&UnlockedUserKey>> {
        self.session_store.get_unlocked_address_key(id)
    }

    pub(crate) fn addresses(&self) -> Vec<&AddressResponse> {
        self.session_store.addresses()
    }
}
