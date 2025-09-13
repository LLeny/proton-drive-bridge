use crate::errors::APIError;
use crate::errors::Result;
use crate::remote::payloads::{
    AddressResponse, DecryptedNode, KeySalts, User, Volume, VolumeShareNodeIDs,
};
use elsa::sync::{FrozenMap, FrozenVec};
use once_cell::sync::OnceCell;
use proton_crypto_account::keys::UnlockedUserKey;

pub(crate) struct Cache<PGPProv: proton_crypto::crypto::PGPProviderSync> {
    user: Option<User>,
    salts: OnceCell<KeySalts>,
    addresses: FrozenVec<Box<AddressResponse>>,
    passphrases: FrozenMap<String, Box<FrozenVec<u8>>>,
    unlocked_user_keys: FrozenMap<String, Box<FrozenVec<Box<UnlockedUserKey<PGPProv>>>>>,
    unlocked_addresses_keys: FrozenMap<String, Box<FrozenVec<Box<UnlockedUserKey<PGPProv>>>>>,
    myfiles_ids: OnceCell<VolumeShareNodeIDs>,
    share_keys: FrozenMap<String, Box<UnlockedUserKey<PGPProv>>>,
    volumes: FrozenMap<String, Box<Volume>>,
    nodes: FrozenMap<String, Box<DecryptedNode<PGPProv>>>,
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync> std::fmt::Debug for Cache<PGPProv> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache").finish()
    }
}

impl<PGPProv: proton_crypto::crypto::PGPProviderSync> Cache<PGPProv> {
    pub(crate) fn new() -> Self {
        Self {
            user: None,
            salts: OnceCell::new(),
            addresses: FrozenVec::new(),
            unlocked_user_keys: FrozenMap::new(),
            unlocked_addresses_keys: FrozenMap::new(),
            passphrases: FrozenMap::new(),
            myfiles_ids: OnceCell::new(),
            share_keys: FrozenMap::new(),
            volumes: FrozenMap::new(),
            nodes: FrozenMap::new(),
        }
    }

    pub(crate) fn get_user(&self) -> Option<&User> {
        self.user.as_ref()
    }

    pub(crate) fn set_user(&mut self, user: User) {
        self.user = Some(user);
    }

    pub(crate) fn set_salt(&self, salt: KeySalts) {
        let _ = self.salts.set(salt);
    }

    pub(crate) fn add_address(&self, addr: AddressResponse) {
        self.addresses.push(Box::new(addr));
    }

    pub(crate) fn add_passphrase(&self, id: String, pass: Vec<u8>) {
        self.passphrases.insert(id, Box::new(FrozenVec::from(pass)));
    }

    pub(crate) fn add_unlocked_user_key(&self, email: &str, key: UnlockedUserKey<PGPProv>) {
        if let Some(v) = self.unlocked_user_keys.get(email) {
            v.push(Box::new(key));
        } else {
            let v = FrozenVec::new();
            v.push(Box::new(key));
            self.unlocked_user_keys
                .insert(email.to_string(), Box::new(v));
        }
    }

    pub(crate) fn add_unlocked_address_key(&self, id: &str, key: UnlockedUserKey<PGPProv>) {
        if let Some(v) = self.unlocked_addresses_keys.get(id) {
            v.push(Box::new(key));
        } else {
            let v = FrozenVec::new();
            v.push(Box::new(key));
            self.unlocked_addresses_keys
                .insert(id.to_string(), Box::new(v));
        }
    }

    pub(crate) fn set_myfile_ids(&self, myfiles: VolumeShareNodeIDs) {
        let _ = self.myfiles_ids.set(myfiles);
    }

    pub(crate) fn add_share_key(&self, id: String, key: UnlockedUserKey<PGPProv>) {
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

    pub(crate) fn get_salts(&self) -> Option<&KeySalts> {
        self.salts.get()
    }

    pub(crate) fn get_share_key(&self, id: &str) -> Option<&UnlockedUserKey<PGPProv>> {
        self.share_keys.get(id)
    }

    pub(crate) fn contains_encrypted_node(&self, id: &str) -> bool {
        self.nodes.get(id).is_some()
    }

    pub(crate) fn get_decrypted_node(&self, id: &str) -> Option<&DecryptedNode<PGPProv>> {
        self.nodes.get(id)
    }

    pub(crate) fn get_passphrase(&self, id: &str) -> Option<&FrozenVec<u8>> {
        self.passphrases.get(id)
    }

    pub(crate) fn get_unlocked_user_keys(
        &self,
        email: &str,
    ) -> Option<Vec<&UnlockedUserKey<PGPProv>>> {
        if let Some(keys) = self.unlocked_user_keys.get(email) {
            let v: Vec<&UnlockedUserKey<PGPProv>> = keys.iter().by_ref().collect();
            Some(v)
        } else {
            None
        }
    }

    pub(crate) fn addresses(&self) -> Vec<&AddressResponse> {
        let addrs: Vec<&AddressResponse> = self.addresses.iter().by_ref().collect();
        addrs
    }

    pub(crate) fn get_unlocked_address_key(
        &self,
        id: &str,
    ) -> Option<Vec<&UnlockedUserKey<PGPProv>>> {
        if let Some(keys) = self.unlocked_addresses_keys.get(id) {
            let v: Vec<&UnlockedUserKey<PGPProv>> = keys.iter().by_ref().collect();
            Some(v)
        } else {
            None
        }
    }

    pub(crate) fn get_node_private_key(&self, node_uid: &str) -> Result<&PGPProv::PrivateKey> {
        Ok(self
            .get_decrypted_node(node_uid)
            .ok_or(APIError::Account(format!(
                "Couldn't find private key for node '{node_uid}'"
            )))?
            .keys
            .private_key
            .as_ref())
    }

    pub(crate) fn get_share_private_key(
        &self,
        share_id: &str,
    ) -> Result<&UnlockedUserKey<PGPProv>> {
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
}
