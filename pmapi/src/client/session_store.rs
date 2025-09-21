use crate::{
    client::authenticator::Password,
    remote::payloads::{AddressResponse, KeySalts, UnlockedUserKey, User},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionStore {
    user: Option<User>,
    salts: Option<KeySalts>,
    addresses: Vec<AddressResponse>,
    passphrases: Vec<(String, Password)>,
    unlocked_user_keys: Vec<(String, Vec<UnlockedUserKey>)>,
    unlocked_addresses_keys: Vec<(String, Vec<UnlockedUserKey>)>,
}

impl SessionStore {
    pub(crate) fn new() -> Self {
        Self {
            user: None,
            salts: None,
            addresses: Vec::new(),
            passphrases: Vec::new(),
            unlocked_user_keys: Vec::new(),
            unlocked_addresses_keys: Vec::new(),
        }
    }

    pub(crate) fn get_user(&self) -> Option<&User> {
        self.user.as_ref()
    }

    pub(crate) fn set_user(&mut self, user: User) {
        self.user = Some(user);
    }

    pub(crate) fn set_salt(&mut self, salt: KeySalts) {
        self.salts = Some(salt);
    }

    pub(crate) fn add_address(&mut self, addr: AddressResponse) {
        self.addresses.push(addr);
    }

    pub(crate) fn add_passphrase(&mut self, id: String, pass: Password) {
        self.passphrases.push((id, pass));
    }

    pub(crate) fn add_unlocked_user_key(&mut self, email: &str, key: UnlockedUserKey) {
        match self.unlocked_user_keys.iter_mut().find(|(e, _)| e == email) {
            Some((_, keys)) => keys.push(key),
            None => self.unlocked_user_keys.push((email.to_owned(), vec![key])),
        }
    }

    pub(crate) fn add_unlocked_address_key(&mut self, id: &str, key: UnlockedUserKey) {
        match self
            .unlocked_addresses_keys
            .iter_mut()
            .find(|(i, _)| i == id)
        {
            Some((_, keys)) => keys.push(key),
            None => self
                .unlocked_addresses_keys
                .push((id.to_owned(), vec![key])),
        }
    }

    pub(crate) fn get_salts(&self) -> Option<&KeySalts> {
        self.salts.as_ref()
    }

    pub(crate) fn get_unlocked_user_keys(&self, email: &str) -> Option<Vec<&UnlockedUserKey>> {
        self.unlocked_user_keys
            .iter()
            .find(|(e, _)| e == email)
            .map(|(_, keys)| keys.iter().collect())
    }

    pub(crate) fn get_unlocked_address_key(&self, id: &str) -> Option<Vec<&UnlockedUserKey>> {
        self.unlocked_addresses_keys
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, keys)| keys.iter().collect())
    }

    pub(crate) fn get_passphrase(&self, id: &str) -> Option<&Password> {
        self.passphrases
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, p)| p)
    }

    pub(crate) fn addresses(&self) -> Vec<&AddressResponse> {
        let addrs: Vec<&AddressResponse> = self.addresses.iter().by_ref().collect();
        addrs
    }
}
