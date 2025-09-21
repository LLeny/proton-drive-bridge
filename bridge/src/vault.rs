use anyhow::Result;
use pmapi::client::{authenticator::AuthTokens, session_store::SessionStore};
use proton_crypto::crypto::{
    Decryptor, DecryptorSync, Encryptor, EncryptorSync, PGPMessage, PGPProviderSync, VerifiedData,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Default, Debug)]
pub(crate) struct LockedVault {
    content: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub(crate) struct UnlockedVault {
    pub refresh: String,
    pub access: String,
    pub uid: String,
    pub session_store: SessionStore,
}

impl LockedVault {
    /// Decrypts and returns the `UnlockedVault` using the provided salted password.
    ///
    /// The salted password must match the one used to protect the private key stored in the keyring.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The keyring cannot be accessed or the private key cannot be retrieved.
    /// - The private key import fails.
    /// - Decryption fails or the decrypted content cannot be deserialized.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn unlock(&self, salted_password: impl AsRef<[u8]>) -> Result<UnlockedVault> {
        let pgp = proton_crypto::new_pgp_provider();
        let priv_key_data = crate::keyring::get_key()?;

        let priv_key = pgp.private_key_import(
            priv_key_data,
            salted_password,
            proton_crypto::crypto::DataEncoding::Armor,
        )?;

        let content = pgp
            .new_decryptor()
            .with_decryption_key(&priv_key)
            .decrypt(&self.content, proton_crypto::crypto::DataEncoding::Armor)?;

        serde_json::from_slice(content.to_vec().as_slice())
            .map_err(|e| anyhow::Error::msg(e.to_string()))
    }
}

impl UnlockedVault {
    /// Encrypts this `UnlockedVault` into a `LockedVault` using the provided salted password.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The keyring cannot be accessed or the private key cannot be retrieved.
    /// - The key import/export fails.
    /// - The data cannot be serialized or encrypted.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn lock(&self, salted_password: impl AsRef<[u8]>) -> Result<LockedVault> {
        let pgp = proton_crypto::new_pgp_provider();
        let priv_key_data = crate::keyring::get_key()?;

        let priv_key = pgp.private_key_import(
            priv_key_data,
            salted_password,
            proton_crypto::crypto::DataEncoding::Armor,
        )?;

        let pub_key = pgp.private_key_to_public_key(&priv_key)?;

        let data = serde_json::to_vec(self)?;

        let content = pgp
            .new_encryptor()
            .with_encryption_key(&pub_key)
            .encrypt(data)?
            .armor()?
            .clone();

        Ok(LockedVault { content })
    }
}

impl From<&UnlockedVault> for AuthTokens {
    fn from(val: &UnlockedVault) -> Self {
        AuthTokens {
            access: val.access.clone(),
            refresh: val.refresh.clone(),
            uid: val.uid.clone(),
        }
    }
}

impl From<UnlockedVault> for AuthTokens {
    fn from(val: UnlockedVault) -> Self {
        (&val).into()
    }
}
