use crate::errors::Result;
use crate::remote::payloads::{
    DecryptedNode, DecryptedRootShare, EncryptedNode, EncryptedNodeCrypto, EncryptedRootShare,
    NodeType, RenameLinkParameters, User,
};
use crate::{
    client::cache::Cache,
    consts::{HASHKEY_LEN, NODEKEY_EMAIL, NODEKEY_USER, PASSPHRASE_LEN},
    errors::APIError,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::{Hmac, Mac};
use proton_crypto::{
    crypto::{
        DataEncoding, Decryptor, DecryptorSync, DetachedSignatureVariant, Encryptor,
        EncryptorDetachedSignatureWriter as _, EncryptorSync, KeyGenerator as _,
        KeyGeneratorSync as _, PGPMessage, PGPProviderSync, Signer, SignerSync, VerifiedData,
    },
    srp::SRPProvider,
};
use proton_crypto_account::{
    keys::{DecryptedUserKey, KeyId, UnlockedUserKey},
    salts::KeySecret,
};
use sha2::Sha256;
use std::{fmt::Debug, io::Write, path::Path};

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct Crypto<PGPProv: PGPProviderSync, SRPProv: SRPProvider> {
    pgp_provider: PGPProv,
    srp_provider: SRPProv,
    password: Option<Vec<u8>>,
}

impl<PGPProv: PGPProviderSync, SRPProv: SRPProvider> Crypto<PGPProv, SRPProv> {
    pub(crate) fn new(pgp_provider: PGPProv, srp_provider: SRPProv) -> Self {
        Self {
            pgp_provider,
            srp_provider,
            password: None,
        }
    }

    pub(crate) fn set_password(&mut self, password: Vec<u8>) {
        self.password = Some(password);
    }

    //TODO: Key ids ?
    pub(crate) fn unlock_user_keys(&self, cache: &Cache<PGPProv>) -> Result<()> {
        let salts = cache
            .get_salts()
            .ok_or_else(|| APIError::Account("Salts not loaded.".into()))?;

        for salt in salts.KeySalts.iter().filter(|s| s.key_salt.is_some()) {
            let Some(key_salt) = salt.key_salt.as_ref() else {
                continue;
            };
            let passphrase = key_salt
                .salted_key_passphrase(
                    &self.srp_provider,
                    self.password
                        .as_ref()
                        .ok_or(APIError::Account("Password not set".into()))?,
                )
                .map_err(APIError::Salt)?;

            cache.add_passphrase(
                salt.id.0.clone(),
                Vec::from(passphrase.as_bytes().to_vec().as_mut_slice()),
            );
        }

        let first_salt_id = salts
            .KeySalts
            .first()
            .ok_or(APIError::Account("No salts available".into()))?
            .id
            .0
            .clone();
        let passphrase = KeySecret::new(
            cache
                .get_passphrase(&first_salt_id)
                .ok_or(APIError::Account("Missing cached passphrase".into()))?
                .clone()
                .into_vec(),
        );

        let user = cache
            .get_user()
            .ok_or(APIError::Account("User not loaded".into()))?;

        let results = user.Keys.unlock(&self.pgp_provider, &passphrase);

        let email = user.Email.clone();

        results
            .unlocked_keys
            .iter()
            .for_each(|k| cache.add_unlocked_user_key(&email, k.clone()));

        Ok(())
    }

    pub(crate) fn unlock_address_keys(&self, cache: &Cache<PGPProv>) -> Result<()> {
        let user = cache
            .get_user()
            .ok_or(APIError::Account("User not loaded".into()))?;
        let user_keys = cache.get_unlocked_user_keys(&user.Email).ok_or_else(|| {
            APIError::Account(format!(
                "Couldn't find unlocked keys for user '{}'",
                user.Email
            ))
        })?;

        let priv_keys: Vec<PGPProv::PrivateKey> =
            user_keys.iter().map(|k| k.private_key.clone()).collect();
        let pub_keys: Vec<PGPProv::PublicKey> =
            user_keys.iter().map(|k| k.public_key.clone()).collect();

        for addr in cache.addresses() {
            for key in &addr.Keys {
                let passphrase = self
                    .pgp_provider
                    .new_decryptor()
                    .with_decryption_keys(priv_keys.as_slice())
                    .with_verification_keys(pub_keys.as_slice())
                    .decrypt(&key.Token, DataEncoding::Armor)
                    .map_err(|e| APIError::PGP(e.to_string()))?;

                if !passphrase.is_verified() {
                    return Err(APIError::PGP(format!("Couldn't verify key '{}'", key.ID)));
                }

                let decrypted_key = DecryptedUserKey {
                    id: KeyId(key.ID.clone()),
                    private_key: self
                        .pgp_provider
                        .private_key_import(
                            &key.PrivateKey,
                            passphrase.as_bytes(),
                            DataEncoding::Armor,
                        )
                        .map_err(|e| APIError::PGP(e.to_string()))?,
                    public_key: self
                        .pgp_provider
                        .public_key_import(key.PublicKey.as_bytes(), DataEncoding::Armor)
                        .map_err(|e| APIError::PGP(e.to_string()))?,
                };

                cache.add_unlocked_address_key(&addr.Email, decrypted_key);
            }
        }

        Ok(())
    }

    pub(crate) fn decrypt_root_share(
        &self,
        share: &EncryptedRootShare,
        cache: &Cache<PGPProv>,
    ) -> Result<(DecryptedRootShare, UnlockedUserKey<PGPProv>)> {
        let addr_keys = cache
            .get_unlocked_address_key(&share.CreatorEmail)
            .ok_or_else(|| {
                APIError::PGP(format!(
                    "Couldn't find address keys for '{}'",
                    &share.AddressID
                ))
            })?;

        let pub_keys: Vec<PGPProv::PublicKey> =
            addr_keys.iter().map(|k| k.public_key.clone()).collect();
        let pri_keys: Vec<PGPProv::PrivateKey> =
            addr_keys.iter().map(|k| k.private_key.clone()).collect();

        let passphrase = self
            .pgp_provider
            .new_decryptor()
            .with_verification_keys(pub_keys.as_slice())
            .with_decryption_keys(pri_keys.as_slice())
            .decrypt(
                share.EncryptedCrypto.ArmoredPassphrase.as_bytes(),
                DataEncoding::Armor,
            )
            .map_err(|e| {
                APIError::PGP(format!(
                    "Couldn't decrypt armored passphrase for '{}': {e:?}",
                    &share.ShareID
                ))
            })?;

        if !passphrase.is_verified() {
            return Err(APIError::PGP(format!(
                "Couldn't verify armored passphrase for '{}'",
                &share.ShareID
            )));
        }

        let priv_key = self
            .pgp_provider
            .private_key_import(
                share.EncryptedCrypto.ArmoredKey.as_bytes(),
                passphrase,
                DataEncoding::Armor,
            )
            .map_err(|e| {
                APIError::PGP(format!(
                    "Couldn't import armored key for '{}': {e:?}",
                    &share.ShareID
                ))
            })?;

        let decrypted_share = DecryptedRootShare {
            ShareID: share.ShareID.clone(),
            VolumeID: share.VolumeID.clone(),
            RootNodeId: share.RootNodeId.clone(),
            AddressID: share.AddressID.clone(),
            CreationTime: share.CreationTime,
            Type: share.Type.clone(),
            Author: Ok(share.CreatorEmail.clone()),
        };

        let decrypted_key = DecryptedUserKey {
            id: KeyId(decrypted_share.ShareID.clone()),
            public_key: self
                .pgp_provider
                .private_key_to_public_key(&priv_key)
                .map_err(|e| {
                    APIError::PGP(format!("Couldn't derive public key from private key: {e}"))
                })?,
            private_key: priv_key,
        };

        Ok((decrypted_share, decrypted_key))
    }

    pub(crate) fn decrypt_node(
        &self,
        encrypted_node: &EncryptedNode,
        cache: &Cache<PGPProv>,
    ) -> Result<DecryptedNode<PGPProv>> {
        let signature_email_key = encrypted_node
            .EncryptedCrypto
            .SignatureEmail
            .as_ref()
            .and_then(|signature_email| {
                cache
                    .get_unlocked_address_key(signature_email)
                    .and_then(|v| v.into_iter().next())
                    .map(|k| k.public_key.clone())
            });

        let node_parent_key = Self::get_parent_keys(encrypted_node, cache)?.clone();

        let key_verification_key = if let Some(key) = signature_email_key.clone() {
            key
        } else {
            self.to_public(&node_parent_key)?
        };

        let name_signature_email = encrypted_node
            .EncryptedCrypto
            .NameSignatureEmail
            .clone()
            .ok_or(APIError::PGP(format!(
                "Missing NameSignatureEmail for '{}'",
                encrypted_node.Uid
            )))?;

        let name_verification_key = if let Some(sign_email) =
            &encrypted_node.EncryptedCrypto.SignatureEmail
            && name_signature_email == *sign_email
        {
            key_verification_key.clone()
        } else {
            cache
                .get_unlocked_address_key(&name_signature_email)
                .and_then(|v| v.into_iter().next())
                .map(|k| k.public_key.clone())
                .unwrap_or(self.to_public(&node_parent_key)?)
        };

        let (name, author_name) =
            self.decrypt_node_name(encrypted_node, &node_parent_key, &name_verification_key)?;

        let decrypted_node_key =
            self.decrypt_node_key(encrypted_node, &node_parent_key, &key_verification_key)?;

        let mut content_session_key: Option<PGPProv::SessionKey> = None;
        let mut hash_key = None;

        if encrypted_node.Type == NodeType::Folder
            && let Some(folder) = &encrypted_node.EncryptedCrypto.Folder
        {
            hash_key = Some(
                String::from_utf8(self.decrypt(
                    &folder.ArmoredHashKey,
                    &decrypted_node_key.private_key,
                    &key_verification_key,
                )?)
                .map_err(|e| {
                    APIError::PGP(format!("Couldn't parse decrypted hash key as UTF-8: {e}"))
                })?,
            );
            let _hash_key_author = encrypted_node.EncryptedCrypto.SignatureEmail.clone();
            // TODO
        } else if encrypted_node.Type == NodeType::File
            && let Some(file) = &encrypted_node.EncryptedCrypto.File
        {
            content_session_key = Some(self.decrypt_content_key(
                &file.ContentKeyPacket,
                &decrypted_node_key,
                &key_verification_key,
            )?);
            // TODO
        }

        Ok(DecryptedNode {
            encrypted: encrypted_node.clone(),
            name,
            author_name,
            keys: decrypted_node_key,
            name_verification_key,
            content_session_key,
            hash_key,
        })
    }

    //TODO: Verify
    pub(crate) fn decrypt_content_key(
        &self,
        content_key_packet: impl AsRef<[u8]>,
        decrypted_node_key: &DecryptedUserKey<PGPProv::PrivateKey, PGPProv::PublicKey>,
        key_verification_key: &PGPProv::PublicKey,
    ) -> Result<PGPProv::SessionKey> {
        self.pgp_provider
            .new_decryptor()
            .with_verification_key(key_verification_key)
            .with_verification_key(&decrypted_node_key.public_key)
            .with_decryption_key(&decrypted_node_key.private_key)
            .decrypt_session_key(content_key_packet)
            .map_err(|e| APIError::PGP(format!("Couldn't decrypt content key packet: {e:?}")))
    }

    fn to_public(&self, priv_key: &PGPProv::PrivateKey) -> Result<PGPProv::PublicKey> {
        let priv_as_pub_key = self
            .pgp_provider
            .private_key_to_public_key(priv_key)
            .map_err(|e| APIError::PGP(format!("Couldn't convert private to public key: {e:?}")))?;
        Ok(priv_as_pub_key)
    }

    fn decrypt(
        &self,
        data: impl AsRef<[u8]>,
        decryption_key: &PGPProv::PrivateKey,
        verification_key: &PGPProv::PublicKey,
    ) -> Result<Vec<u8>> {
        let decrypted = self
            .pgp_provider
            .new_decryptor()
            .with_decryption_key(decryption_key)
            .with_verification_key(verification_key)
            .decrypt(data, DataEncoding::Armor)
            .map_err(|e| APIError::PGP(format!("Couldn't decrypt: {e:?}")))?;

        if !decrypted.is_verified() {
            return Err(APIError::PGP("Couldn't verify.".into()));
        }

        Ok(decrypted.as_bytes().to_vec())
    }

    fn decrypt_node_name(
        &self,
        encrypted_node: &EncryptedNode,
        parent_key: &PGPProv::PrivateKey,
        name_verification_key: &PGPProv::PublicKey,
    ) -> Result<(String, String)> {
        let name = self
            .pgp_provider
            .new_decryptor()
            .with_decryption_key(parent_key)
            .with_verification_key(name_verification_key)
            .decrypt(&encrypted_node.EncryptedName, DataEncoding::Armor)
            .map_err(|e| {
                APIError::PGP(format!(
                    "Couldn't decrypt name of '{}': {e:?}",
                    encrypted_node.Uid
                ))
            })?;

        if !name.is_verified() {
            return Err(APIError::PGP(format!(
                "Couldn't verify name of '{}'",
                encrypted_node.Uid
            )));
        }

        let decrypted_name = String::from_utf8(name.as_bytes().to_vec())
            .map_err(|e| APIError::PGP(format!("Couldn't parse decrypted name as UTF-8: {e}")))?;

        let name_signature_email = encrypted_node
            .EncryptedCrypto
            .NameSignatureEmail
            .clone()
            .ok_or(APIError::PGP(format!(
                "Missing NameSignatureEmail for '{}'",
                encrypted_node.Uid
            )))?;

        Ok((decrypted_name, name_signature_email))
    }

    fn decrypt_node_key(
        &self,
        encrypted_node: &EncryptedNode,
        parent_key: &PGPProv::PrivateKey,
        key_verification_key: &PGPProv::PublicKey,
    ) -> Result<UnlockedUserKey<PGPProv>> {
        let passphrase = self
            .pgp_provider
            .new_decryptor()
            .with_verification_key(key_verification_key)
            .with_decryption_key(parent_key)
            .decrypt(
                encrypted_node
                    .EncryptedCrypto
                    .ArmoredNodePassphrase
                    .as_bytes(),
                DataEncoding::Armor,
            )
            .map_err(|e| {
                APIError::PGP(format!(
                    "Couldn't decrypt armored passphrase for node '{}': {e:?}",
                    &encrypted_node.Uid
                ))
            })?;

        if !passphrase.is_verified() {
            return Err(APIError::PGP(format!(
                "Couldn't verify armored passphrase for node '{}'",
                &encrypted_node.Uid
            )));
        }

        let priv_key = self
            .pgp_provider
            .private_key_import(
                &encrypted_node.EncryptedCrypto.ArmoredKey,
                passphrase,
                DataEncoding::Armor,
            )
            .map_err(|e| {
                APIError::PGP(format!(
                    "Couldn't import armored key for '{}': {e:?}",
                    &encrypted_node.Uid
                ))
            })?;

        Ok(DecryptedUserKey {
            id: KeyId(encrypted_node.Uid.clone()),
            public_key: self
                .pgp_provider
                .private_key_to_public_key(&priv_key)
                .map_err(|e| {
                    APIError::PGP(format!("Couldn't derive public key from private key: {e}"))
                })?,
            private_key: priv_key,
        })
    }

    pub(crate) fn get_parent_keys<'a>(
        node: &EncryptedNode,
        cache: &'a Cache<PGPProv>,
    ) -> Result<&'a PGPProv::PrivateKey> {
        if let Some(parent_uid) = &node.ParentUid {
            return cache.get_node_private_key(parent_uid);
        } else if let Some(share_id) = &node.ShareId {
            let key = cache.get_share_private_key(share_id)?;
            return Ok(&key.private_key);
        }
        Err(APIError::Node(format!(
            "Couldn't find parent of '{}'",
            node.Uid
        )))
    }

    pub(crate) fn generate_node_file_content_key(
        &self,
        node_private_key: &PGPProv::PrivateKey,
    ) -> Result<NodeFileContentKey<PGPProv>> {
        let content_key_packet_session_key = self
            .pgp_provider
            .new_encryptor()
            .generate_session_key()
            .map_err(|e| APIError::PGP(format!("Couldn't generate session key: {e:?}")))?;

        let public_key = self
            .pgp_provider
            .private_key_to_public_key(node_private_key)
            .map_err(|e| {
                APIError::PGP(format!("Couldn't derive public key from private key: {e}"))
            })?;

        let encrypted_session_key = self
            .pgp_provider
            .new_encryptor()
            .with_encryption_key(&public_key)
            .encrypt_session_key(&content_key_packet_session_key)
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt session key: {e:?}")))?;

        let armored_session_key_signature = self
            .pgp_provider
            .new_signer()
            .with_signing_key(node_private_key)
            .sign_detached(encrypted_session_key.as_slice(), DataEncoding::Armor)
            .map_err(|e| APIError::PGP(format!("Error while signing the key: {e:?}")))?;

        Ok(NodeFileContentKey {
            content_key_packet_session_key,
            encrypted_session_key,
            armored_session_key_signature,
        })
    }

    pub(crate) fn create_new_node_encrypted_crypto(
        &self,
        user: &User,
        encryption_key: &PGPProv::PublicKey,
        signing_key: &PGPProv::PrivateKey,
    ) -> Result<(EncryptedNodeCrypto, PGPProv::PrivateKey)> {
        let passphrase = Self::generate_passphrase();
        let new_private_key = self
            .pgp_provider
            .new_key_generator()
            .with_user_id(NODEKEY_USER, NODEKEY_EMAIL)
            .generate()
            .map_err(|e| APIError::PGP(format!("Couldn't generate new key: {e:?}")))?;

        let mut encrypted_passphrase: Vec<u8> = vec![];
        let passphrase_encryptor = self
            .pgp_provider
            .new_encryptor()
            .with_encryption_key(encryption_key)
            .with_signing_key(signing_key);

        let mut encryptor_writer = passphrase_encryptor
            .encrypt_stream_with_detached_signature(
                &mut encrypted_passphrase,
                DetachedSignatureVariant::Plaintext,
                DataEncoding::Armor,
            )
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt passphrase: {e}")))?;

        encryptor_writer
            .write_all(passphrase.as_ref().as_bytes())
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt passphrase: {e}")))?;

        let detached_signature = encryptor_writer
            .finalize_with_detached_signature()
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt passphrase: {e}")))?;

        let encrypted_passphrase = String::from_utf8(encrypted_passphrase).unwrap();
        let passphrase_signature = String::from_utf8(detached_signature).unwrap();

        let armored_key_data = self
            .pgp_provider
            .private_key_export(&new_private_key, passphrase.as_ref(), DataEncoding::Armor)
            .map_err(|e| APIError::PGP(format!("Couldn't export new key: {e:?}")))?
            .as_ref()
            .to_vec();

        Ok((
            EncryptedNodeCrypto {
                SignatureEmail: Some(user.Email.to_string()),
                NameSignatureEmail: Some(user.Email.to_string()),
                ArmoredKey: String::from_utf8(armored_key_data).unwrap(),
                ArmoredNodePassphrase: encrypted_passphrase,
                ArmoredNodePassphraseSignature: passphrase_signature,
                File: None,
                ActiveRevision: None,
                Folder: None,
            },
            new_private_key,
        ))
    }

    pub(crate) fn export_session_key(&self, key: &PGPProv::SessionKey) -> Result<impl AsRef<[u8]>> {
        Ok(self
            .pgp_provider
            .session_key_export(key)
            .map_err(|e| APIError::PGP(format!("Couldn't export session key: {e}")))?
            .0)
    }

    pub(crate) fn export_public_key(&self, key: &PGPProv::PublicKey) -> Result<impl AsRef<[u8]>> {
        self.pgp_provider
            .public_key_export(key, proton_crypto::crypto::DataEncoding::Armor)
            .map_err(|e| APIError::PGP(format!("Couldn't export public key: {e}")))
    }

    pub(crate) fn generate_passphrase() -> impl AsRef<str> {
        let mut data: [u8; PASSPHRASE_LEN] = [0; PASSPHRASE_LEN];
        rand::fill(&mut data);
        BASE64_STANDARD.encode(data)
    }

    pub(crate) fn generate_hashkey() -> impl AsRef<str> {
        let mut data: [u8; HASHKEY_LEN] = [0; HASHKEY_LEN];
        rand::fill(&mut data);
        BASE64_STANDARD.encode(data)
    }

    pub(crate) fn encrypt_hash_key(
        &self,
        hash_key: impl AsRef<[u8]>,
        node_private_key: &PGPProv::PrivateKey,
        verif_key: &PGPProv::PrivateKey,
    ) -> Result<String> {
        let node_key = self
            .pgp_provider
            .private_key_to_public_key(node_private_key)
            .map_err(|e| {
                APIError::PGP(format!("Couldn't derive public key from private key: {e}"))
            })?;

        let encrypted = self
            .pgp_provider
            .new_encryptor()
            .with_encryption_key(&node_key)
            .with_signing_key(verif_key)
            .encrypt(hash_key)
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt hash key: {e:?}")))?
            .armor()
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt hash key: {e:?}")))?;

        String::from_utf8(encrypted)
            .map_err(|e| APIError::PGP(format!("Couldn't parse encrypted hash key as UTF-8: {e}")))
    }

    pub(crate) fn encrypt_new_node_name(
        &self,
        parent: &DecryptedNode<PGPProv>,
        node_type: &NodeType,
        node_hash: Option<&str>,
        parent_hashkey: impl AsRef<[u8]>,
        new_name: &str,
        cache: &Cache<PGPProv>,
    ) -> Result<RenameLinkParameters> {
        let user = cache
            .get_user()
            .ok_or(APIError::Account("User not loaded".into()))?;
        let user_email: String = user.Email.clone();

        let address_key = cache
            .get_unlocked_address_key(&user_email)
            .ok_or(APIError::Account(
                "Couldn't retrieve user address keys".into(),
            ))?
            .into_iter()
            .next()
            .ok_or(APIError::Account(
                "No unlocked address keys available".into(),
            ))?;

        let encrypted_name = String::from_utf8(
            self.pgp_provider
                .new_encryptor()
                .with_encryption_key(&parent.keys.public_key)
                .with_signing_key(&address_key.private_key)
                .encrypt(new_name)
                .map_err(|e| APIError::PGP(format!("Couldn't encrypt name: {e:?}")))?
                .armor()
                .map_err(|e| APIError::PGP(format!("Couldn't armor name: {e}")))?,
        )
        .map_err(|e| APIError::PGP(format!("Couldn't parse encrypted name as UTF-8: {e}")))?;

        let mut new_name_hasher = HmacSha256::new_from_slice(parent_hashkey.as_ref())
            .map_err(|e| APIError::PGP(format!("Couldn't hash encrypted name: {e:?}")))?;
        new_name_hasher.update(new_name.as_bytes());
        let new_name_hash = new_name_hasher.finalize().into_bytes();

        let new_name_hash_hex = hex::encode(new_name_hash);

        let mime = if *node_type == NodeType::File {
            Some(
                mime_guess::from_path(Path::new(new_name))
                    .first_or_octet_stream()
                    .as_ref()
                    .to_string(),
            )
        } else {
            None
        };

        Ok(RenameLinkParameters {
            Name: encrypted_name,
            Hash: new_name_hash_hex,
            MediaType: mime,
            NameSignatureEmail: user_email.clone(),
            OriginalNameHash: node_hash.map(std::string::ToString::to_string),
        })
    }

    pub(crate) fn encrypt_block(
        &self,
        session_key: &PGPProv::SessionKey,
        encryption_key: &PGPProv::PrivateKey,
        signing_key: &PGPProv::PrivateKey,
        data: impl AsRef<[u8]>,
    ) -> Result<(Vec<u8>, String)> {
        let encryption_key = self
            .pgp_provider
            .private_key_to_public_key(encryption_key)
            .map_err(|e| {
                APIError::PGP(format!("Couldn't derive public key from private key: {e}"))
            })?;

        let encrypted_msg = self
            .pgp_provider
            .new_encryptor()
            .with_session_key_ref(session_key)
            .with_signing_key(signing_key)
            .encrypt_raw(data.as_ref(), DataEncoding::Bytes)
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt block: {e}")))?;

        let encrypted = encrypted_msg.as_slice();

        let exported_session_key = self
            .pgp_provider
            .session_key_export(session_key)
            .map_err(|e| APIError::PGP(format!("Couldn't export session key: {e:?}")))?;

        let signature = self
            .pgp_provider
            .new_signer()
            .with_signing_key(signing_key)
            .sign_detached(exported_session_key.0, DataEncoding::Bytes)
            .map_err(|e| APIError::PGP(format!("Error while signing the key: {e:?}")))?;

        let armored_signature = self
            .pgp_provider
            .new_encryptor()
            .with_encryption_key(&encryption_key)
            .encrypt(signature)
            .map_err(|e| APIError::PGP(format!("Couldn't encrypt signature: {e}")))?
            .armor()
            .map_err(|e| APIError::PGP(format!("Couldn't armor signature: {e}")))?;

        Ok((
            encrypted.to_vec(),
            String::from_utf8(armored_signature).map_err(|e| {
                APIError::PGP(format!("Couldn't parse manifest signature as UTF-8: {e}"))
            })?,
        ))
    }

    pub(crate) fn sign_manifest(
        &self,
        manifest: impl AsRef<[u8]>,
        signing_key: &PGPProv::PrivateKey,
    ) -> Result<String> {
        let signer = self.pgp_provider.new_signer().with_signing_key(signing_key);
        let armored_signature = signer
            .sign_detached(manifest, DataEncoding::Armor)
            .map_err(|e| APIError::PGP(format!("Error while signing the manifest: {e:?}")))?;

        String::from_utf8(armored_signature)
            .map_err(|e| APIError::PGP(format!("Couldn't parse manifest signature as UTF-8: {e}")))
    }

    pub(crate) fn encrypt_extended_attributes(
        &self,
        xattr: impl AsRef<[u8]>,
        node_private_key: &PGPProv::PrivateKey,
        address_key: &PGPProv::PrivateKey,
    ) -> Result<String> {
        let node_key = self
            .pgp_provider
            .private_key_to_public_key(node_private_key)
            .map_err(|e| {
                APIError::PGP(format!("Couldn't derive public key from private key: {e}"))
            })?;

        let armored_xattr = self
            .pgp_provider
            .new_encryptor()
            .with_encryption_key(&node_key)
            .with_signing_key(address_key)
            .encrypt(xattr.as_ref())
            .map_err(|e| {
                APIError::PGP(format!(
                    "Error while encrypting the extended attributes: {e:?}"
                ))
            })?
            .armor()
            .map_err(|e| {
                APIError::PGP(format!(
                    "Error while armoring the extended attributes: {e:?}"
                ))
            })?;

        String::from_utf8(armored_xattr).map_err(|e| {
            APIError::PGP(format!(
                "Couldn't parse armored extended attributes as UTF-8: {e}"
            ))
        })
    }
}

impl<PGPProv: PGPProviderSync, SRPProv: SRPProvider> Debug for Crypto<PGPProv, SRPProv> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crypto").finish()
    }
}

pub(crate) struct NodeFileContentKey<PGPProv: PGPProviderSync> {
    pub content_key_packet_session_key: PGPProv::SessionKey,
    pub encrypted_session_key: Vec<u8>,
    pub armored_session_key_signature: Vec<u8>,
}
