use anyhow::Result;
use keyring::Entry;
use proton_crypto::crypto::{KeyGenerator, KeyGeneratorSync, PGPProviderSync};

fn entry() -> Result<Entry> {
    Entry::new("proton-drive-bridge", "key").map_err(anyhow::Error::msg)
}

pub(crate) fn store_key(key: impl AsRef<[u8]>) -> Result<()> {
    entry()?
        .set_secret(key.as_ref())
        .map_err(anyhow::Error::msg)
}

pub(crate) fn get_key() -> Result<impl AsRef<[u8]>> {
    entry()?.get_secret().map_err(anyhow::Error::msg)
}

pub(crate) fn generate_new_key(salted_password: impl AsRef<[u8]>) -> Result<()> {
    let pgp = proton_crypto::new_pgp_provider();
    let key = pgp
        .new_key_generator()
        .with_user_id("PDrive", "PDrive@no-reply.co")
        .generate()?;
    let export = pgp.private_key_export(
        &key,
        salted_password,
        proton_crypto::crypto::DataEncoding::Armor,
    )?;
    store_key(export)
}

pub(crate) fn clear_key() -> Result<()> {
    entry()?.delete_credential().map_err(anyhow::Error::msg)
}
