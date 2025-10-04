use crate::APP_NAME;
use anyhow::{Ok, Result, anyhow};
use proton_crypto::crypto::{KeyGenerator, KeyGeneratorSync, PGPProviderSync};
use std::path::PathBuf;

pub(crate) fn store_key(key: impl AsRef<[u8]>) -> Result<()> {
    clear_key()?;
    let key_file = key_file()?;
    std::fs::write(key_file, key).map_err(anyhow::Error::msg)
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
    let key_file = key_file()?;
    if key_file.exists() {
        std::fs::remove_file(key_file).map_err(anyhow::Error::msg)
    } else {
        Ok(())
    }
}

pub(crate) fn get_key() -> Result<impl AsRef<[u8]>> {
    let key_file = key_file()?;
    if key_file.exists() {
        let content = std::fs::read(key_file)?;
        Ok(content)
    } else {
        Err(anyhow::Error::msg("No key found"))
    }
}

fn key_file() -> Result<PathBuf> {
    let mut config_path = dirs::data_local_dir().ok_or(anyhow!("No data local dir"))?;
    config_path.push(APP_NAME);
    config_path.push(format!("key.key"));
    Ok(config_path)
}
