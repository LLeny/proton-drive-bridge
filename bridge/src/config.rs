use crate::{APP_NAME, vault::LockedVault};
use anyhow::{Result, anyhow};
use log::error;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Default, Deserialize, Serialize, Debug)]
pub(crate) struct Config {
    pub(crate) ui: UIConfig,
    pub(crate) drive: DriveConfig,
    pub(crate) server: ServerConfig,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub(crate) struct UIConfig {
    pub(crate) dark_theme: bool,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct DriveConfig {
    pub(crate) vault: LockedVault,
    pub(crate) salt: [u8; 16],
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct ServerConfig {
    pub(crate) port: u16,
    pub(crate) greeting: String,
    pub(crate) auth_json: Option<PathBuf>,
    pub(crate) tls: bool,
    pub(crate) tls_cert: Option<PathBuf>,
    pub(crate) tls_key: Option<PathBuf>,
    pub(crate) worker_count: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 2121,
            greeting: "Welcome to my Proton Drive FTP Server".to_owned(),
            auth_json: None,
            tls: false,
            tls_cert: None,
            tls_key: None,
            worker_count: 4,
        }
    }
}

impl Config {
    pub(crate) fn initialize() -> Result<Config> {
        let config_file = Self::config_file()?;
        if config_file.exists() {
            let content = std::fs::read(config_file)?;
            let cfg: Config = serde_json::from_slice(&content).unwrap_or_else(|e| {
                error!("Couldn't parse config file, using default: {e}");
                let cfg = Config::default();
                let _ = cfg.save();
                cfg
            });
            Ok(cfg)
        } else {
            let cfg = Config::default();
            cfg.save()?;
            Ok(cfg)
        }
    }

    pub(crate) fn save(&self) -> Result<()> {
        let config_file = Self::config_file()?;
        let prefix = config_file.parent().ok_or(anyhow::Error::msg(
            "Couldn't identify parent directory".to_owned(),
        ))?;
        std::fs::create_dir_all(prefix)?;
        let content = serde_json::to_vec(self)?;
        std::fs::write(config_file, content).map_err(anyhow::Error::msg)
    }

    fn config_file() -> Result<PathBuf> {
        let mut config_path = dirs::data_local_dir().ok_or(anyhow!("No data local dir"))?;
        config_path.push(APP_NAME);
        config_path.push(format!("{APP_NAME}.json"));
        Ok(config_path)
    }
}

impl Default for DriveConfig {
    fn default() -> Self {
        Self {
            vault: LockedVault::default(),
            salt: proton_crypto::generate_secure_random_bytes(),
        }
    }
}
