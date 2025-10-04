
#[cfg(feature = "keyring")]
pub(crate) mod keyring;
#[cfg(not(feature = "keyring"))]
#[path ="keyring_local.rs"]
pub(crate) mod keyring;