use libunftp::auth::DefaultUser;
use libunftp::ServerBuilder;
use proton_crypto::crypto::PGPProviderSync;
use proton_crypto::srp::SRPProvider;

use crate::ProtonDriveStorage;

/// Creates a new `Server` with a Proton Drive storage back-end
///
/// # Example
///
/// ```rust
/// use libunftp::Server;
/// use unftp_sbe_pd::ext::with_pd;
///
/// let server = with_pd("username", "password", || {
///         println!("Enter your 2FA code: ");
///         let mut code = String::new();
///         std::io::stdin()
///             .read_line(&mut code)
///             .expect("Failed to read line");
///         code.trim().to_string()
///     })
///     .build();
/// ```
#[allow(clippy::missing_panics_doc)]
pub fn with_pd(
    username: &'static str,
    password: &'static str,
    two_fa: fn() -> String,
) -> ServerBuilder<ProtonDriveStorage<impl PGPProviderSync + Send + Sync + 'static, impl SRPProvider + 'static>, DefaultUser> {
    libunftp::ServerBuilder::new(Box::new(move || {
        let pgp_provider = proton_crypto::new_pgp_provider();
        let srp_provider = proton_crypto::new_srp_provider();
        ProtonDriveStorage::new(
            pgp_provider,
            srp_provider,
            username,
            password,
            Some(two_fa),
        )
        .expect("Failed to create ProtonDriveStorage")
    }))
}
