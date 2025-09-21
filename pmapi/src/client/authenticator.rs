use crate::{
    client::{crypto::Crypto, session_store::SessionStore},
    errors::{APIError, Result},
};
use log::info;
use proton_crypto::{crypto::PGPProviderSync, srp::SRPProvider};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct Password(pub Vec<u8>);

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct AuthTokens {
    pub access: String,
    pub refresh: String,
    pub uid: String,
}

impl AuthTokens {
    /// Creates a new set of authentication tokens.
    ///
    /// The tokens are typically returned by the Proton API after a successful login or refresh.
    ///
    /// # Errors
    ///
    /// This constructor does not return errors.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new(access: String, refresh: String, uid: String) -> Self {
        Self {
            access,
            refresh,
            uid,
        }
    }
}

pub struct Authenticator {
    remote_client: crate::remote::Client,
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator {
    /// Creates a new `Authenticator` with a fresh remote client.
    ///
    /// # Errors
    ///
    /// This constructor does not return errors.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self {
            remote_client: crate::remote::Client::new(),
        }
    }

    /// Refreshes the session using the provided refresh token.
    ///
    /// Returns new authentication tokens on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the network request fails, the response is invalid, or
    /// the API rejects the refresh token.
    pub async fn refresh_session(&mut self, refresh_token: &str) -> Result<AuthTokens> {
        self.remote_client.refresh_session(refresh_token).await
    }

    /// Performs username/password authentication.
    ///
    /// Returns a tuple `(two_factor_required, tokens)` on success. If `two_factor_required` is `true`,
    /// call [`two_fa`] to complete authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the credentials are invalid, if 2FA is required but cannot be initiated,
    /// or if the network request/response fails.
    pub async fn login(
        &mut self,
        username: &str,
        password: Password,
    ) -> Result<(bool, AuthTokens)> {
        self.remote_client.login_auth(username, password).await
    }

    /// Retrieves and prepares session data required for Drive operations.
    ///
    /// This fetches the user, salts, addresses and unlocks the necessary keys using the provided `crypto`
    /// implementation and the user's mailbox password (already hashed/salted as needed by SRP).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - User information cannot be retrieved from the API.
    /// - Salts or addresses cannot be fetched.
    /// - Cryptographic operations (SRP/PGP) to unlock keys fail.
    /// - Any network or API error occurs during the process.
    pub async fn get_session_data<PGPProv: PGPProviderSync, SRPProv: SRPProvider>(
        &mut self,
        crypto: &Crypto<PGPProv, SRPProv>,
        password: &Password,
    ) -> Result<SessionStore> {
        info!("get_session_data");

        let mut session_store = SessionStore::new();

        let user = self
            .remote_client
            .get_user()
            .await?
            .ok_or(APIError::Account("Couldn't retrieve user.".to_owned()))?;

        session_store.set_user(user);

        session_store.set_salt(self.remote_client.get_salts().await?);

        self.remote_client
            .get_addresses()
            .await?
            .into_iter()
            .for_each(|a| session_store.add_address(a));

        crypto.unlock_user_keys(password, &mut session_store)?;

        crypto.unlock_address_keys(&mut session_store)?;

        Ok(session_store)
    }

    /// Completes two-factor authentication using the provided code.
    ///
    /// Returns `true` on success, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server responds with an error.
    pub async fn two_fa(&self, two_fa: &str) -> Result<bool> {
        self.remote_client.send_2fa(two_fa).await
    }

    /// Sets the authentication tokens on the underlying remote client.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn set_tokens(&mut self, tokens: AuthTokens) {
        self.remote_client.set_tokens(tokens);
    }
}
