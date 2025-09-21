use crate::client::authenticator::{AuthTokens, Password};
use crate::consts::REFRESH_ENDPOINT;
use crate::errors::Result;
use crate::remote::payloads::{
    AddressResponse, Auth, Auth2FARequest, AuthInfo, AuthInfoRequest, AuthRequest,
    GetAddressesResponse, KeySalts, RefreshSessionRequest, RefreshSessionResponse, User,
    UserResponse,
};
use crate::{
    consts::{
        ADDRESSES_ENDPOINT, AUTH_2FA_ENDPOINT, AUTH_ENDPOINT, AUTH_INFO_ENDPOINT, SALTS_ENDPOINT,
        USERS_ENDPOINT,
    },
    errors::APIError,
    remote::{Client, api_session::RequestType},
};
use base64::prelude::*;

impl Client {
    async fn auth_info(&self, username: &str, password: Password) -> Result<Auth> {
        let auth_info: AuthInfo = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                AUTH_INFO_ENDPOINT,
                Some(&AuthInfoRequest {
                    Username: username,
                    Intent: "Proton",
                }),
            )
            .await?;

        let srp_auth = proton_srp::SRPAuth::new(
            &proton_srp::RPGPVerifier::default(),
            str::from_utf8(password.0.as_slice()).map_err(|e| APIError::Unknown(e.to_string()))?,
            auth_info.Version,
            &auth_info.Salt,
            &auth_info.Modulus,
            &auth_info.ServerEphemeral,
        );

        let proofs = srp_auth
            .map_err(APIError::SRP)?
            .generate_proofs()
            .map_err(APIError::SRP)?;

        let auth: Auth = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                AUTH_ENDPOINT,
                Some(&AuthRequest {
                    Username: username,
                    ClientEphemeral: base64::prelude::BASE64_STANDARD
                        .encode(proofs.client_ephemeral)
                        .as_str(),
                    ClientProof: base64::prelude::BASE64_STANDARD
                        .encode(proofs.client_proof)
                        .as_str(),
                    SRPSession: &auth_info.SRPSession,
                }),
            )
            .await?;

        let server_proof = base64::prelude::BASE64_STANDARD
            .decode(&auth.ServerProof)
            .map_err(|e| APIError::Unknown(e.to_string()))?;

        if !proofs.compare_server_proof(server_proof.as_slice()) {
            return Err(APIError::Unknown("Server proof verification failed".to_owned()));
        }

        Ok(auth)
    }

    pub(crate) fn set_tokens(&mut self, auth: AuthTokens) {
        self.api_session.set_tokens(auth);
    }

    pub(crate) async fn login_auth(
        &mut self,
        username: &str,
        password: Password,
    ) -> Result<(bool, AuthTokens)> {
        let auth_info = self.auth_info(username, password).await?;

        let tokens = AuthTokens::new(auth_info.AccessToken, auth_info.RefreshToken, auth_info.Uid);

        self.set_tokens(tokens.clone());

        Ok((auth_info.TwoFA.Enabled, tokens))
    }

    pub(crate) async fn send_2fa(&self, tfa: &str) -> Result<bool> {
        let resp = self
            .api_session
            .request(
                RequestType::Post,
                AUTH_2FA_ENDPOINT,
                Some(&Auth2FARequest { TwoFactorCode: tfa }),
            )
            .await?;

        Ok(resp.status().is_success())
    }

    pub(crate) async fn refresh_session(&self, refresh_token: &str) -> Result<AuthTokens> {
        let auth: RefreshSessionResponse = self
            .api_session
            .request_with_json_response(
                RequestType::Post,
                REFRESH_ENDPOINT,
                Some(&RefreshSessionRequest::new(refresh_token.to_owned())),
            )
            .await?;

        if auth.Code.is_error() {
            return Err(APIError::Account("Authentication required.".to_owned()));
        }

        Ok(AuthTokens {
            refresh: auth.RefreshToken,
            access: auth.AccessToken,
            uid: auth.UID,
        })
    }

    pub(crate) async fn get_user(&mut self) -> Result<Option<User>> {
        let user = self
            .api_session
            .request_with_json_response::<(), UserResponse>(RequestType::Get, USERS_ENDPOINT, None)
            .await?;

        Ok(user.User)
    }

    pub(crate) async fn get_salts(&mut self) -> Result<KeySalts> {
        let salts = self
            .api_session
            .request_with_json_response::<(), KeySalts>(RequestType::Get, SALTS_ENDPOINT, None)
            .await?;

        Ok(salts)
    }

    pub(crate) async fn get_addresses(&mut self) -> Result<Vec<AddressResponse>> {
        let addresses = self
            .api_session
            .request_with_json_response::<(), GetAddressesResponse>(
                RequestType::Get,
                ADDRESSES_ENDPOINT,
                None,
            )
            .await?;

        Ok(addresses.Addresses)
    }
}
