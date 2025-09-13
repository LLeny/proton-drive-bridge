use crate::errors::Result;
use crate::remote::payloads::{
    AddressResponse, Auth, Auth2FA, Auth2FARequest, AuthInfo, AuthInfoRequest, AuthRequest,
    GetAddressesResponse, KeySalts, User, UserResponse,
};
use crate::{
    consts::{
        ADDRESSES_ENDPOINT, AUTH_2FA_ENDPOINT, AUTH_ENDPOINT, AUTH_INFO_ENDPOINT, SALTS_ENDPOINT,
        USERS_ENDPOINT,
    },
    errors::APIError,
    remote::{api_session::RequestType, Client},
};
use base64::prelude::*;
use log::info;

impl Client {
    async fn auth_info(&self, username: &str, password: &[u8]) -> Result<Auth> {
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
            str::from_utf8(password)
                .map_err(|e| APIError::Unknown(e.to_string()))?,
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
            return Err(APIError::Unknown("Server proof verification failed".into()));
        }

        Ok(auth)
    }

    pub(crate) async fn login_auth(
        &mut self,
        username: &str,
        password: &[u8],
        two_fa: Option<fn() -> String>,
    ) -> Result<()> {
        let auth_info = self.auth_info(username, password).await?;

        self.api_session.set_authentication(
            auth_info.Uid,
            auth_info.AccessToken,
            auth_info.RefreshToken,
        );

        if !auth_info.TwoFA.Enabled {
            return Ok(());
        }

        let mut tfa_ok = false;

        let tfa = two_fa.ok_or(APIError::Account(
            "2FA enabled, requires 2FA function implemented.".to_string(),
        ))?;

        while !tfa_ok {
            let two_fa_code = tfa();

            let resp = self
                .api_session
                .request(
                    RequestType::Post,
                    AUTH_2FA_ENDPOINT,
                    Some(&Auth2FARequest {
                        TwoFactorCode: two_fa_code.as_str(),
                    }),
                )
                .await?;

            tfa_ok = resp.status().is_success();

            if tfa_ok {
                let auth_2fa_resp = resp
                    .json::<Auth2FA>()
                    .await
                    .map_err(|e| APIError::DeserializeJSON(e.to_string()))?;
                info!("Fetched 2FA auth: {auth_2fa_resp:#?}");
            } else {
                info!("2FA code was incorrect.");
            }
        }

        Ok(())
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
