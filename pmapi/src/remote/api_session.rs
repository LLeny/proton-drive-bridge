use crate::client::authenticator::AuthTokens;
use crate::errors::Result;
use crate::{consts::APP_VERSION, errors::APIError};
use reqwest::{Response, multipart};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;

#[derive(Clone)]
pub(crate) struct APISession {
    client: reqwest::Client,
    host_url: reqwest::Url,
    tokens: Option<AuthTokens>,
}

impl APISession {
    pub(crate) fn new(host_url: reqwest::Url) -> Self {
        Self {
            client: reqwest::Client::new(),
            host_url,
            tokens: None,
        }
    }

    pub(crate) fn set_tokens(&mut self, tokens: AuthTokens) {
        self.tokens = Some(tokens);
    }

    fn url(&self, endpoint: &str) -> Result<reqwest::Url> {
        self.host_url
            .join(endpoint)
            .map_err(|_| APIError::UrlError(endpoint.to_owned()))
    }

    pub(crate) async fn request<P>(
        &self,
        req_type: RequestType,
        endpoint: &str,
        payload: Option<&P>,
    ) -> Result<Response>
    where
        P: Serialize + ?Sized,
    {
        let url = self.url(endpoint)?;
        let request = match req_type {
            RequestType::Get => self.client.get(url),
            RequestType::Post => self.client.post(url),
            RequestType::Put => self.client.put(url),
        };
        let mut request = self.add_auth(request);
        if let Some(pl) = payload {
            request = request.json(pl);
        }

        request.send().await.map_err(APIError::Reqwest)
    }

    pub(crate) async fn request_with_json_response<P, R>(
        &self,
        req_type: RequestType,
        endpoint: &str,
        payload: Option<&P>,
    ) -> Result<R>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let response = self.request(req_type, endpoint, payload).await?;
        let content = response.text().await.map_err(APIError::Reqwest)?;
        
        serde_json::from_str(&content)
            .map_err(|e| APIError::DeserializeJSON(format!("{:?}: {}", e, &content)))
    }

    pub(crate) async fn post_multipart_form_data(
        &self,
        endpoint: &str,
        token: &str,
        data: impl AsRef<[u8]>,
    ) -> Result<usize> {
        let form_data = multipart::Part::bytes(data.as_ref().to_vec())
            .file_name("blob")
            .mime_str("application/octet-stream")
            .map_err(APIError::Reqwest)?;
        let form = multipart::Form::new().part("Block", form_data);
        let url = self.url(endpoint)?;
        self.client
            .post(url)
            .header("pm-storage-token", token)
            .header("x-pm-drive-sdk-version", APP_VERSION)
            .multipart(form)
            .send()
            .await
            .map_err(APIError::Reqwest)?
            .error_for_status()
            .map_err(APIError::Reqwest)?;
        Ok(data.as_ref().len())
    }

    fn add_auth(&self, reqwest: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut request = reqwest.header("X-Pm-Appversion", APP_VERSION);

        if let Some(tokens) = &self.tokens {
            request = request
                .header("X-Pm-Uid", &tokens.uid)
                .bearer_auth(&tokens.access);
        }

        request
    }
}

unsafe impl Sync for APISession {}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for APISession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("APISession")
            .field("client", &self.client)
            .field("host_url", &self.host_url)
            .finish()
    }
}

#[derive(Debug)]
pub enum RequestType {
    Get,
    Post,
    Put,
}
