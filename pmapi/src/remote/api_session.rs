use std::fmt;
use crate::errors::Result;
use reqwest::{multipart, Response};
use serde::{de::DeserializeOwned, Serialize};
use crate::{consts::APP_VERSION, errors::APIError};

#[derive(Clone)]
pub(crate) struct APISession {
    client: reqwest::Client,
    host_url: reqwest::Url,
    uid: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl APISession {
    pub(crate) fn new(host_url: reqwest::Url) -> Self {
        Self {
            client: reqwest::Client::new(),
            host_url,
            uid: None,
            access_token: None,
            refresh_token: None,
        }
    }

    pub(crate) fn set_authentication(
        &mut self,
        uid: String,
        access_token: String,
        refresh_token: String
    ) {
        self.uid = Some(uid);
        self.access_token = Some(access_token);
        self.refresh_token = Some(refresh_token);
    }

    fn url(&self, endpoint: &str) -> Result<reqwest::Url> {
        self.host_url
            .join(endpoint)
            .map_err(|_| APIError::UrlError(endpoint.to_string()))
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
        if let Some(uid) = &self.uid {
            request = request.header("X-Pm-Uid", uid);
        }
        if let Some(acc) = &self.access_token {
            request = request.bearer_auth(acc);
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
            .field("uid", &self.uid)
            .finish()
    }
}

#[derive(Debug)]
pub enum RequestType {
    Get,
    Post,
    Put,
}
