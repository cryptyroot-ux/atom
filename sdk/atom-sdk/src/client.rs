//! Typed client for the ATOM /v1 API.
//!
//! Matches OpenAPI spec v4.0. Supports async via `reqwest` and blocking via `ureq`.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{SdkError, SdkResult};
use crate::types::{
    GetClaimResponse, HealthStatus, ProblemDetail, PutClaimRequest, PutClaimResponse,
    SubmitEffectRequest, SubmitEffectResponse, VerifyArtifactRequest, VerifyArtifactResponse,
};

/// The async client. Use [`AtomClientBuilder`] to construct one.
#[derive(Debug, Clone)]
pub struct AtomClient {
    inner: ClientInner,
    base_url: String,
    auth_token: Option<String>,
    user_agent: String,
}

#[derive(Debug, Clone)]
enum ClientInner {
    Async(reqwest::Client),
    Blocking(ureq::Agent),
}

impl AtomClient {
    /// Builder for [`AtomClient`]. Default timeout is 30s.
    pub fn builder() -> AtomClientBuilder {
        AtomClientBuilder::default()
    }

    /// Perform a GET against `path` and deserialize the JSON response.
    pub async fn get_json_async<T: DeserializeOwned>(&self, path: &str) -> SdkResult<T> {
        match &self.inner {
            ClientInner::Async(c) => {
                let url = self.url(path);
                let mut req = c.get(&url);
                req = self.apply_async_headers(req);
                let resp = req
                    .send()
                    .await
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                self.parse_response(resp.status(), resp.json::<T>().await)
            }
            ClientInner::Blocking(_) => Err(SdkError::InvalidConfig(
                "this client is blocking-only; call get_json instead".into(),
            )),
        }
    }

    /// Perform a POST with a JSON body and deserialize the JSON response.
    pub async fn post_json_async<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> SdkResult<T> {
        match &self.inner {
            ClientInner::Async(c) => {
                let url = self.url(path);
                let mut req = c.post(&url).json(body);
                if let Some(key) = idempotency_key {
                    req = req.header("Idempotency-Key", key);
                }
                req = self.apply_async_headers(req);
                let resp = req
                    .send()
                    .await
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                let status = resp.status();
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                self.parse_bytes(status, &bytes)
            }
            ClientInner::Blocking(_) => Err(SdkError::InvalidConfig(
                "this client is blocking-only; call post_json instead".into(),
            )),
        }
    }

    /// Perform a PUT with a JSON body and deserialize the JSON response.
    pub async fn put_json_async<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> SdkResult<T> {
        match &self.inner {
            ClientInner::Async(c) => {
                let url = self.url(path);
                let mut req = c.put(&url).json(body);
                req = self.apply_async_headers(req);
                let resp = req
                    .send()
                    .await
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                let status = resp.status();
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                self.parse_bytes(status, &bytes)
            }
            ClientInner::Blocking(_) => Err(SdkError::InvalidConfig(
                "this client is blocking-only; call put_json instead".into(),
            )),
        }
    }

    /// Blocking GET against `path`.
    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> SdkResult<T> {
        match &self.inner {
            ClientInner::Blocking(a) => {
                let url = self.url(path);
                let mut req = a.get(&url);
                req = self.apply_blocking_headers(req);
                let resp = req.call().map_err(|e| SdkError::Transport(e.to_string()))?;
                self.parse_ureq(resp)
            }
            ClientInner::Async(_) => Err(SdkError::InvalidConfig(
                "this client is async-only; call get_json_async instead".into(),
            )),
        }
    }

    /// Blocking POST with a JSON body.
    pub fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> SdkResult<T> {
        match &self.inner {
            ClientInner::Blocking(a) => {
                let url = self.url(path);
                let body_str = serde_json::to_string(body).map_err(SdkError::Serialize)?;
                let mut req = a
                    .post(&url)
                    .set("Content-Type", "application/json");
                if let Some(key) = idempotency_key {
                    req = req.set("Idempotency-Key", key);
                }
                req = self.apply_blocking_headers(req);
                let resp = req
                    .send_string(&body_str)
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                self.parse_ureq(resp)
            }
            ClientInner::Async(_) => Err(SdkError::InvalidConfig(
                "this client is async-only; call post_json_async instead".into(),
            )),
        }
    }

    /// Blocking PUT with a JSON body.
    pub fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> SdkResult<T> {
        match &self.inner {
            ClientInner::Blocking(a) => {
                let url = self.url(path);
                let body_str = serde_json::to_string(body).map_err(SdkError::Serialize)?;
                let mut req = a
                    .put(&url)
                    .set("Content-Type", "application/json");
                req = self.apply_blocking_headers(req);
                let resp = req
                    .send_string(&body_str)
                    .map_err(|e| SdkError::Transport(e.to_string()))?;
                self.parse_ureq(resp)
            }
            ClientInner::Async(_) => Err(SdkError::InvalidConfig(
                "this client is async-only; call put_json_async instead".into(),
            )),
        }
    }

    fn apply_async_headers(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }
        req = req.header("User-Agent", &self.user_agent);
        req
    }

    fn apply_blocking_headers(&self, mut req: ureq::Request) -> ureq::Request {
        if let Some(ref token) = self.auth_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }
        req = req.set("User-Agent", &self.user_agent);
        req
    }

    /// `GET /v1/health` — typed health check.
    pub async fn health_async(&self) -> SdkResult<HealthStatus> {
        self.get_json_async("/v1/health").await
    }

    /// Blocking `GET /v1/health`.
    pub fn health(&self) -> SdkResult<HealthStatus> {
        self.get_json("/v1/health")
    }

    /// `POST /v1/effects/submit` — submit an effect for authorize + commit.
    pub async fn submit_effect_async(
        &self,
        req: &SubmitEffectRequest,
    ) -> SdkResult<SubmitEffectResponse> {
        self.post_json_async("/v1/effects/submit", req, Some(&req.idempotency_key))
            .await
    }

    /// Blocking `POST /v1/effects/submit`.
    pub fn submit_effect(&self, req: &SubmitEffectRequest) -> SdkResult<SubmitEffectResponse> {
        self.post_json("/v1/effects/submit", req, Some(&req.idempotency_key))
    }

    /// `POST /v1/artifacts/verify` — verify a content-addressed artifact.
    pub async fn verify_artifact_async(
        &self,
        req: &VerifyArtifactRequest,
    ) -> SdkResult<VerifyArtifactResponse> {
        self.post_json_async("/v1/artifacts/verify", req, None).await
    }

    /// Blocking `POST /v1/artifacts/verify`.
    pub fn verify_artifact(
        &self,
        req: &VerifyArtifactRequest,
    ) -> SdkResult<VerifyArtifactResponse> {
        self.post_json("/v1/artifacts/verify", req, None)
    }

    /// `GET /v1/claims/{id}` — fetch a claim + its provenance.
    pub async fn get_claim_async(&self, claim_id: &str) -> SdkResult<GetClaimResponse> {
        self.get_json_async(&format!("/v1/claims/{claim_id}")).await
    }

    /// Blocking `GET /v1/claims/{id}`.
    pub fn get_claim(&self, claim_id: &str) -> SdkResult<GetClaimResponse> {
        self.get_json(&format!("/v1/claims/{claim_id}"))
    }

    /// `PUT /v1/claims/{id}` — create or replace a claim.
    pub async fn put_claim_async(&self, req: &PutClaimRequest) -> SdkResult<PutClaimResponse> {
        let path = format!("/v1/claims/{}", req.claim_id);
        self.put_json_async(&path, req).await
    }

    /// Blocking `PUT /v1/claims/{id}`.
    pub fn put_claim(&self, req: &PutClaimRequest) -> SdkResult<PutClaimResponse> {
        let path = format!("/v1/claims/{}", req.claim_id);
        self.put_json(&path, req)
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{path}", self.base_url)
        } else {
            format!("{}/{path}", self.base_url)
        }
    }

    fn parse_response<T: DeserializeOwned>(
        &self,
        status: reqwest::StatusCode,
        body: reqwest::Result<T>,
    ) -> SdkResult<T> {
        let status_u16 = status.as_u16();
        if (200..300).contains(&status_u16) {
            body.map_err(|e| SdkError::Transport(e.to_string()))
        } else {
            Err(SdkError::Api {
                status: status_u16,
                message: body
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| status.to_string()),
            })
        }
    }

    fn parse_bytes<T: DeserializeOwned>(
        &self,
        status: reqwest::StatusCode,
        bytes: &[u8],
    ) -> SdkResult<T> {
        let status_u16 = status.as_u16();
        if (200..300).contains(&status_u16) {
            serde_json::from_slice(bytes).map_err(|e| SdkError::Deserialize(e.to_string()))
        } else {
            // Try to parse as RFC 9457 ProblemDetail
            if let Ok(problem) = serde_json::from_slice::<ProblemDetail>(bytes) {
                Err(SdkError::Problem(problem))
            } else {
                let message = String::from_utf8_lossy(bytes).into_owned();
                Err(SdkError::Api {
                    status: status_u16,
                    message,
                })
            }
        }
    }

    fn parse_ureq<T: DeserializeOwned>(&self, resp: ureq::Response) -> SdkResult<T> {
        let status = resp.status();
        if (200..300).contains(&status) {
            let body = resp
                .into_string()
                .map_err(|e| SdkError::Transport(e.to_string()))?;
            serde_json::from_str(&body).map_err(|e| SdkError::Deserialize(e.to_string()))
        } else {
            // Try to parse as ProblemDetail
            if let Ok(body) = resp.into_string() {
                if let Ok(problem) = serde_json::from_str::<ProblemDetail>(&body) {
                    return Err(SdkError::Problem(problem));
                }
                Err(SdkError::Api {
                    status,
                    message: body,
                })
            } else {
                Err(SdkError::Api {
                    status,
                    message: status.to_string(),
                })
            }
        }
    }
}

/// Builder for [`AtomClient`].
///
/// Caller decides async vs blocking by setting `async_mode(true|false)`.
/// Defaults: async, 30s timeout, base_url=http://localhost:8420, no auth.
#[derive(Debug)]
pub struct AtomClientBuilder {
    base_url: String,
    timeout: Duration,
    auth_token: Option<String>,
    async_mode: bool,
    user_agent: String,
}

impl Default for AtomClientBuilder {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8420".to_owned(),
            timeout: Duration::from_secs(30),
            auth_token: None,
            async_mode: true,
            user_agent: format!("atom-sdk/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl AtomClientBuilder {
    /// Set the base URL (no trailing slash required).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Set the bearer token (or API key) used for `Authorization: Bearer ...`.
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// If `true` (default), build an async client. If `false`, build a blocking client.
    pub fn async_mode(mut self, is_async: bool) -> Self {
        self.async_mode = is_async;
        self
    }

    /// Override the user agent.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Build the client.
    pub fn build(self) -> SdkResult<AtomClient> {
        if self.base_url.is_empty() {
            return Err(SdkError::InvalidConfig("base_url is empty".into()));
        }
        let inner = if self.async_mode {
            let mut b = reqwest::Client::builder()
                .timeout(self.timeout)
                .user_agent(self.user_agent.clone());
            if let Some(tok) = &self.auth_token {
                let mut headers = reqwest::header::HeaderMap::new();
                let val = reqwest::header::HeaderValue::from_str(&format!("Bearer {tok}"))
                    .map_err(|e| SdkError::InvalidConfig(format!("bad auth token: {e}")))?;
                headers.insert(reqwest::header::AUTHORIZATION, val);
                b = b.default_headers(headers);
            }
            let c = b.build().map_err(|e| SdkError::Transport(e.to_string()))?;
            ClientInner::Async(c)
        } else {
            let a = ureq::AgentBuilder::new()
                .timeout_read(self.timeout)
                .timeout_write(self.timeout)
                .build();
            ClientInner::Blocking(a)
        };
        Ok(AtomClient {
            inner,
            base_url: self.base_url,
            auth_token: self.auth_token,
            user_agent: self.user_agent,
        })
    }
}

/// Convenience alias for the blocking client (same as [`AtomClient`] built with
/// `async_mode(false)`). Exists so callers can name the variant explicitly.
pub type BlockingAtomClient = AtomClient;