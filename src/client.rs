//! Minimal Vault HTTP client over `reqwest`.
//!
//! v0.1 surface:
//!
//! - AppRole login (`POST /v1/auth/{mount}/login`) → token
//! - Token refresh tracking (renew when close to expiry) — deferred
//!   beyond v0.1; for now we re-login on auth errors
//! - KV v2 read (`GET /v1/{mount}/data/{path}`)
//! - KV v2 raw read for non-KV-v2 paths (dynamic creds, PKI) —
//!   reused with the same response-shape parser
//!
//! The client is async on the inside; the trait method block_on's
//! the operation timeout via `tokio::time::timeout`. Token state is
//! held behind `tokio::sync::RwLock` so the lease-refresh task we
//! add in v0.2 can rotate it without blocking concurrent reads.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client as HttpClient, Method, Response, StatusCode};
use serde::Deserialize;
use tokio::sync::RwLock;

use mcpg_plugin_protocol::secret::SecretError;

use crate::config::{AuthConfig, VaultSecretConfig};
use crate::error::{reqwest_to_secret_error, status_to_secret_error};

/// Cached auth token + the metadata Vault returned on issue. We
/// keep the raw `lease_duration` (seconds) so a v0.2 refresh path
/// can decide when to renew; the v0.1 path just re-auths if a
/// 401/403 ever lands.
#[derive(Debug, Clone)]
struct TokenState {
    token: String,
    /// Vault's `lease_duration` field — informational only in v0.1.
    /// Future lease-refresh path uses it.
    #[allow(dead_code)]
    lease_seconds: u64,
}

pub(crate) struct VaultClient {
    http: HttpClient,
    base_url: String,
    namespace: Option<String>,
    auth: AuthConfig,
    token: RwLock<Option<TokenState>>,
    op_timeout: Duration,
}

impl VaultClient {
    pub(crate) fn from_config(cfg: &VaultSecretConfig) -> Result<Arc<Self>, SecretError> {
        let mut builder = HttpClient::builder()
            .connect_timeout(Duration::from_millis(cfg.connection.connect_timeout_ms))
            .timeout(Duration::from_millis(cfg.connection.operation_timeout_ms))
            .user_agent(format!(
                "mcpg-plugin-secret-vault/{}",
                env!("CARGO_PKG_VERSION")
            ));

        if let Some(tls) = &cfg.tls {
            if let Some(ca_path) = &tls.ca_cert {
                let pem = std::fs::read(ca_path).map_err(|e| SecretError::Backend {
                    reason: format!("vault tls: failed to read ca_cert {ca_path}: {e}"),
                })?;
                let cert =
                    reqwest::Certificate::from_pem(&pem).map_err(|e| SecretError::Backend {
                        reason: format!("vault tls: invalid ca_cert {ca_path}: {e}"),
                    })?;
                builder = builder.add_root_certificate(cert);
            }
            if !tls.verify_peer {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        let http = builder.build().map_err(|e| SecretError::Backend {
            reason: format!("vault http builder: {e}"),
        })?;

        let base_url = cfg.url.trim_end_matches('/').to_owned();

        Ok(Arc::new(Self {
            http,
            base_url,
            namespace: cfg
                .namespace
                .as_ref()
                .filter(|s| !s.trim().is_empty())
                .cloned(),
            auth: cfg.auth.clone(),
            token: RwLock::new(None),
            op_timeout: Duration::from_millis(cfg.connection.operation_timeout_ms),
        }))
    }

    /// Look up `path` against Vault and return the response body's
    /// `data` field. KV v2 wraps in a double `data` envelope:
    /// `{ "data": { "data": {...}, "metadata": {...} } }`. The
    /// caller deals with the unwrap; this helper returns the raw
    /// `data` object so the same path works for KV v2 and non-KV
    /// engines.
    ///
    /// For dynamic-secret engines (database, PKI, AWS STS) the
    /// response also carries lease metadata (`lease_id`,
    /// `renewable`, `lease_duration`). Most callers don't need
    /// it; the trait's `get` path uses [`get_envelope`] which
    /// surfaces the full shape.
    pub(crate) async fn get_raw(
        &self,
        path: &str,
        op: &'static str,
    ) -> Result<serde_json::Value, SecretError> {
        Ok(self.get_envelope(path, op).await?.data)
    }

    /// Variant of [`get_raw`] that surfaces the full Vault
    /// response envelope including optional lease metadata.
    /// Used by the trait's `get` path so it can register
    /// dynamic-secret leases for auto-renewal.
    pub(crate) async fn get_envelope(
        &self,
        path: &str,
        op: &'static str,
    ) -> Result<VaultGetResponse, SecretError> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let resp = self.send_authed(Method::GET, &url, None, op).await?;

        // 404 / 401 / 403 already mapped by send_authed via
        // status_to_secret_error; anything reaching here is 2xx.
        let body = resp
            .json::<VaultEnvelope>()
            .await
            .map_err(|e| SecretError::Backend {
                reason: format!("vault {op}: response decode: {e}"),
            })?;

        let lease = body.lease_info();
        Ok(VaultGetResponse {
            data: body.data,
            lease,
        })
    }

    /// Renew a dynamic-secret lease via
    /// `PUT /v1/sys/leases/renew`. Vault returns the new
    /// `lease_duration` (seconds) on success.
    pub(crate) async fn renew_lease(
        &self,
        lease_id: &str,
        increment_secs: Option<u64>,
    ) -> Result<u64, SecretError> {
        let url = format!("{}/v1/sys/leases/renew", self.base_url);
        let mut body = serde_json::json!({ "lease_id": lease_id });
        if let Some(inc) = increment_secs {
            body["increment"] = serde_json::Value::Number(inc.into());
        }
        let resp = self
            .send_authed(Method::PUT, &url, Some(body), "renew_lease")
            .await?;
        let parsed: VaultEnvelope = resp.json().await.map_err(|e| SecretError::Backend {
            reason: format!("vault renew_lease: response decode: {e}"),
        })?;
        // Vault's renew response carries the new lease_duration
        // in the same shape as the original auth/secret read.
        match parsed.lease_duration {
            Some(d) if d > 0 => Ok(d),
            _ => Err(SecretError::Backend {
                reason: "vault renew_lease: response missing lease_duration".into(),
            }),
        }
    }

    /// Send an HTTP request with the cached token + Vault namespace
    /// header. On 401/403 we re-auth once and retry — the cached
    /// token may have expired between our last successful request
    /// and now. A second 401/403 surfaces as `PermissionDenied`.
    async fn send_authed(
        &self,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
        op: &'static str,
    ) -> Result<Response, SecretError> {
        // First attempt: ensure we have a token, then issue the
        // request. We don't hold the read lock across the await —
        // grab a clone of the token string.
        let token = self.ensure_token(op).await?;
        let resp = self
            .send_once(method.clone(), url, body.clone(), &token, op)
            .await?;
        if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN {
            // Token may have expired. Re-auth + retry exactly once.
            // If the second attempt still yields 401/403 we return
            // PermissionDenied.
            self.invalidate_token().await;
            let token = self.ensure_token(op).await?;
            let resp2 = self.send_once(method, url, body, &token, op).await?;
            self.expect_2xx(resp2, op).await
        } else {
            self.expect_2xx(resp, op).await
        }
    }

    async fn send_once(
        &self,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
        token: &str,
        op: &'static str,
    ) -> Result<Response, SecretError> {
        let mut req = self
            .http
            .request(method, url)
            .header("X-Vault-Token", token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let fut = req.send();
        tokio::time::timeout(self.op_timeout, fut)
            .await
            .map_err(|_| SecretError::Backend {
                reason: format!("vault {op}: operation timeout"),
            })?
            .map_err(|e| reqwest_to_secret_error(op, e))
    }

    async fn expect_2xx(&self, resp: Response, op: &'static str) -> Result<Response, SecretError> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(status_to_secret_error(op, status, &body))
    }

    /// Get a token, logging in if we don't have one. Login uses
    /// the configured auth method.
    async fn ensure_token(&self, op: &'static str) -> Result<String, SecretError> {
        {
            let guard = self.token.read().await;
            if let Some(state) = guard.as_ref() {
                return Ok(state.token.clone());
            }
        }
        // Need to login. Take the write lock once; double-check in
        // case another thread populated while we waited.
        let mut guard = self.token.write().await;
        if let Some(state) = guard.as_ref() {
            return Ok(state.token.clone());
        }
        let state = self.login(op).await?;
        let token = state.token.clone();
        *guard = Some(state);
        Ok(token)
    }

    async fn invalidate_token(&self) {
        let mut guard = self.token.write().await;
        *guard = None;
    }

    /// Public(crate) version of `invalidate_token` for the native
    /// watch path: it drops the cached token after a 401/403 on the
    /// WebSocket upgrade so the next reconnect re-auths.
    pub(crate) async fn invalidate_token_for_watch(&self) {
        self.invalidate_token().await
    }

    /// Public(crate) accessor that wraps `ensure_token`. The native
    /// watch loop needs a token string for the `X-Vault-Token`
    /// upgrade header; everything else (timeout, retry-on-401)
    /// stays inside the client.
    pub(crate) async fn ensure_token_for_watch(
        &self,
        op: &'static str,
    ) -> Result<String, SecretError> {
        self.ensure_token(op).await
    }

    /// Optional namespace header value for the WS upgrade request.
    pub(crate) fn namespace_header(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Build the `wss://` (or `ws://`) URL for
    /// `sys/events/subscribe/<event_type>?json=true`. Operators
    /// running Vault on `https://` automatically get TLS via
    /// `wss://`; the rustls integration we wired into the WS dep
    /// matches reqwest's TLS choice so platform CA roots flow
    /// through.
    pub(crate) fn events_subscribe_url(&self, event_type: &str) -> String {
        let ws_base = if let Some(stripped) = self.base_url.strip_prefix("https://") {
            format!("wss://{stripped}")
        } else if let Some(stripped) = self.base_url.strip_prefix("http://") {
            format!("ws://{stripped}")
        } else {
            // Validation rejects anything that isn't http(s)://, so
            // this branch is unreachable in practice. Falling
            // through to `ws://` is the safest behaviour if it ever
            // does fire — the connect will fail loudly with an
            // unparsed-URL error.
            format!("ws://{}", self.base_url)
        };
        format!("{ws_base}/v1/sys/events/subscribe/{event_type}?json=true")
    }

    async fn login(&self, op: &'static str) -> Result<TokenState, SecretError> {
        match &self.auth {
            AuthConfig::Token { token } => Ok(TokenState {
                token: token.clone(),
                lease_seconds: 0,
            }),
            AuthConfig::Approle {
                role_id,
                secret_id,
                mount,
            } => {
                let body = serde_json::json!({
                    "role_id": role_id,
                    "secret_id": secret_id,
                });
                self.post_login(op, mount, body, "approle_login").await
            }
            AuthConfig::Userpass {
                username,
                password,
                mount,
            } => {
                // Userpass uses username in the URL, password in
                // the body. Mount path is configurable.
                let url = format!("{}/v1/auth/{}/login/{}", self.base_url, mount, username);
                let body = serde_json::json!({ "password": password });
                self.post_login_url(op, &url, body, "userpass_login").await
            }
            AuthConfig::Kubernetes {
                role,
                token_path,
                mount,
            } => {
                // Read the projected SA token from disk every
                // login — operators with token rotation enabled
                // get fresh JWTs without restarting the gateway.
                let jwt =
                    std::fs::read_to_string(token_path).map_err(|e| SecretError::Backend {
                        reason: format!(
                            "vault {op}: kubernetes auth — reading SA token at {token_path}: {e}"
                        ),
                    })?;
                let body = serde_json::json!({
                    "role": role,
                    "jwt": jwt.trim(),
                });
                self.post_login(op, mount, body, "kubernetes_login").await
            }
        }
    }

    /// Shared POST-to-login-endpoint helper. Caller supplies the
    /// auth mount path; the URL is built as
    /// `{base}/v1/auth/{mount}/login`. Userpass needs a different
    /// URL shape (username in path) so it uses [`post_login_url`]
    /// directly.
    async fn post_login(
        &self,
        op: &'static str,
        mount: &str,
        body: serde_json::Value,
        login_kind: &'static str,
    ) -> Result<TokenState, SecretError> {
        let url = format!("{}/v1/auth/{}/login", self.base_url, mount);
        self.post_login_url(op, &url, body, login_kind).await
    }

    async fn post_login_url(
        &self,
        op: &'static str,
        url: &str,
        body: serde_json::Value,
        login_kind: &'static str,
    ) -> Result<TokenState, SecretError> {
        let mut req = self.http.post(url).json(&body);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let fut = req.send();
        let resp = tokio::time::timeout(self.op_timeout, fut)
            .await
            .map_err(|_| SecretError::Backend {
                reason: format!("vault {op}: {login_kind} timeout"),
            })?
            .map_err(|e| reqwest_to_secret_error(op, e))?;
        let resp = self.expect_2xx(resp, login_kind).await?;
        let parsed: ApproleLoginResponse = resp.json().await.map_err(|e| SecretError::Backend {
            reason: format!("vault {op}: {login_kind} decode: {e}"),
        })?;
        Ok(TokenState {
            token: parsed.auth.client_token,
            lease_seconds: parsed.auth.lease_duration,
        })
    }
}

/// Full response envelope from a Vault read, surfaced to callers
/// that need both the data and the optional lease metadata.
/// Dynamic-secret engines (database, PKI, AWS STS) populate
/// `lease`; KV v2 reads return `lease == None`.
#[derive(Debug)]
pub(crate) struct VaultGetResponse {
    pub(crate) data: serde_json::Value,
    pub(crate) lease: Option<VaultLeaseInfo>,
}

/// Lease metadata extracted from a Vault response. The plugin's
/// lease-tracker uses these fields to drive auto-renewal.
#[derive(Debug, Clone)]
pub(crate) struct VaultLeaseInfo {
    pub(crate) lease_id: String,
    pub(crate) renewable: bool,
    pub(crate) lease_duration_secs: u64,
}

#[derive(Debug, Deserialize)]
struct VaultEnvelope {
    /// Vault's standard response carries `data` plus optional
    /// `metadata` / `wrap_info` / `warnings` fields. We only need
    /// `data`; `serde` ignores the rest by default.
    #[serde(default)]
    data: serde_json::Value,
    /// Dynamic-engine responses carry these top-level fields. KV
    /// v2 reads omit them (or set lease_id="", lease_duration=0).
    #[serde(default)]
    lease_id: Option<String>,
    #[serde(default)]
    renewable: Option<bool>,
    #[serde(default)]
    lease_duration: Option<u64>,
}

impl VaultEnvelope {
    /// Extract the lease metadata when present + meaningful.
    /// Treat empty `lease_id` or zero `lease_duration` as "no
    /// lease" — KV v2 responses set both to those defaults.
    fn lease_info(&self) -> Option<VaultLeaseInfo> {
        let lease_id = self.lease_id.as_deref()?.to_owned();
        if lease_id.is_empty() {
            return None;
        }
        let lease_duration_secs = self.lease_duration.unwrap_or(0);
        if lease_duration_secs == 0 {
            return None;
        }
        Some(VaultLeaseInfo {
            lease_id,
            renewable: self.renewable.unwrap_or(false),
            lease_duration_secs,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ApproleLoginResponse {
    auth: ApproleAuth,
}

#[derive(Debug, Deserialize)]
struct ApproleAuth {
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
}
