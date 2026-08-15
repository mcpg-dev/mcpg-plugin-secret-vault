//! Operator-supplied configuration for the Vault secret provider.
//!
//! v0.2 covers token / AppRole /
//! userpass / Kubernetes SA auth, KV v2 reads, poll + native
//! (`sys/events/subscribe`) watch strategies, and dynamic-secret
//! lease refresh. Deferred: AWS IAM and GCP service-account auth.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Root config struct. Only `url` and `auth` have no defaults —
/// every other field falls back to a conservative sane value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSecretConfig {
    /// Vault HTTP(S) endpoint, e.g. `https://vault.example:8200`.
    /// Required — there's no sane default.
    pub url: String,

    /// Vault Enterprise namespace. Sent as the `X-Vault-Namespace`
    /// header on every request. Omit (or leave empty) for OSS Vault
    /// or the root namespace.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Authentication method + credentials.
    pub auth: AuthConfig,

    /// KV v2 mount path. Vault's default is `secret/`. Operators
    /// with a custom-mounted KV v2 (`vault secrets enable -path=…`)
    /// override here.
    #[serde(default = "default_kv_mount")]
    pub kv_mount: String,

    /// Field name used when a `vault://...` URI omits the `#field`
    /// anchor. Vault has no notion of a canonical field; this is
    /// the gateway's convention; the default is `value`.
    #[serde(default = "default_field")]
    pub default_field: String,

    /// TLS knobs. Only consulted when `url` uses `https://`.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Watch-strategy selector. Both `poll` (default, works on any
    /// Vault) and `native` (Vault 1.13+ `sys/events/subscribe` over
    /// WebSocket — drops rotation latency from `poll_interval_ms`
    /// to ~20ms) ship in v0.2.
    #[serde(default)]
    pub watch: WatchConfig,

    /// Connection / per-op timeouts. Same shape as the cache.redis
    /// plugin so operator muscle memory carries across.
    #[serde(default)]
    pub connection: ConnectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Static token auth. Fastest to wire up; common for dev +
    /// small static deploys. Production deploys should prefer
    /// AppRole or one of the platform-IAM methods.
    Token { token: String },
    /// AppRole with role_id + secret_id. The plugin issues
    /// `POST /v1/auth/approle/login` at startup and on token
    /// expiry.
    Approle {
        role_id: String,
        secret_id: String,
        /// Optional non-default mount path for the AppRole auth
        /// method (matches `vault auth enable -path=…`). Defaults
        /// to `approle`.
        #[serde(default = "default_approle_mount")]
        mount: String,
    },
    /// Username + password against Vault's userpass auth method.
    /// Common in lab + small teams; production should prefer
    /// AppRole or platform-IAM.
    Userpass {
        username: String,
        password: String,
        #[serde(default = "default_userpass_mount")]
        mount: String,
    },
    /// Kubernetes ServiceAccount auth. Reads the JWT from the
    /// projected service-account token file (default
    /// `/var/run/secrets/kubernetes.io/serviceaccount/token`),
    /// POSTs to `/v1/auth/kubernetes/login` with the configured
    /// role. The Vault role MUST be configured to trust the
    /// gateway's service account.
    Kubernetes {
        /// Vault role name configured via
        /// `vault write auth/kubernetes/role/<name> ...`.
        role: String,
        /// Filesystem path to the projected SA token. Operators
        /// override only when their pod spec uses a non-default
        /// mount path.
        #[serde(default = "default_k8s_token_path")]
        token_path: String,
        #[serde(default = "default_k8s_mount")]
        mount: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to a CA-cert bundle the plugin trusts in addition to
    /// the system roots. Optional — omit to use system trust only.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Disable to permit a self-signed Vault (dev only).
    #[serde(default = "default_verify_peer")]
    pub verify_peer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    /// Watch strategy selector. v0.1 ships only `poll`; `native`
    /// will land in v0.2 alongside the sys/events/subscribe
    /// WebSocket bridge.
    #[serde(default = "default_watch_strategy")]
    pub strategy: WatchStrategy,
    /// Poll interval in milliseconds. Floor 1000ms enforced at
    /// validate-time so a misconfig doesn't DoS Vault.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            strategy: default_watch_strategy(),
            poll_interval_ms: default_poll_interval_ms(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchStrategy {
    /// Polls the secret on `watch.poll_interval_ms`; works on any
    /// Vault version. Default.
    Poll,
    /// Subscribes to Vault's `sys/events/subscribe` WebSocket
    /// (Vault 1.13+), filters events by `data_path`, re-reads on
    /// match. Sub-second rotation latency at the cost of a held
    /// WebSocket connection.
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            operation_timeout_ms: default_operation_timeout_ms(),
        }
    }
}

fn default_kv_mount() -> String {
    "secret".into()
}
fn default_field() -> String {
    "value".into()
}
fn default_approle_mount() -> String {
    "approle".into()
}
fn default_userpass_mount() -> String {
    "userpass".into()
}
fn default_k8s_mount() -> String {
    "kubernetes".into()
}
fn default_k8s_token_path() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
}
fn default_verify_peer() -> bool {
    true
}
fn default_watch_strategy() -> WatchStrategy {
    WatchStrategy::Poll
}
fn default_poll_interval_ms() -> u64 {
    30_000
}
fn default_connect_timeout_ms() -> u64 {
    5_000
}
fn default_operation_timeout_ms() -> u64 {
    10_000
}

impl VaultSecretConfig {
    pub fn parse(config_json: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(config_json)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.url.trim().is_empty() {
            return Err(ConfigError::Invalid("`url` must not be empty".into()));
        }
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return Err(ConfigError::Invalid(format!(
                "`url` must use scheme http:// or https:// — got `{}`",
                self.url
            )));
        }
        if self.kv_mount.trim().is_empty() {
            return Err(ConfigError::Invalid("`kv_mount` must not be empty".into()));
        }
        if self.default_field.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "`default_field` must not be empty".into(),
            ));
        }
        if self.watch.poll_interval_ms < 1_000 {
            return Err(ConfigError::Invalid(
                "`watch.poll_interval_ms` must be >= 1000 (don't DoS Vault)".into(),
            ));
        }
        // v0.2 unlocks the native sys/events/subscribe (Vault 1.13+)
        // WebSocket watch path. Both strategies are valid now;
        // operators on Vault < 1.13 stay on `poll`.
        if self.connection.connect_timeout_ms == 0 || self.connection.operation_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "`connection.*_timeout_ms` must be > 0".into(),
            ));
        }
        match &self.auth {
            AuthConfig::Token { token } => {
                if token.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "auth.token must not be empty when method = token".into(),
                    ));
                }
            }
            AuthConfig::Approle {
                role_id,
                secret_id,
                mount,
            } => {
                if role_id.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "auth.role_id must not be empty when method = approle".into(),
                    ));
                }
                if secret_id.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "auth.secret_id must not be empty when method = approle".into(),
                    ));
                }
                if mount.trim().is_empty() {
                    return Err(ConfigError::Invalid("auth.mount must not be empty".into()));
                }
            }
            AuthConfig::Userpass {
                username,
                password,
                mount,
            } => {
                if username.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "auth.username must not be empty when method = userpass".into(),
                    ));
                }
                if password.is_empty() {
                    // Don't trim — Vault accepts whitespace
                    // passwords. Empty IS rejected.
                    return Err(ConfigError::Invalid(
                        "auth.password must not be empty when method = userpass".into(),
                    ));
                }
                if mount.trim().is_empty() {
                    return Err(ConfigError::Invalid("auth.mount must not be empty".into()));
                }
            }
            AuthConfig::Kubernetes {
                role,
                token_path,
                mount,
            } => {
                if role.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "auth.role must not be empty when method = kubernetes".into(),
                    ));
                }
                if token_path.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "auth.token_path must not be empty (default is the projected SA token path)".into(),
                    ));
                }
                if mount.trim().is_empty() {
                    return Err(ConfigError::Invalid("auth.mount must not be empty".into()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approle_blob() -> &'static str {
        r#"{
            "url": "https://vault.example:8200",
            "auth": {"method": "approle", "role_id": "r", "secret_id": "s"}
        }"#
    }

    fn token_blob() -> &'static str {
        r#"{
            "url": "http://localhost:8200",
            "auth": {"method": "token", "token": "test"}
        }"#
    }

    #[test]
    fn approle_minimal_parses() {
        let cfg = VaultSecretConfig::parse(approle_blob()).unwrap();
        assert_eq!(cfg.url, "https://vault.example:8200");
        assert_eq!(cfg.kv_mount, "secret");
        assert_eq!(cfg.default_field, "value");
        match cfg.auth {
            AuthConfig::Approle { mount, .. } => assert_eq!(mount, "approle"),
            _ => panic!("expected approle"),
        }
    }

    #[test]
    fn token_minimal_parses() {
        let cfg = VaultSecretConfig::parse(token_blob()).unwrap();
        match cfg.auth {
            AuthConfig::Token { token } => assert_eq!(token, "test"),
            _ => panic!("expected token"),
        }
    }

    #[test]
    fn http_url_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "ftp://x", "auth": {"method": "token", "token": "t"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }

    #[test]
    fn empty_token_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "token", "token": ""}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("token"));
    }

    #[test]
    fn approle_missing_secret_id_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "approle", "role_id": "r", "secret_id": ""}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("secret_id"));
    }

    #[test]
    fn unknown_field_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "token", "token": "t"}, "bogus": 1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn poll_interval_floor_enforced() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "token", "token": "t"}, "watch": {"strategy": "poll", "poll_interval_ms": 100}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("poll_interval_ms"));
    }

    #[test]
    fn native_watch_strategy_now_accepted_in_v02() {
        let cfg = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "token", "token": "t"}, "watch": {"strategy": "native"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.watch.strategy, WatchStrategy::Native);
    }

    #[test]
    fn custom_kv_mount_overrides_default() {
        let cfg = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "token", "token": "t"}, "kv_mount": "kv"}"#,
        )
        .unwrap();
        assert_eq!(cfg.kv_mount, "kv");
    }

    #[test]
    fn userpass_minimal_parses() {
        let cfg = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "userpass", "username": "alice", "password": "p4ss"}}"#,
        )
        .unwrap();
        match cfg.auth {
            AuthConfig::Userpass {
                username,
                password,
                mount,
            } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "p4ss");
                assert_eq!(mount, "userpass");
            }
            _ => panic!("expected userpass"),
        }
    }

    #[test]
    fn userpass_custom_mount_overrides_default() {
        let cfg = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "userpass", "username": "alice", "password": "p4ss", "mount": "ldap-users"}}"#,
        )
        .unwrap();
        match cfg.auth {
            AuthConfig::Userpass { mount, .. } => assert_eq!(mount, "ldap-users"),
            _ => panic!("expected userpass"),
        }
    }

    #[test]
    fn userpass_empty_username_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "userpass", "username": "", "password": "p"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("username"));
    }

    #[test]
    fn userpass_empty_password_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "userpass", "username": "alice", "password": ""}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("password"));
    }

    #[test]
    fn kubernetes_minimal_parses() {
        let cfg = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "kubernetes", "role": "mcpg-gateway"}}"#,
        )
        .unwrap();
        match cfg.auth {
            AuthConfig::Kubernetes {
                role,
                token_path,
                mount,
            } => {
                assert_eq!(role, "mcpg-gateway");
                assert_eq!(
                    token_path,
                    "/var/run/secrets/kubernetes.io/serviceaccount/token"
                );
                assert_eq!(mount, "kubernetes");
            }
            _ => panic!("expected kubernetes"),
        }
    }

    #[test]
    fn kubernetes_empty_role_rejected() {
        let err = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "kubernetes", "role": ""}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("role"));
    }

    #[test]
    fn kubernetes_custom_token_path_overrides_default() {
        let cfg = VaultSecretConfig::parse(
            r#"{"url": "http://x", "auth": {"method": "kubernetes", "role": "r", "token_path": "/tmp/jwt"}}"#,
        )
        .unwrap();
        match cfg.auth {
            AuthConfig::Kubernetes { token_path, .. } => assert_eq!(token_path, "/tmp/jwt"),
            _ => panic!("expected kubernetes"),
        }
    }
}
