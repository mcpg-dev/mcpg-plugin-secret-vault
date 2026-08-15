//! `dev.mcpg.secret.vault` — HashiCorp Vault `secret_provider` plugin.
//!
//! This crate is the implementation; the operator-facing
//! summary lives in `README.md`.
//!
//! # Layout
//!
//! - [`config`] — operator-supplied YAML/JSON shape + parsing.
//! - [`error`] — config errors + the Vault → [`SecretError`] mapping.
//! - [`uri`] — `vault://<path>#<field>` URI parser.
//! - [`client`] — reqwest-based Vault HTTP client.
//! - The crate root wires the [`SyncSecretProvider`] impl + the
//!   [`declare_plugin!`](mcpg_plugin_sdk::declare_plugin)
//!   invocation.
//!
//! # v0.2 scope (current)
//!
//! v0.2 closes the production-readiness gaps left
//! over from v0.1:
//!
//! - **Auth methods** — token, AppRole, userpass, Kubernetes SA.
//! - **KV v2 read** — `#field` anchor + `default_field`.
//! - **Watch strategies** — `poll` (any Vault) and `native`
//!   (Vault 1.13+ `sys/events/subscribe` over WebSocket).
//! - **Dynamic-secret lease refresh** — per-lease background task
//!   renews PKI / DB creds / AWS STS tokens at ~50% of their TTL.
//!
//! Still deferred:
//! AWS IAM + GCP service-account auth, Vault Sentinel / namespace
//! traversal, optional secret-cache between rotation events.

mod client;
mod config;
mod error;
mod lease;
mod uri;
mod watch;
mod watch_native;

use std::collections::BTreeMap;
use std::sync::Arc;

use mcpg_plugin_protocol::secret::{SecretError, SecretValueWire};
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::{SyncSecretProvider, WatchHandleBox};
use tokio::runtime::Runtime;

pub use config::{
    AuthConfig, ConnectionConfig, TlsConfig, VaultSecretConfig, WatchConfig, WatchStrategy,
};
pub use error::ConfigError;

const PLUGIN_ID: &str = "dev.mcpg.secret.vault";
const SCHEME: &str = "vault";

/// The Vault secret provider. Cheap to clone; heavy state lives
/// behind `Arc`.
pub struct VaultSecretProvider {
    inner: Arc<VaultSecretInner>,
}

struct VaultSecretInner {
    manifest: PluginManifest,
    config: VaultSecretConfig,
    client: Arc<client::VaultClient>,
    /// Tracks every active dynamic-secret lease so the
    /// background renewal task can keep them alive past
    /// Vault's default `lease_duration`. KV v2 reads return no
    /// lease and don't populate this map.
    leases: Arc<lease::LeaseTracker>,
    /// Bundled tokio runtime. The trait is sync; reqwest needs an
    /// executor. 2 worker threads + the lease tracker tasks
    /// share this; renewal cadence is well under one task per
    /// 30 seconds for typical deploys, so 2 workers absorb it.
    runtime: Runtime,
}

impl VaultSecretProvider {
    /// Factory used by `declare_plugin!`. Panics on bad config —
    /// the macro's `catch_panic_to_null_handle`
    /// translates that into a host-visible "plugin failed to
    /// register" error referencing `plugin_id`. Same stance as
    /// the OIDC + cache.redis plugins.
    pub fn from_config_json(config_json: &str) -> Self {
        let config = VaultSecretConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "vault secret: config parse failed; refusing to register"
            );
            panic!("vault secret config parse failed: {err}")
        });

        let client = client::VaultClient::from_config(&config).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                url = %config.url,
                "vault secret: client init failed; refusing to register"
            );
            panic!("vault secret client init failed: {err}")
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcpg-secret-vault")
            .enable_all()
            .build()
            .unwrap_or_else(|err| {
                tracing::error!(
                    plugin_id = PLUGIN_ID,
                    error = %err,
                    "vault secret: tokio runtime init failed; refusing to register"
                );
                panic!("vault secret tokio runtime init failed: {err}")
            });

        let leases = Arc::new(lease::LeaseTracker::new());

        Self {
            inner: Arc::new(VaultSecretInner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "HashiCorp Vault Secret Provider".into(),
                    plugin_class: PluginClass::SecretProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: vec![SCHEME.into()],
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config,
                client,
                leases,
                runtime,
            }),
        }
    }
}

impl SyncSecretProvider for VaultSecretProvider {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn supported_schemes(&self) -> Vec<String> {
        vec![SCHEME.into()]
    }

    /// Resolve a `vault://<path>#<field>` reference. The request
    /// maps to `GET /v1/{path}` (the URI's path is the
    /// full backend path including the mount segment); the
    /// response's `data` envelope is unwrapped and the configured
    /// field anchor (or `default_field` when the URI omits one) is
    /// extracted.
    ///
    /// KV v2 returns `{ "data": { "data": {...}, "metadata": {...} } }`
    /// — a double `data` wrap. We detect KV v2 by the presence of
    /// a nested `data` object and unwrap it; non-KV-v2 paths
    /// (dynamic creds, PKI) skip the nested unwrap.
    fn get(&self, secret_ref: &str) -> Result<SecretValueWire, SecretError> {
        let parsed = uri::VaultRef::parse(secret_ref)?;
        let field = parsed.field.unwrap_or(&self.inner.config.default_field);
        let client = Arc::clone(&self.inner.client);
        let path = parsed.backend_path.to_owned();
        let field = field.to_owned();

        let envelope = self
            .inner
            .runtime
            .block_on(async move { client.get_envelope(&path, "get").await })?;

        // Register dynamic-secret leases for auto-renewal. KV v2
        // reads return `lease == None`; non-KV reads (PKI,
        // database, AWS STS, etc.) populate the lease metadata
        // and the tracker spawns a renewal task per lease_id.
        if let Some(lease_info) = envelope.lease.clone() {
            self.inner.leases.register(
                self.inner.runtime.handle(),
                Arc::clone(&self.inner.client),
                lease_info,
                50, // renew at half-TTL — the conservative default
                    // for `refresh_before_expiry_percent`.
            );
        }

        let raw = envelope.data;

        // KV v2 wraps `data` again. Detect by checking whether the
        // response's `data` field is itself an object containing a
        // `data` member. Non-KV-v2 engines return their values
        // directly under `data`.
        let body = if let Some(inner) = raw.get("data").and_then(|v| v.as_object()) {
            // Heuristic: KV v2 sets `metadata.version`. If we see a
            // `metadata` sibling alongside the `data` member, it's KV v2.
            if raw.get("metadata").is_some() {
                serde_json::Value::Object(inner.clone())
            } else {
                raw.clone()
            }
        } else {
            raw.clone()
        };

        let value = body
            .get(&field)
            .ok_or_else(|| SecretError::InvalidReference {
                message: format!("vault: response for `{secret_ref}` has no field `{field}`"),
            })?;

        // Field values can be string, number, bool, null. Reject
        // structured types (object/array) — operators reaching for a
        // structured secret should issue a separate `vault://` per
        // leaf field.
        let bytes = match value {
            serde_json::Value::String(s) => s.as_bytes().to_vec(),
            serde_json::Value::Number(n) => n.to_string().into_bytes(),
            serde_json::Value::Bool(b) => b.to_string().into_bytes(),
            serde_json::Value::Null => Vec::new(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                return Err(SecretError::InvalidReference {
                    message: format!(
                        "vault: field `{field}` for `{secret_ref}` is structured \
                         (array/object); request a leaf field instead"
                    ),
                });
            }
        };

        // KV v2 metadata.version → SecretValueWire.version when present.
        let version = raw
            .get("metadata")
            .and_then(|m| m.get("version"))
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string());

        Ok(SecretValueWire {
            bytes,
            version,
            expires_at: None,
            metadata: BTreeMap::new(),
        })
    }

    /// Start a poll-mode rotation watch on `secret_ref`. The plugin
    /// spawns a tokio task that re-reads the secret every
    /// `watch.poll_interval_ms`; on a
    /// KV v2 `metadata.version` bump it emits a `SecretRotationWire`
    /// JSON through `emit_event`.
    ///
    /// The returned [`WatchHandleBox`] is a leaked `Box<WatchState>`
    /// pointer; the host returns it via `cancel_watch` to abort the
    /// task. Plugin shutdown also aborts every task via the bundled
    /// runtime's drop, so a host that loses a handle still doesn't
    /// leak the poll loop past plugin teardown.
    ///
    /// v0.1 limitation: native `sys/events/subscribe` is not
    /// implemented. The config validator rejects
    /// `watch.strategy: native` at registration time so this method
    /// is reached only on the poll path.
    fn watch(
        &self,
        secret_ref: &str,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, SecretError> {
        let parsed = uri::VaultRef::parse(secret_ref)?;
        let field = parsed
            .field
            .unwrap_or(&self.inner.config.default_field)
            .to_owned();
        let backend_path = parsed.backend_path.to_owned();
        let poll_interval =
            std::time::Duration::from_millis(self.inner.config.watch.poll_interval_ms);

        watch::start_watch(
            &self.inner.runtime,
            Arc::clone(&self.inner.client),
            backend_path,
            field,
            self.inner.config.watch.strategy,
            poll_interval,
            emit_event,
        )
    }

    fn cancel_watch(&self, watch_handle: WatchHandleBox) {
        // SAFETY: contract — the host only hands us back handles
        // produced by our own `watch` impl, exactly once. The
        // `drop_watch` helper reclaims the leaked Box and the
        // resulting drop fires the WatchState::drop which aborts
        // the spawned task.
        unsafe { watch::drop_watch(watch_handle) }
    }

    fn shutdown(&self) {
        // Abort every pending lease-renewal task. The bundled
        // tokio runtime drops with the plugin handle which is the
        // safety net, but a graceful shutdown gets a clean
        // teardown via this explicit abort first.
        self.inner.leases.shutdown_all();
        tracing::info!(plugin_id = PLUGIN_ID, "vault secret: shutdown signalled");
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        secret_provider as vault {
            inner_name: "",
            plugin_type: VaultSecretProvider,
            factory: |cfg, _host: ::mcpg_plugin_sdk::HostHandle| VaultSecretProvider::from_config_json(cfg),
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap_plugin() -> VaultSecretProvider {
        VaultSecretProvider::from_config_json(
            r#"{"url": "https://vault.invalid:8200", "auth": {"method": "token", "token": "test"}}"#,
        )
    }

    #[test]
    fn factory_parses_minimal_config() {
        let _plugin = cheap_plugin();
    }

    #[test]
    #[should_panic(expected = "vault secret config parse failed")]
    fn factory_panics_on_unparseable_config() {
        let _ = VaultSecretProvider::from_config_json("not-json");
    }

    #[test]
    fn manifest_carries_required_capability() {
        // Capabilities live on
        // PluginRegistration.capabilities (typed). Manifest is
        // display-only.
        let plugin = cheap_plugin();
        let manifest = plugin.manifest();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.plugin_class, PluginClass::SecretProvider);
    }

    #[test]
    fn supported_schemes_is_just_vault() {
        let plugin = cheap_plugin();
        let schemes = plugin.supported_schemes();
        assert_eq!(schemes, vec!["vault".to_string()]);
    }

    #[test]
    fn descriptor_yaml_is_well_formed() {
        assert!(DESCRIPTOR_YAML.contains(&format!("id: {PLUGIN_ID}")));
        assert!(DESCRIPTOR_YAML.contains("class: secret_provider"));
        assert!(DESCRIPTOR_YAML.contains("runtime: native-cdylib-v1"));
        assert!(DESCRIPTOR_YAML.contains("network_outbound"));
    }

    /// `vault.invalid` is RFC-6761 reserved — DNS MUST refuse to
    /// resolve it. The connect attempt fails fast (well within the
    /// 10s op timeout), and we verify the trait method surfaces a
    /// `Backend` error rather than panicking.
    #[test]
    fn get_surfaces_backend_error_when_vault_unreachable() {
        let plugin = VaultSecretProvider::from_config_json(
            r#"{
              "url": "https://vault.invalid:8200",
              "auth": {"method": "token", "token": "test"},
              "connection": {"connect_timeout_ms": 500, "operation_timeout_ms": 1000}
            }"#,
        );
        let err = plugin
            .get("vault://secret/data/foo#password")
            .expect_err("must fail when vault is unreachable");
        assert!(
            matches!(err, SecretError::Backend { .. }),
            "expected Backend, got {err:?}"
        );
    }

    #[test]
    fn get_rejects_non_vault_scheme() {
        let plugin = cheap_plugin();
        let err = plugin
            .get("https://vault.example/secret/data/foo")
            .expect_err("non-vault scheme must be rejected");
        assert!(
            matches!(err, SecretError::InvalidReference { .. }),
            "expected InvalidReference, got {err:?}"
        );
    }

    #[test]
    fn watch_returns_handle_then_cancel_drops_state() {
        // Without a real Vault the poll task will fail every tick
        // and just log warnings — that's exactly the "errors don't
        // terminate the watch" behaviour we want to verify here.
        // We assert the lifecycle handshake: `watch` hands back a
        // non-null pointer, `cancel_watch` accepts it without
        // panicking, and the plugin remains usable afterwards.
        let plugin = cheap_plugin();
        let handle = plugin
            .watch(
                "vault://secret/data/foo#password",
                Box::new(|_| { /* discard events; we're testing handshake */ }),
            )
            .expect("watch must hand back a handle");
        assert!(!handle.0.is_null(), "handle must be non-null");
        plugin.cancel_watch(handle);
        // Plugin still functional — issue another get and confirm
        // it surfaces the expected backend error (not a panic).
        let err = plugin
            .get("vault://secret/data/foo")
            .expect_err("get after cancel must still reach the trait method");
        assert!(matches!(err, SecretError::Backend { .. }));
    }

    #[test]
    fn watch_rejects_invalid_uri() {
        // `WatchHandleBox` is a transparent `*mut ()` and doesn't
        // derive `Debug`; use a manual match instead of `expect_err`
        // so we don't need the Debug bound.
        let plugin = cheap_plugin();
        let result = plugin.watch("https://not-vault/x", Box::new(|_| {}));
        match result {
            Ok(handle) => {
                plugin.cancel_watch(handle);
                panic!("non-vault URI must be rejected");
            }
            Err(SecretError::InvalidReference { .. }) => {}
            Err(other) => panic!("expected InvalidReference, got {other:?}"),
        }
    }
}
