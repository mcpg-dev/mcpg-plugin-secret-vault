//! Native-mode watch via `sys/events/subscribe` (Vault 1.13+).
//!
//! Vault 1.13 added a server-sent events stream on
//! `/v1/sys/events/subscribe/<event_type>` that publishes write /
//! delete / patch events for KV v2 secrets in real time. This
//! module opens that stream as a WebSocket, filters events by
//! `data_path`, re-reads the secret on a match, and emits the
//! standard `SecretRotationWire` that the gateway already
//! understands from the poll path.
//!
//! ## Why re-read?
//!
//! The event payload carries metadata only (mount, path, version,
//! operation). It does NOT include the new value, so the rotation
//! event must trigger an authenticated `GET /v1/{path}` to fetch
//! the rotated field. This is the same shape the poll loop uses
//! and reuses `VaultClient::get_raw` directly.
//!
//! ## Reconnect strategy
//!
//! `sys/events/subscribe` is a long-lived WebSocket; Vault restarts,
//! network blips, and token expiry all close it. The loop:
//!
//! 1. Auths (if needed) → opens the WS.
//! 2. Reads frames forever.
//! 3. On any error / clean close: backs off 1s → 2s → … → 30s
//!    (capped) and reconnects.
//! 4. On 401/403 specifically: invalidates the cached token before
//!    reconnecting so the new connection re-auths.
//!
//! Plugin shutdown drops the runtime which aborts the spawned task.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use mcpg_plugin_protocol::secret::{SecretRotationWire, SecretValueWire};

use crate::client::VaultClient;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Subscribe to `kv-v2/data-write` events specifically. Other KV v2
/// event types (`data-delete`, `data-destroy`, `data-undelete`,
/// `data-patch`) don't represent rotations the gateway can act on:
/// a delete means the secret is gone, a destroy is permanent, a
/// patch updates partial fields without bumping `metadata.version`
/// in a way the watch model can encode.
const EVENT_TYPE: &str = "kv-v2/data-write";

pub(crate) async fn native_loop(
    client: Arc<VaultClient>,
    backend_path: String,
    field: String,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
) {
    let mut last_version: Option<String> = None;
    let mut backoff = INITIAL_BACKOFF;

    loop {
        let outcome = run_once(
            client.as_ref(),
            &backend_path,
            &field,
            &mut last_version,
            emit_event.as_ref(),
        )
        .await;

        match outcome {
            RunOutcome::ServerClosed => {
                tracing::info!(
                    backend_path = %backend_path,
                    "vault watch (native): stream closed; reconnecting"
                );
                backoff = INITIAL_BACKOFF;
                tokio::time::sleep(INITIAL_BACKOFF).await;
            }
            RunOutcome::AuthFailure(err) => {
                tracing::warn!(
                    backend_path = %backend_path,
                    error = %err,
                    "vault watch (native): auth failure; invalidating token + reconnecting"
                );
                client.invalidate_token_for_watch().await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            RunOutcome::TransportFailure(err) => {
                tracing::warn!(
                    backend_path = %backend_path,
                    error = %err,
                    backoff_ms = backoff.as_millis() as u64,
                    "vault watch (native): connection error; backing off"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

enum RunOutcome {
    ServerClosed,
    AuthFailure(String),
    TransportFailure(String),
}

async fn run_once(
    client: &VaultClient,
    backend_path: &str,
    field: &str,
    last_version: &mut Option<String>,
    emit_event: &(dyn Fn(&str) + Send + Sync),
) -> RunOutcome {
    let token = match client.ensure_token_for_watch("watch_native_login").await {
        Ok(t) => t,
        Err(err) => return RunOutcome::AuthFailure(err.to_string()),
    };

    let url = client.events_subscribe_url(EVENT_TYPE);
    let mut req = match url.as_str().into_client_request() {
        Ok(r) => r,
        Err(err) => {
            return RunOutcome::TransportFailure(format!("invalid ws url `{url}`: {err}"));
        }
    };
    let token_header = match HeaderValue::from_str(&token) {
        Ok(v) => v,
        Err(_) => {
            return RunOutcome::TransportFailure(
                "vault token contains characters invalid for an HTTP header".into(),
            );
        }
    };
    req.headers_mut().insert("X-Vault-Token", token_header);
    if let Some(ns) = client.namespace_header() {
        match HeaderValue::from_str(ns) {
            Ok(v) => {
                req.headers_mut().insert("X-Vault-Namespace", v);
            }
            Err(_) => {
                return RunOutcome::TransportFailure(
                    "vault namespace contains characters invalid for an HTTP header".into(),
                );
            }
        }
    }

    let (mut ws, response) = match connect_async(req).await {
        Ok(pair) => pair,
        Err(err) => {
            // tungstenite surfaces 401/403 as Http(StatusCode::...).
            let s = err.to_string();
            if s.contains("401") || s.contains("403") {
                return RunOutcome::AuthFailure(s);
            }
            return RunOutcome::TransportFailure(s);
        }
    };
    tracing::info!(
        backend_path = %backend_path,
        status = ?response.status(),
        "vault watch (native): connected to sys/events/subscribe"
    );

    while let Some(msg) = ws.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(err) => {
                return RunOutcome::TransportFailure(format!("ws frame: {err}"));
            }
        };
        match msg {
            Message::Text(text) => {
                handle_event(client, backend_path, field, last_version, &text, emit_event).await;
            }
            Message::Close(frame) => {
                tracing::debug!(
                    backend_path = %backend_path,
                    code = ?frame.as_ref().map(|f| f.code),
                    "vault watch (native): server close frame received"
                );
                return RunOutcome::ServerClosed;
            }
            // Vault always sends JSON text frames. Ping/Pong are
            // handled by tokio-tungstenite automatically; binary
            // and Frame are unused. Ignore.
            Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    RunOutcome::ServerClosed
}

async fn handle_event(
    client: &VaultClient,
    backend_path: &str,
    field: &str,
    last_version: &mut Option<String>,
    raw: &str,
    emit_event: &(dyn Fn(&str) + Send + Sync),
) {
    let event: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "vault watch (native): malformed event JSON");
            return;
        }
    };

    if !event_matches(&event, backend_path) {
        return;
    }

    // Re-read the secret to get the new value. Native events
    // carry only metadata; the rotated field comes from a fresh
    // KV v2 read against the same path.
    let raw_response = match client.get_raw(backend_path, "watch_native").await {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                backend_path = %backend_path,
                error = %err,
                "vault watch (native): failed to re-read after event"
            );
            return;
        }
    };

    let version = raw_response
        .get("metadata")
        .and_then(|m| m.get("version"))
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string());

    // Skip if version didn't actually move forward. Possible if
    // the event is a duplicate, or our re-read raced ahead of
    // the actual write commit.
    if last_version.as_ref() == version.as_ref() {
        return;
    }

    let new_field = match extract_field_bytes(&raw_response, field) {
        ExtractResult::Bytes(b) => b,
        ExtractResult::Skip => {
            *last_version = version;
            return;
        }
    };

    let payload = SecretRotationWire {
        new_value: SecretValueWire {
            bytes: new_field,
            version: version.clone(),
            expires_at: None,
            metadata: Default::default(),
        },
        reason: format!(
            "kv-v2 native event: version {} → {}",
            last_version.as_deref().unwrap_or("?"),
            version.as_deref().unwrap_or("?")
        ),
    };
    match serde_json::to_string(&payload) {
        Ok(json) => emit_event(&json),
        Err(err) => {
            tracing::error!(error = %err, "vault watch (native): serialise rotation event")
        }
    }
    *last_version = version;
}

/// Vault event shape (CloudEvents-derived):
/// ```json
/// { "data": { "event": { "metadata": { "data_path": "secret/data/foo", ... } },
///             "event_type": "kv-v2/data-write", ... } }
/// ```
/// Filter: `data.event.metadata.data_path == backend_path`. Pure
/// function so the test below can exercise it without a live Vault.
fn event_matches(event: &serde_json::Value, backend_path: &str) -> bool {
    event
        .pointer("/data/event/metadata/data_path")
        .and_then(|v| v.as_str())
        == Some(backend_path)
}

enum ExtractResult {
    Bytes(Vec<u8>),
    Skip,
}

fn extract_field_bytes(raw: &serde_json::Value, field: &str) -> ExtractResult {
    let body = if let Some(inner) = raw.get("data").and_then(|v| v.as_object()) {
        if raw.get("metadata").is_some() {
            serde_json::Value::Object(inner.clone())
        } else {
            raw.clone()
        }
    } else {
        raw.clone()
    };
    match body.get(field) {
        Some(serde_json::Value::String(s)) => ExtractResult::Bytes(s.as_bytes().to_vec()),
        Some(serde_json::Value::Number(n)) => ExtractResult::Bytes(n.to_string().into_bytes()),
        Some(serde_json::Value::Bool(b)) => ExtractResult::Bytes(b.to_string().into_bytes()),
        Some(serde_json::Value::Null) => ExtractResult::Bytes(Vec::new()),
        _ => {
            tracing::warn!(
                field = %field,
                "vault watch (native): rotated value's field missing or structured"
            );
            ExtractResult::Skip
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_for(path: &str) -> serde_json::Value {
        serde_json::json!({
            "data": {
                "event": {
                    "id": "abc",
                    "metadata": {
                        "current_version": "2",
                        "data_path": path,
                        "modified": "true",
                        "operation": "data-write",
                        "path": path,
                    }
                },
                "event_type": "kv-v2/data-write",
                "plugin_info": { "mount_path": "secret" }
            }
        })
    }

    #[test]
    fn event_matches_when_data_path_equals_backend_path() {
        let ev = event_for("secret/data/foo");
        assert!(event_matches(&ev, "secret/data/foo"));
    }

    #[test]
    fn event_does_not_match_unrelated_path() {
        let ev = event_for("secret/data/other");
        assert!(!event_matches(&ev, "secret/data/foo"));
    }

    #[test]
    fn event_without_metadata_does_not_match() {
        let ev = serde_json::json!({"data": {"event": {}}});
        assert!(!event_matches(&ev, "secret/data/foo"));
    }

    #[test]
    fn event_without_data_does_not_match() {
        let ev = serde_json::json!({"unrelated": "shape"});
        assert!(!event_matches(&ev, "secret/data/foo"));
    }

    #[test]
    fn extract_field_kv_v2_envelope() {
        let raw = serde_json::json!({
            "data": {"password": "hunter2"},
            "metadata": {"version": 3}
        });
        let bytes = match extract_field_bytes(&raw, "password") {
            ExtractResult::Bytes(b) => b,
            ExtractResult::Skip => panic!("expected bytes"),
        };
        assert_eq!(bytes, b"hunter2");
    }

    #[test]
    fn extract_field_non_kv_v2_envelope() {
        // Dynamic-secret response: data is flat, no metadata.
        let raw = serde_json::json!({"username": "v-root", "password": "p"});
        let bytes = match extract_field_bytes(&raw, "password") {
            ExtractResult::Bytes(b) => b,
            ExtractResult::Skip => panic!("expected bytes"),
        };
        assert_eq!(bytes, b"p");
    }

    #[test]
    fn extract_field_skips_structured_value() {
        let raw = serde_json::json!({
            "data": {"creds": {"user": "u"}},
            "metadata": {"version": 1}
        });
        match extract_field_bytes(&raw, "creds") {
            ExtractResult::Skip => {}
            ExtractResult::Bytes(_) => panic!("expected skip for structured value"),
        }
    }

    #[test]
    fn extract_field_handles_missing_field() {
        let raw = serde_json::json!({"data": {"x": "1"}, "metadata": {"version": 1}});
        match extract_field_bytes(&raw, "missing") {
            ExtractResult::Skip => {}
            ExtractResult::Bytes(_) => panic!("expected skip when field absent"),
        }
    }

    #[test]
    fn extract_field_handles_numeric_value() {
        let raw = serde_json::json!({"data": {"port": 5432}, "metadata": {"version": 1}});
        let bytes = match extract_field_bytes(&raw, "port") {
            ExtractResult::Bytes(b) => b,
            ExtractResult::Skip => panic!("expected bytes"),
        };
        assert_eq!(bytes, b"5432");
    }

    #[test]
    fn extract_field_handles_bool_value() {
        let raw = serde_json::json!({"data": {"enabled": true}, "metadata": {"version": 1}});
        let bytes = match extract_field_bytes(&raw, "enabled") {
            ExtractResult::Bytes(b) => b,
            ExtractResult::Skip => panic!("expected bytes"),
        };
        assert_eq!(bytes, b"true");
    }
}
