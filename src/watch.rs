//! Poll-mode watch task.
//!
//! Streaming-FFI: the host hands the plugin an `emit_event`
//! callback when starting a watch. The plugin spawns a background
//! task that polls Vault on a configured interval, compares the
//! KV v2 `metadata.version` returned by each pass, and on a version
//! bump JSON-encodes a `SecretRotationWire` and pushes it through
//! `emit_event`.
//!
//! Lifetime model:
//!
//! - `start_watch` returns a `Box<WatchState>::into_raw()`-leaked
//!   pointer wrapped in [`WatchHandleBox`]. The host opaque-stores
//!   this pointer and hands it back via `cancel_watch`.
//! - `cancel_watch` reclaims the pointer through `Box::from_raw`
//!   and drops it; the [`WatchState::drop`] impl aborts the task.
//! - On plugin shutdown the bundled tokio runtime drops, aborting
//!   every remaining task. This is the safety net for any handle
//!   the host failed to cancel explicitly.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::secret::{SecretError, SecretRotationWire, SecretValueWire};
use mcpg_plugin_sdk::ffi::WatchHandleBox;
use tokio::task::AbortHandle;

use crate::client::VaultClient;
use crate::config::WatchStrategy;
use crate::watch_native::native_loop;

/// Per-active-watch state; dropped when the host calls
/// `cancel_watch` or the plugin's runtime tears down.
pub(crate) struct WatchState {
    abort: AbortHandle,
}

impl Drop for WatchState {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// Spawn the watch task on `runtime`, return the leaked
/// `WatchState` pointer cast to a [`WatchHandleBox`]. The task
/// closes over the `emit_event` callback the host provided.
///
/// Dispatch on `strategy`:
/// - [`WatchStrategy::Poll`] → [`poll_loop`] (re-reads on a timer)
/// - [`WatchStrategy::Native`] →
///   [`native_loop`](crate::watch_native::native_loop) (subscribes
///   to `sys/events/subscribe` over WebSocket)
pub(crate) fn start_watch(
    runtime: &tokio::runtime::Runtime,
    client: Arc<VaultClient>,
    backend_path: String,
    field: String,
    strategy: WatchStrategy,
    poll_interval: Duration,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
) -> Result<WatchHandleBox, SecretError> {
    let join = match strategy {
        WatchStrategy::Poll => runtime.spawn(async move {
            poll_loop(client, backend_path, field, poll_interval, emit_event).await
        }),
        WatchStrategy::Native => {
            runtime.spawn(async move { native_loop(client, backend_path, field, emit_event).await })
        }
    };
    let state = Box::new(WatchState {
        abort: join.abort_handle(),
    });
    let raw: *mut WatchState = Box::into_raw(state);
    Ok(WatchHandleBox(raw as *mut ()))
}

/// Reclaim the leaked `WatchState` and drop it, which fires
/// [`WatchState::drop`] → aborts the task. Safe iff `handle` was
/// produced by [`start_watch`] and hasn't been dropped already —
/// the host's vtable contract guarantees both.
pub(crate) unsafe fn drop_watch(handle: WatchHandleBox) {
    if handle.0.is_null() {
        return;
    }
    let raw = handle.0 as *mut WatchState;
    // SAFETY: per-fn doc, raw was Box::into_raw'd by start_watch and
    // hasn't been reclaimed before. Boxing it back drops the state
    // (which aborts the task) and frees the heap allocation.
    unsafe {
        let _ = Box::from_raw(raw);
    }
}

/// The actual poll loop. Reads the secret on every tick, compares
/// the metadata.version field against the last seen value, emits
/// a `SecretRotationWire` on a version bump.
///
/// Errors during poll (Vault temporarily down, transient network
/// blip) are logged at warn but do NOT terminate the watch — the
/// next tick retries. This matches the operator expectation that a
/// watch is durable and survives Vault hiccups; only an explicit
/// `cancel_watch` ends the loop.
async fn poll_loop(
    client: Arc<VaultClient>,
    backend_path: String,
    field: String,
    poll_interval: Duration,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
) {
    let mut last_version: Option<String> = None;
    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let raw = match client.get_raw(&backend_path, "watch_poll").await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    backend_path = %backend_path,
                    error = %err,
                    "vault watch: poll failed; retrying next tick"
                );
                continue;
            }
        };

        let version = raw
            .get("metadata")
            .and_then(|m| m.get("version"))
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string());

        // First successful poll establishes the baseline. We do NOT
        // emit on initial read — the operator already has the value
        // via `get`; emitting here would surface a spurious
        // "rotation" event that didn't actually correspond to a
        // backend rotation.
        if last_version.is_none() {
            last_version = version;
            continue;
        }
        if last_version == version {
            continue;
        }

        // Version bumped — fetch the new value's chosen field and
        // emit. The double-data unwrap matches the trait `get`
        // path; non-KV-v2 paths fall through.
        let body = if let Some(inner) = raw.get("data").and_then(|v| v.as_object()) {
            if raw.get("metadata").is_some() {
                serde_json::Value::Object(inner.clone())
            } else {
                raw.clone()
            }
        } else {
            raw.clone()
        };
        let new_field = match body.get(&field) {
            Some(serde_json::Value::String(s)) => s.as_bytes().to_vec(),
            Some(serde_json::Value::Number(n)) => n.to_string().into_bytes(),
            Some(serde_json::Value::Bool(b)) => b.to_string().into_bytes(),
            Some(serde_json::Value::Null) => Vec::new(),
            _ => {
                tracing::warn!(
                    backend_path = %backend_path,
                    field = %field,
                    "vault watch: rotated value's field missing or structured; \
                     skipping rotation event"
                );
                last_version = version;
                continue;
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
                "kv-v2 version bump: {} → {}",
                last_version.as_deref().unwrap_or("?"),
                version.as_deref().unwrap_or("?")
            ),
        };
        match serde_json::to_string(&payload) {
            Ok(json) => emit_event(&json),
            Err(err) => {
                tracing::error!(
                    backend_path = %backend_path,
                    error = %err,
                    "vault watch: failed to serialise rotation event"
                );
            }
        }
        last_version = version;
    }
}
