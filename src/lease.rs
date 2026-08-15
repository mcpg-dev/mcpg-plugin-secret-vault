//! Dynamic-secret lease tracker.
//!
//! Vault responses for dynamic engines (database, PKI, AWS STS,
//! GCP, etc.) carry a `lease_id`, `renewable: true`, and
//! `lease_duration` in seconds. The credentials Vault hands back
//! are valid only for that window; the operator (or the gateway)
//! has to issue `PUT /v1/sys/leases/renew` before expiry to keep
//! them alive. Vault enforces a `max_ttl` per role — once that's
//! reached the lease becomes non-renewable and Vault rejects
//! further renews.
//!
//! Without this tracker, every dynamic-secret read returns fresh
//! credentials (Vault issues a brand-new lease) and the previous
//! lease silently expires. That's not a correctness problem on
//! its own — but operators who cache the credentials in memory
//! between gets get bitten when the lease expires before the
//! cache TTL.
//!
//! Tracker model:
//!
//! - On `get(secret_ref)` against a dynamic engine, the trait
//!   impl calls `LeaseTracker::register` with the lease_id +
//!   duration + renewable flag.
//! - The tracker spawns a per-lease task that wakes at
//!   `lease_duration × renew_before_expiry_percent / 100`,
//!   issues `PUT /v1/sys/leases/renew`, updates the local
//!   record on success, and re-sleeps. On non-renewable leases
//!   or permanent renewal failures the task ends; the lease
//!   record is removed from the tracker.
//! - `LeaseTracker::shutdown_all` aborts every pending task
//!   on plugin teardown. The bundled tokio runtime's drop is
//!   the safety net — even an explicit shutdown miss can't
//!   leak tasks past plugin handle drop.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::task::AbortHandle;

use crate::client::{VaultClient, VaultLeaseInfo};

/// Per-lease state held inside the tracker. The abort handle lets
/// the tracker stop the renewal task from outside; the renewed
/// duration lives inside the task itself, not here.
struct LeaseEntry {
    abort: AbortHandle,
}

/// Tracker shared across the plugin via `Arc<LeaseTracker>`. The
/// `BTreeMap` is keyed on `lease_id` — operator-supplied
/// `secret_ref`s aren't unique (multiple gets against the same
/// dynamic-creds path produce different lease_ids).
pub(crate) struct LeaseTracker {
    leases: Mutex<BTreeMap<String, LeaseEntry>>,
}

impl LeaseTracker {
    pub(crate) fn new() -> Self {
        Self {
            leases: Mutex::new(BTreeMap::new()),
        }
    }

    /// Register a lease for auto-renewal. Idempotent on
    /// already-tracked lease_ids — replaces the entry + aborts
    /// the previous task. (Vault never re-issues a lease_id, so
    /// this is defensive only.)
    pub(crate) fn register(
        self: &Arc<Self>,
        runtime: &Handle,
        client: Arc<VaultClient>,
        lease: VaultLeaseInfo,
        renew_before_expiry_percent: u32,
    ) {
        // Non-renewable leases are tracked as a no-op — they'll
        // expire naturally; nothing for us to do.
        if !lease.renewable {
            tracing::debug!(
                lease_id = %lease.lease_id,
                lease_duration = lease.lease_duration_secs,
                "vault lease tracker: skipping non-renewable lease"
            );
            return;
        }

        let tracker_for_task = Arc::clone(self);
        let lease_id_for_task = lease.lease_id.clone();
        let lease_duration = lease.lease_duration_secs;
        let join = runtime.spawn(async move {
            renewal_loop(
                tracker_for_task,
                client,
                lease_id_for_task,
                lease_duration,
                renew_before_expiry_percent,
            )
            .await;
        });

        let entry = LeaseEntry {
            abort: join.abort_handle(),
        };
        let mut guard = self.leases.lock().expect("lease tracker lock poisoned");
        // Replace any stale entry for this lease_id; abort the
        // outgoing task so we don't double-renew.
        if let Some(prev) = guard.insert(lease.lease_id.clone(), entry) {
            prev.abort.abort();
        }
    }

    /// Remove a lease from the tracker without aborting (the
    /// task itself signals removal when it ends).
    fn drop_entry(&self, lease_id: &str) {
        if let Ok(mut guard) = self.leases.lock() {
            guard.remove(lease_id);
        }
    }

    /// Stop every pending renewal task. Called on plugin
    /// `shutdown` so a graceful teardown doesn't leak tasks past
    /// the shutdown signal. Plugin runtime drop is the safety
    /// net for non-graceful shutdowns.
    pub(crate) fn shutdown_all(&self) {
        if let Ok(mut guard) = self.leases.lock() {
            for entry in guard.values() {
                entry.abort.abort();
            }
            guard.clear();
        }
    }
}

/// Per-lease background task. Sleeps, renews, repeats. Errors
/// end the task; the tracker removes the entry on exit.
async fn renewal_loop(
    tracker: Arc<LeaseTracker>,
    client: Arc<VaultClient>,
    lease_id: String,
    initial_duration_secs: u64,
    renew_before_expiry_percent: u32,
) {
    let pct = renew_before_expiry_percent.clamp(1, 99);
    let mut duration_secs = initial_duration_secs;

    loop {
        // sleep = duration × (100 - pct) / 100
        let sleep_secs = duration_secs.saturating_mul(100 - pct as u64) / 100;
        let sleep_for = Duration::from_secs(sleep_secs.max(1));
        tokio::time::sleep(sleep_for).await;

        match client.renew_lease(&lease_id, None).await {
            Ok(new_duration) => {
                tracing::debug!(
                    lease_id = %lease_id,
                    new_duration_secs = new_duration,
                    "vault lease tracker: renewed lease"
                );
                duration_secs = new_duration;
            }
            Err(err) => {
                // Renewal failed permanently or transiently.
                // Vault returns a 400 with "lease cannot be
                // renewed" once max_ttl is hit; we don't pivot
                // on the wire shape here — any error ends the
                // task. The next operator-driven `get` will
                // mint a fresh lease.
                tracing::warn!(
                    lease_id = %lease_id,
                    error = %err,
                    "vault lease tracker: renewal failed; ending renewal task"
                );
                break;
            }
        }
    }

    tracker.drop_entry(&lease_id);
}
