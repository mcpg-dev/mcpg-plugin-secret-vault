//! Config errors are local; runtime Vault errors translate to
//! [`SecretError`].

use mcpg_plugin_protocol::secret::SecretError;
use thiserror::Error;

/// Failures while parsing the operator-supplied config blob.
/// Surface verbatim in the host startup log; never reaches the
/// trait's `SecretError` (a config failure prevents the plugin
/// from registering at all).
#[derive(Debug, Clone, Error)]
pub enum ConfigError {
    #[error("vault secret config: failed to parse JSON: {0}")]
    ParseError(String),

    #[error("vault secret config: invalid: {0}")]
    Invalid(String),
}

/// Translate a `reqwest`-level error into the wire-stable
/// [`SecretError`]. `op` names the
/// trait method invoked — we surface it in the `reason` so log
/// readers can pivot without needing the metric label.
///
/// HTTP-status mapping happens at a higher layer (the request
/// helper inspects the response and calls
/// [`status_to_secret_error`] for non-2xx). This function only
/// handles the transport-level failure modes (DNS, TLS, refused,
/// timeout).
pub(crate) fn reqwest_to_secret_error(op: &'static str, err: reqwest::Error) -> SecretError {
    let reason = format!("vault {op}: {err}");
    SecretError::Backend { reason }
}

/// Map an HTTP status from a Vault response to the matching
/// `SecretError` variant. Vault uses 404 / 403 as the operative
/// signals; everything else falls under `Backend`.
pub(crate) fn status_to_secret_error(
    op: &'static str,
    status: reqwest::StatusCode,
    body: &str,
) -> SecretError {
    match status.as_u16() {
        404 => SecretError::NotFound,
        // 403 covers a missing token or an ACL denying the path.
        // The token-expired-and-reauth-failed case lands here too
        // because reauth happens transparently on the way in;
        // a 403 reaching the trait method means no recovery is
        // possible from the plugin's side.
        401 | 403 => SecretError::PermissionDenied,
        _ => SecretError::Backend {
            reason: format!(
                "vault {op}: HTTP {status}{}",
                if body.is_empty() {
                    String::new()
                } else {
                    format!(": {}", body.lines().next().unwrap_or("").trim())
                }
            ),
        },
    }
}
