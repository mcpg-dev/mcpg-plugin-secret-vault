//! `vault://<path>#<field>` URI parser.
//!
//! Grammar:
//!
//! ```text
//! vault://<backend_path>            # default_field anchor implied
//! vault://<backend_path>#<field>    # explicit field
//! ```
//!
//! `<backend_path>` is the Vault API suffix the plugin will resolve
//! against the configured KV mount. For KV v2 the resolution is:
//!
//! ```text
//! GET /v1/{kv_mount}/data/{path_after_mount}
//! ```
//!
//! Operators MUST include the mount segment in the URI — the plugin
//! does not assume it. So `vault://secret/data/foo#password` resolves
//! against the default `secret/` mount; `vault://kv/data/foo#password`
//! resolves against a custom-mounted `kv/`.

use mcpg_plugin_protocol::secret::SecretError;

/// Parsed `vault://` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultRef<'a> {
    /// Path under the Vault HTTP API root (`/v1/...`). For a KV v2
    /// secret this looks like `secret/data/foo`; for dynamic creds
    /// `database/creds/readonly`. Already URL-decoded by the time
    /// we hand it to reqwest.
    pub(crate) backend_path: &'a str,
    /// Field anchor from the URI fragment, or `None` if absent.
    /// When `None`, the resolver substitutes `config.default_field`.
    pub(crate) field: Option<&'a str>,
}

impl<'a> VaultRef<'a> {
    /// Parse a `vault://...` reference. Returns
    /// `SecretError::InvalidReference` on a wrong scheme, missing
    /// path, or other shape problem; the gateway surfaces this as
    /// the operator-visible `invalid_reference` metric label.
    pub(crate) fn parse(secret_ref: &'a str) -> Result<Self, SecretError> {
        let trimmed = secret_ref.trim();
        let after_scheme =
            trimmed
                .strip_prefix("vault://")
                .ok_or_else(|| SecretError::InvalidReference {
                    message: format!("expected vault:// scheme, got `{}`", short(secret_ref, 40)),
                })?;

        if after_scheme.is_empty() {
            return Err(SecretError::InvalidReference {
                message: "vault:// reference has no path".into(),
            });
        }

        // Split on the first `#` for the optional field anchor.
        let (backend_path, field) = match after_scheme.split_once('#') {
            Some((p, f)) if !f.is_empty() => (p, Some(f)),
            Some((p, _)) => (p, None),
            None => (after_scheme, None),
        };

        if backend_path.is_empty() {
            return Err(SecretError::InvalidReference {
                message: "vault:// reference has empty path before the `#` anchor".into(),
            });
        }

        // Reject obviously malformed paths early — leading `/` would
        // confuse the URL builder, and embedded `//` is almost always
        // a config bug rather than a deliberate Vault path.
        if backend_path.starts_with('/') {
            return Err(SecretError::InvalidReference {
                message: format!("vault:// path must not start with `/`: `{backend_path}`"),
            });
        }

        Ok(Self {
            backend_path,
            field,
        })
    }
}

fn short(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.into()
    } else {
        format!("{}…", &s[..max.min(s.len())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kv_v2_path_with_field() {
        let r = VaultRef::parse("vault://secret/data/db#password").unwrap();
        assert_eq!(r.backend_path, "secret/data/db");
        assert_eq!(r.field, Some("password"));
    }

    #[test]
    fn parses_path_without_field() {
        let r = VaultRef::parse("vault://secret/data/api-key").unwrap();
        assert_eq!(r.backend_path, "secret/data/api-key");
        assert_eq!(r.field, None);
    }

    #[test]
    fn parses_empty_field_as_none() {
        // Trailing `#` with no field is treated as no anchor —
        // operators sometimes copy URLs that pick up an empty
        // fragment from a paste tool.
        let r = VaultRef::parse("vault://secret/data/x#").unwrap();
        assert_eq!(r.field, None);
    }

    #[test]
    fn dynamic_secret_path_parses() {
        let r = VaultRef::parse("vault://database/creds/readonly").unwrap();
        assert_eq!(r.backend_path, "database/creds/readonly");
        assert_eq!(r.field, None);
    }

    #[test]
    fn rejects_wrong_scheme() {
        let err = VaultRef::parse("https://vault.example/secret/data/x").unwrap_err();
        assert!(matches!(err, SecretError::InvalidReference { .. }));
    }

    #[test]
    fn rejects_empty_path() {
        let err = VaultRef::parse("vault://").unwrap_err();
        assert!(matches!(err, SecretError::InvalidReference { .. }));
    }

    #[test]
    fn rejects_empty_path_with_field() {
        let err = VaultRef::parse("vault://#field").unwrap_err();
        assert!(matches!(err, SecretError::InvalidReference { .. }));
    }

    #[test]
    fn rejects_leading_slash_in_path() {
        let err = VaultRef::parse("vault:///secret/data/x").unwrap_err();
        assert!(matches!(err, SecretError::InvalidReference { .. }));
    }
}
