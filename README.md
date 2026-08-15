# HashiCorp Vault Secret Provider — `dev.mcpg.secret.vault`

> class `secret_provider` · `native` · package `mcpg-plugin-secret-vault` · artifact `libmcpg_plugin_secret_vault.so` · BUSL-1.1

Resolves `vault://<backend_path>#<field>` references against a HashiCorp Vault
server, so a gateway config names a secret instead of carrying it. Every config
string that *is* such a reference is replaced with the live secret at config
load; afterwards the plugin keeps watching for KV v2 rotations and renewing
dynamic-secret leases. Reach for it when Vault already holds the credentials
your backends, credential issuers and sinks need, and the config file should
stay free of secret material.

## What it does
- Binds the `vault://` URI scheme. Once the entry registers, any config string
  whose entire value is a `vault://` reference resolves through it; strings
  carrying other schemes pass through untouched.
- Reads KV v2 secrets and unwraps Vault's double `data` envelope, selecting the
  `#field` anchor or falling back to `default_field`. The KV v2
  `metadata.version` becomes the resolved value's version.
- Reads non-KV engines (database credentials, PKI, AWS STS) through the same
  path. Only scalar leaves are returned — a field holding an array or object is
  rejected as an invalid reference rather than stringified.
- Authenticates with a static token, AppRole, userpass, or a Kubernetes
  ServiceAccount token, and re-authenticates when Vault rejects the cached one.
- Registers each renewable lease Vault attaches to a dynamic-secret read and
  renews it at half its TTL through `PUT /v1/sys/leases/renew`. A failed renewal
  ends that lease's renewal task, and shutdown aborts every pending one.
- Watches a reference for rotation and emits a `SecretRotation` event on change,
  either by polling KV v2 version metadata or over Vault's native event stream.
- Declares the `network_outbound` capability: every read, login, renewal and
  watch dials Vault's HTTP API.

## Configuration
Loaded from the flat top-level `plugins:` list. There is no separate binding
block — the `vault://` scheme goes live as soon as the entry registers, because
the gateway binds a secret provider's declared schemes automatically.

```yaml
plugins:
  - id: dev.mcpg.secret.vault
    class: secret_provider
    source: { path: ./plugins/libmcpg_plugin_secret_vault.so }
    granted_capabilities: [network_outbound]
    config:
      url: https://vault.example:8200
      auth:
        method: approle
        role_id: ${env.VAULT_ROLE_ID}
        secret_id: ${env.VAULT_SECRET_ID}
      default_field: value
      # namespace: team-a                    # Vault Enterprise
      # tls: { ca_cert: /etc/ssl/vault-ca.pem, verify_peer: true }
      watch:
        strategy: poll
        poll_interval_ms: 30000
      connection:
        connect_timeout_ms: 5000
        operation_timeout_ms: 10000

# …and anywhere else in the config a secret is needed:
mcp:
  capabilities:
    tools:
      - name: billing.charge
        description: Charge a customer.
        backend:
          kind: http
          url: https://billing.internal/charge
          headers:
            authorization: vault://secret/data/billing#token
```

To pull the published artifact instead of building it, write
`source: { oci: ghcr.io/mcpg-dev/source-code/plugins/secret-vault:protocol-1 }`.
The reference is platform-agnostic; the gateway resolves the variant for its own
OS, architecture and libc.

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | — (required) | Vault endpoint; must start with `http://` or `https://`. |
| `auth` | object | — (required) | Auth method plus credentials, tagged by `method` (see below). |
| `namespace` | string | unset | Sent as `X-Vault-Namespace` on every request and on the watch upgrade (Vault Enterprise). |
| `kv_mount` | string | `secret` | Validated as non-empty; the plugin does not prepend it to reference paths. |
| `default_field` | string | `value` | Field selected when a reference carries no `#field` anchor. |
| `tls.ca_cert` | string | unset | Extra CA bundle added to the system roots; consulted only for `https://`. |
| `tls.verify_peer` | bool | `true` | Set `false` only for a self-signed development Vault. |
| `watch.strategy` | `poll` \| `native` | `poll` | Rotation-detection mode. |
| `watch.poll_interval_ms` | u64 | `30000` | Poll cadence; values below `1000` are rejected. |
| `connection.connect_timeout_ms` | u64 | `5000` | Connect budget; must be greater than zero. |
| `connection.operation_timeout_ms` | u64 | `10000` | Per-request budget; must be greater than zero. |

Auth methods, keyed by `auth.method`:

| `method` | Fields |
|---|---|
| `token` | `token` — a static Vault token. |
| `approle` | `role_id`, `secret_id`, `mount` (default `approle`). |
| `userpass` | `username`, `password`, `mount` (default `userpass`). |
| `kubernetes` | `role`, `token_path` (default `/var/run/secrets/kubernetes.io/serviceaccount/token`), `mount` (default `kubernetes`). |

Unknown fields are rejected. A config that fails to parse or validate refuses to
register rather than starting in a degraded state.

## Operations
A reference is `vault://<backend_path>[#<field>]`. `<backend_path>` is the full
path under Vault's `/v1/` API root, **including** the mount segment — the plugin
does not prepend `kv_mount`:

```text
vault://secret/data/db#password   → GET /v1/secret/data/db, field `password`
vault://kv/data/db                → GET /v1/kv/data/db, field from `default_field`
vault://database/creds/readonly   → GET /v1/database/creds/readonly
```

A leading `/` in the path, a missing path, or a non-`vault` scheme is an invalid
reference. A trailing `#` with nothing after it is treated as no anchor.

Responses carrying a non-empty `lease_id` and a non-zero `lease_duration` — the
dynamic engines — are handed to the lease tracker. A lease Vault marks
`renewable: false` is left to expire; a renewable one gets a renewal task, which
ends on the first failed renewal and leaves the next read to mint a fresh lease.
KV v2 reads carry no lease and skip that path.

Vault status codes map to stable errors: `404` becomes not-found, `401` and
`403` become permission-denied, and transport failures or any other status
become a backend error naming the operation.

## Change-watching
`watch.strategy: poll` re-reads the reference on every tick and emits a rotation
event when KV v2 `metadata.version` advances. The first successful poll only
establishes a baseline, so no event is emitted for it. A failed poll logs a
warning and retries on the next tick; only an explicit cancellation ends the
loop.

`watch.strategy: native` subscribes to `sys/events/subscribe` over WebSocket
(Vault 1.13 and newer) and filters `kv-v2/data-write` events by data path,
re-reading the secret when one matches — the event payload carries metadata
only. The connection is re-established with backoff from one second to a
thirty-second cap; a `401`/`403` invalidates the cached token first so the new
connection re-authenticates. Deployments on older Vault stay on `poll`.

## Security
- Credentials inside the entry's `config:` should themselves come from the
  environment (`${env.VAULT_ROLE_ID}`) or another bound secret scheme rather
  than being written inline.
- `tls.verify_peer: false` disables certificate validation for the whole client.
  It exists for self-signed development servers and has no production use.
- Prefer AppRole or Kubernetes ServiceAccount auth over a static `token` in
  production: both are re-issued by Vault, so a leaked config artefact ages out.
- The Vault role backing Kubernetes auth must be configured to trust the
  gateway's ServiceAccount; the plugin reads the projected token from
  `token_path` on every login.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; a binary that links several plugins together turns
it off so they do not all export `mcpg_plugin_register`:

```bash
cargo build -p mcpg-plugin-secret-vault --features cdylib-export --release   # → target/release/libmcpg_plugin_secret_vault.so
```

## Testing
```bash
cargo test -p mcpg-plugin-secret-vault --lib
cargo test -p mcpg-plugin-secret-vault --features integration-tests
```

The `integration-tests` feature turns on a suite that boots a dev-mode Vault
container per test and exercises reads, auth methods, lease renewal and the
watch paths end to end. It needs a working Docker daemon; without the feature
the crate's tests stay offline.

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, the ABI, and how entries load:
  <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema, including `plugins[]`:
  <https://mcpg.dev/docs/reference/configuration>
- Per-caller dynamic database credentials, issued at request time rather than
  resolved at config load: `libs/plugins/credential/vault-dynamic-db`
