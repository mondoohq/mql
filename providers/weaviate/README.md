# Weaviate Provider

The `weaviate` provider connects to a Weaviate vector database server and inventories it through read-only requests to the REST API. It exposes the server version and enabled modules, collections and their data-governance settings, role-based access control roles and their permissions, users, and cluster nodes, so you can audit the server's security posture without touching the vector data.

Weaviate has no published CIS benchmark; the resources here target the security-relevant configuration surface: anonymous access, authentication and OIDC, RBAC least-privilege, multi-tenancy isolation, and replication.

## Authentication

The provider authenticates with a Weaviate API key (sent as a bearer token) and connects over `--scheme` `http` or `https`.

Arguments:

- `--host` - the server hostname or IP address (also accepted as the positional argument).
- `--port` - the REST API port (default `8080`).
- `--scheme` - `http` (default) or `https`.
- `--api-key` - the API key to authenticate with, or `--ask-api-key` to be prompted.
- `--tls-ca` - path to a CA certificate to verify an `https` server with a private CA.
- `--tls-insecure` - skip TLS certificate verification (testing only).

```shell
mql shell weaviate localhost --api-key API_KEY
```

> Prefer a least-privileged API key for auditing. A key mapped to the built-in `viewer` role can read everything the resources below need; a more restricted key still resolves the server metadata, and the roles, users, and node collections it cannot read come back empty rather than failing the scan. When the server allows anonymous access, the API key may be omitted entirely.

## Usage

Open an interactive shell against a server:

```shell
mql shell weaviate --host localhost --api-key API_KEY
```

The host may also be given as the positional argument, and a verified-TLS connection adds the scheme and CA flags:

```shell
mql shell weaviate my-instance.example.com --scheme https --api-key API_KEY --tls-ca ca.pem
```

## Discovery

By default the provider discovers each collection on the server as its own `weaviate-collection` asset, alongside the server asset. The `--discover` targets control which child assets are emitted:

- `auto` (default) - also emit one asset per collection. Same as `all`.
- `all` - also emit one asset per collection.
- `collections` - also emit one asset per collection.
- `instance` - the server asset only.
- `none` - the server only, without per-collection assets.

```shell
# Scan the server and every collection
cnspec scan weaviate localhost --api-key API_KEY

# Scan the server only
cnspec scan weaviate localhost --api-key API_KEY --discover none
```

## Examples

**Server version and hardening settings**

Read the instance metadata and the security-relevant access-control settings at once.

```shell
mql> weaviate.instance { version rbacEnabled anonymousAccessEnabled oidcEnabled }
weaviate.instance: {
  version: "1.38.9"
  rbacEnabled: true
  anonymousAccessEnabled: false
  oidcEnabled: false
}
```

**Collections with weakened tenant isolation**

Find multi-tenant collections that create tenants automatically, which materializes tenants on first use and weakens isolation.

```shell
mql> weaviate.instance.collections.where(multiTenancyEnabled && autoTenantCreation) { name replicationFactor vectorizer }
weaviate.instance.collections.where: [
  0: {
    name: "Article"
    vectorizer: "none"
    replicationFactor: 1
  }
]
```

**Custom (non-built-in) roles**

List roles that an administrator created, separating them from the predefined `root`, `admin`, `viewer`, and `read-only` roles.

```shell
mql> weaviate.instance.roles.where(isBuiltin == false) { name }
weaviate.instance.roles.where: [
  0: {
    name: "articleReader"
  }
]
```

**Permissions and assignees of a role**

Inspect what a role is allowed and who holds it, for reviewing over-broad access.

```shell
mql> weaviate.instance.roles.where(name == "articleReader").first { permissions { action collection } assignedUsers }
weaviate.instance.roles.where.first: {
  permissions: [
    0: { action: "read_data"        collection: "Article" }
    1: { action: "read_collections" collection: "Article" }
  ]
  assignedUsers: [
    0: "viewer-user"
  ]
}
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell weaviate localhost --api-key API_KEY -c "weaviate.instance { version rbacEnabled }"
```

If `weaviate.instance.roles` comes back empty, either role-based access control is not enabled (`rbacEnabled` is false) or the connecting key cannot read roles; grant it the built-in `viewer` role (or use a more privileged key) and retry.
