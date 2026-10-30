# Elasticsearch Provider

The `elasticsearch` provider connects to an Elasticsearch cluster and inventories it through read-only requests to the REST API. It exposes the cluster version and health, its security posture (whether security is enabled, anonymous access, HTTP and transport TLS, audit logging), and its users, roles, role mappings, and API keys, so you can audit the cluster's security posture without touching the data.

This provider is for Elasticsearch. OpenSearch serves a different security API (`_plugins/_security/*`) and is covered by the separate `opensearch` provider; pointing this provider at an OpenSearch node is detected and refused.

## Authentication

The provider authenticates with basic auth (user and password) or an API key, and connects over `--scheme` `http` or `https`.

Arguments:

- `--host` - the cluster hostname or IP address (also accepted as the positional argument).
- `--port` - the REST API port (default `9200`).
- `--scheme` - `http` or `https` (default `https`; Elasticsearch 8+ enables HTTPS by default).
- `--user` (`-u`) - the user for basic authentication.
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--api-key` - an API key to authenticate with instead of basic auth (base64 of `id:api_key`).
- `--tls-ca` - path to a CA certificate to verify an `https` cluster with a private CA.
- `--tls-insecure` - skip TLS certificate verification (testing only).

```shell
mql shell elasticsearch localhost --user elastic --ask-pass
```

> Prefer a least-privileged account for auditing. A user with the `monitor` cluster privilege plus `read_security` can read everything the resources below need.
>
> In mql 14, a collection the account cannot read comes back empty, and health and `security` come back null, so a check over them can pass on a cluster the scanner could not read. With the `StructuredErrors` feature enabled (the default from mql 15), a 403 errors and names the missing privilege instead: `users`, `roles`, `roleMappings`, and `apiKeys` (`read_security`), and `healthStatus`, `nodeCount`, `dataNodeCount`, and `security` (`monitor`). A 401 is reported as an authentication error.

## Usage

Open an interactive shell against a cluster:

```shell
mql shell elasticsearch --host es.contoso.com --user elastic --ask-pass
```

The host may also be given as the positional argument, and a verified-TLS connection adds the CA flag:

```shell
mql shell elasticsearch es.contoso.com --scheme https --user auditor --ask-pass --tls-ca ca.pem
```

## Examples

**Cluster version and health**

Read the cluster metadata and health at once.

```shell
mql> elasticsearch.cluster { name version distribution healthStatus nodeCount }
elasticsearch.cluster: {
  name: "docker-cluster"
  version: "8.15.3"
  distribution: "elasticsearch"
  healthStatus: "green"
  nodeCount: 1
}
```

**Security posture**

Check whether security is enabled and how the cluster is exposed.

```shell
mql> elasticsearch.cluster.security { enabled anonymousAccessEnabled httpTlsEnabled transportTlsEnabled auditLoggingEnabled }
elasticsearch.cluster.security: {
  enabled: true
  anonymousAccessEnabled: false
  httpTlsEnabled: false
  transportTlsEnabled: false
  auditLoggingEnabled: false
}
```

**Superuser-equivalent roles**

Find roles that grant the `all` cluster privilege, for reviewing over-broad access.

```shell
mql> elasticsearch.cluster.roles.where(clusterPrivileges.contains("all")) { name isReserved }
elasticsearch.cluster.roles.where: [
  0: {
    name: "superuser"
    isReserved: true
  }
]
```

**API keys that never expire**

A key created without an expiration never expires, a posture concern.

```shell
mql> elasticsearch.cluster.apiKeys.where(neverExpires) { name username }
elasticsearch.cluster.apiKeys.where: [
  0: {
    name: "forever-key"
    username: "elastic"
  }
]
```

**Per-index privileges of a role**

Inspect the index patterns and privileges a role grants, and whether field- or document-level security narrows them.

```shell
mql> elasticsearch.cluster.roles.where(name == "reader").first.indexPrivileges { names privileges hasFieldSecurity hasDocumentSecurity }
elasticsearch.cluster.roles.where.first.indexPrivileges: [
  0: {
    names: ["logs-*"]
    privileges: ["read"]
    hasFieldSecurity: false
    hasDocumentSecurity: false
  }
]
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell elasticsearch localhost --user elastic --ask-pass -c "elasticsearch.cluster { version healthStatus }"
```

If `elasticsearch.cluster.users` comes back empty, or errors with a forbidden error, the connecting account lacks the `read_security` privilege; grant it (or use a more privileged auditing account) and retry.
