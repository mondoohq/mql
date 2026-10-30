# OpenSearch Provider

The `opensearch` provider connects to an OpenSearch cluster and inventories it through read-only requests to the REST API. It exposes the cluster version and health, its security posture (anonymous access, audit logging, enabled authentication realms), and its internal users, roles, and role mappings from the OpenSearch security plugin, so you can audit the cluster's security posture without touching the data.

This provider is for OpenSearch. Elasticsearch serves a different security API (`_security/*`) and is covered by the separate `elasticsearch` provider; pointing this provider at an Elasticsearch node is detected and refused.

## Authentication

The provider authenticates with basic auth (user and password) and connects over `--scheme` `http` or `https`. OpenSearch's security plugin serves HTTPS with a self-signed demo certificate by default, so `--tls-insecure` is typically needed for a default local install.

Arguments:

- `--host` - the cluster hostname or IP address (also accepted as the positional argument).
- `--port` - the REST API port (default `9200`).
- `--scheme` - `http` or `https` (default `https`).
- `--user` (`-u`) - the user for basic authentication.
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--tls-ca` - path to a CA certificate to verify the cluster.
- `--tls-insecure` - skip TLS certificate verification (for the default self-signed demo certificate).

```shell
mql shell opensearch localhost --user admin --ask-pass --tls-insecure
```

> Prefer a least-privileged account for auditing. A user mapped to a role with the `cluster_monitor` permission and read access to the security API (for example through `security_rest_api_access`) can read everything the resources below need.
>
> In mql 14, with only monitor-level access the cluster resolves while the security posture comes back null and users, roles, and role mappings come back empty, so a check over them can pass on a cluster the scanner could not read. With the `StructuredErrors` feature enabled (the default from mql 15), a 403 errors and names the missing permission instead: `security`, `users`, `roles`, and `roleMappings` (`security_rest_api_access`), and `healthStatus`, `nodeCount`, and `dataNodeCount` (`cluster_monitor`). A 401 is reported as an authentication error.

## Usage

Open an interactive shell against a cluster:

```shell
mql shell opensearch --host os.contoso.com --user admin --ask-pass
```

The host may also be given as the positional argument, and a verified-TLS connection adds the CA flag:

```shell
mql shell opensearch os.contoso.com --user auditor --ask-pass --tls-ca ca.pem
```

## Examples

**Cluster version and health**

Read the cluster metadata and health at once.

```shell
mql> opensearch.cluster { name version distribution healthStatus nodeCount }
opensearch.cluster: {
  name: "docker-cluster"
  version: "2.17.1"
  distribution: "opensearch"
  healthStatus: "yellow"
  nodeCount: 1
}
```

**Security posture**

Check anonymous access, audit logging, and the enabled authentication realms.

```shell
mql> opensearch.cluster.security { anonymousAccessEnabled auditLoggingEnabled doNotFailOnForbidden enabledAuthRealms }
opensearch.cluster.security: {
  anonymousAccessEnabled: false
  auditLoggingEnabled: true
  doNotFailOnForbidden: false
  enabledAuthRealms: ["basic_internal_auth_domain"]
}
```

**Roles granting full cluster access**

Find roles that grant the `*` cluster permission, for reviewing over-broad access.

```shell
mql> opensearch.cluster.roles.where(clusterPermissions.contains("*")) { name isReserved }
opensearch.cluster.roles.where: [
  0: {
    name: "all_access"
    isReserved: true
  }
]
```

**Per-index permissions of a role**

Inspect the index patterns and actions a role grants, and whether field-level security or field masking narrows them.

```shell
mql> opensearch.cluster.roles.where(name == "readers").first.indexPermissions { indexPatterns allowedActions hasFieldLevelSecurity hasFieldMasking }
opensearch.cluster.roles.where.first.indexPermissions: [
  0: {
    indexPatterns: ["logs-*"]
    allowedActions: ["read"]
    hasFieldLevelSecurity: false
    hasFieldMasking: false
  }
]
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell opensearch localhost --user admin --ask-pass --tls-insecure -c "opensearch.cluster { version healthStatus }"
```

If `opensearch.cluster.users` comes back empty, or errors with a forbidden error, the connecting account cannot read the security API; map it to a role with security-read access (or use a more privileged auditing account) and retry.

## Notes

- OpenSearch masks user password hashes in the security API, so the provider does not report whether a user has a password set.
- `opensearch.security.auditLoggingEnabled` reads the `enabled` flag of the audit configuration. The audit sink (`plugins.security.audit.type` in `opensearch.yml`) is not exposed over the API, so a cluster with the flag on and no sink configured reports `true` while writing no audit events. Check the node configuration for the sink.
