# Apache Cassandra Provider

The `cassandra` provider connects to an Apache Cassandra cluster over CQL and inventories it through read-only queries against the `system` and `system_auth` keyspaces and the `system_views.settings` virtual table. It exposes the cluster version, its security posture (authentication, authorization, encryption, and audit logging), and its roles, permissions, nodes, and keyspaces, so you can audit the cluster against the CIS Apache Cassandra benchmark without touching the data.

## Authentication

The provider authenticates with a Cassandra role and password (the `PasswordAuthenticator`) and connects over TLS when `--tls` is set.

Arguments:

- `--host` - the cluster hostname or IP address (also accepted as the positional argument).
- `--port` - the CQL native transport port (default `9042`).
- `--user` (`-u`) - the role to authenticate as.
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--tls` - connect over TLS.
- `--tls-ca` - path to a CA certificate to verify the cluster.
- `--tls-insecure` - skip TLS certificate verification (testing only).

```shell
mql shell cassandra localhost --user cassandra --ask-pass
```

> Prefer a least-privileged role for auditing. A role with `SELECT` on the `system`, `system_schema`, `system_auth`, and `system_views` keyspaces can read everything the resources below need. Without the `system_auth`/`system_views` grants, the cluster resolves while the security posture and roles cannot be read. With the `StructuredErrors` feature on they report a permission error naming the missing grant; without it they come back null/empty, as in earlier releases. When the cluster runs the default `AllowAllAuthenticator`, no credentials are required and the roles table is empty; `cassandra.cluster.security.authenticationEnabled` reports this.

## Usage

Open an interactive shell against a cluster:

```shell
mql shell cassandra --host db.contoso.com --user cassandra --ask-pass
```

The host may also be given as the positional argument, and a TLS connection adds the TLS flags:

```shell
mql shell cassandra db.contoso.com --user auditor --ask-pass --tls --tls-ca ca.pem
```

## Examples

**Cluster version and security posture**

Read the cluster metadata and the authentication, authorization, and encryption settings at once.

```shell
mql> cassandra.cluster { version } cassandra.cluster.security { authenticationEnabled authorizationEnabled clientEncryptionEnabled internodeEncryption auditLoggingEnabled }
cassandra.cluster: {
  version: "5.0.8"
}
cassandra.cluster.security: {
  authenticationEnabled: true
  authorizationEnabled: true
  clientEncryptionEnabled: false
  internodeEncryption: "none"
  auditLoggingEnabled: false
}
```

**Superuser roles (CIS review)**

Find the superuser roles, including the default `cassandra` account that CIS recommends securing.

```shell
mql> cassandra.cluster.roles.where(isSuperuser) { name canLogin hasPassword }
cassandra.cluster.roles.where: [
  0: {
    name: "cassandra"
    canLogin: true
    hasPassword: true
  }
]
```

**Permissions granted to a role**

List a role's permission grants, for reviewing over-broad access.

```shell
mql> cassandra.cluster.roles.where(name == "auditor").first.permissions { resource permissions }
cassandra.cluster.roles.where.first.permissions: [
  0: {
    resource: "data/app"
    permissions: ["SELECT"]
  }
]
```

**Keyspaces with weak replication**

Find keyspaces that use `SimpleStrategy` or a single replica, an availability concern.

```shell
mql> cassandra.cluster.keyspaces.where(replicationStrategy == "SimpleStrategy" && isSystem == false) { name replicationFactors durableWrites }
cassandra.cluster.keyspaces.where: [
  0: {
    name: "app"
    replicationFactors: { replication_factor: "1" }
    durableWrites: true
  }
]
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell cassandra localhost --user cassandra --ask-pass -c "cassandra.cluster { version }"
```

If `cassandra.cluster.roles` comes back empty on an authenticated cluster, the connecting role cannot read `system_auth`; grant it `SELECT ON KEYSPACE system_auth` (or use a more privileged auditing role) and retry.

## Notes

- Password hashes are never exposed. Each role reports only whether it `hasPassword`, from the presence of its `salted_hash`.
- File-level CIS items (cassandra.yaml and keystore permissions, JMX configuration) are not reachable over CQL and are out of scope for this provider.
