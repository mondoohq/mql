# PostgreSQL Provider

The `postgresdb` provider connects to a PostgreSQL server and inventories it through read-only queries against `pg_catalog` and `information_schema`. It exposes roles, databases, schemas, tables, functions, privileges, host-based authentication rules, extensions, foreign servers, and configuration settings, so you can audit the server's security posture (the CIS PostgreSQL benchmark) without touching the data.

## Authentication

The provider authenticates with a PostgreSQL role and password, and connects over TLS according to `--sslmode`.

Arguments:

- `--host` - the server hostname or IP address (also accepted as the positional argument).
- `--port` - the server port (default `5432`).
- `--user` (`-u`) - the role to authenticate as.
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--database` - the database used for the initial (server) connection (default `postgres`).
- `--sslmode` - `disable`, `allow`, `prefer` (default), `require`, `verify-ca`, or `verify-full`.
- `--sslrootcert`, `--sslcert`, `--sslkey` - paths to CA and client-certificate material for verified or mutual TLS.

```shell
mql shell postgresdb db.contoso.com --user postgres --ask-pass
```

> Prefer a least-privileged role for auditing. Some fields need more: a role's `passwordType` and the `hbaRules` require superuser, and the superuser-only `settings` require superuser or `pg_read_all_settings` membership. Without the privilege, `hbaRules` and `subscriptions` return a permission error, and `passwordType` reads null.

The host may also be a unix-socket directory, for example `--host /var/run/postgresql`, to connect over the local socket.

The provider supports PostgreSQL 9.2 and later. Catalog fields that a release does not have read their implied value (for example, every row-level security policy is permissive before PostgreSQL 10), and features a release does not have (replication slots before 9.4, row-level security before 9.5) read as empty. Before 9.6 the server cannot report its system identifier, so the asset id is derived from the host and port instead. On 9.2, `privileges` returns an error.

## Usage

Open an interactive shell against a server:

```shell
mql shell postgresdb --host db.contoso.com --user postgres --ask-pass
```

For a verified-TLS connection, add the certificate flags:

```shell
mql shell postgresdb db.contoso.com --user auditor --ask-pass --sslmode verify-full --sslrootcert ca.pem
```

## Discovery

Because PostgreSQL cannot query across databases, the provider connects per database. By default it scans the server asset alone. The `--discover` targets control which child assets are emitted:

- `auto` (default) - the server only.
- `instance` - the server only.
- `all` - the server plus one `postgresdb-database` asset per connectable database.
- `databases` - one asset per connectable database, alongside the server.
- `none` - the server only, without per-database assets.

```shell
# Scan the server only
cnspec scan postgresdb db.contoso.com --user auditor --ask-pass

# Scan the server and every database
cnspec scan postgresdb db.contoso.com --user auditor --ask-pass --discover all
```

## Examples

**Server settings**

Read the version and a couple of security-relevant settings at once.

```shell
mql> postgresdb.instance { version ssl passwordEncryption }
postgresdb.instance: {
  version: "PostgreSQL 17.10 (Debian 17.10-1.pgdg13+1) on aarch64-unknown-linux-gnu, ..."
  ssl: false
  passwordEncryption: "scram-sha-256"
}
```

**Superuser roles (CIS 4.3)**

List the roles that hold superuser, to review over-broad administrative access.

```shell
mql> postgresdb.instance.roles.where(isSuperuser) { name canLogin }
postgresdb.instance.roles.where: [
  0: {
    canLogin: true
    name: "postgres"
  }
]
```

**Privileges on the `public` schema**

List the privileges granted on a database's `public` schema, to confirm `CREATE` is not granted to `PUBLIC`.

```shell
mql> postgresdb.instance.databases.where(name == "appdb").first.schemas.where(name == "public").first.privileges { grantee privilegeType }
postgresdb.instance.databases.where.first.schemas.where.first.privileges: [
  0: { privilegeType: "USAGE"  grantee: "pg_database_owner" }
  1: { privilegeType: "CREATE" grantee: "pg_database_owner" }
  2: { privilegeType: "USAGE"  grantee: "PUBLIC" }
]
```

**SECURITY DEFINER functions (CIS 4.5)**

Find functions that run with their owner's privileges, a privilege-escalation surface.

```shell
mql> postgresdb.instance.databases.where(name == "appdb").first.functions.where(isSecurityDefiner) { name schema isSecurityDefiner }
postgresdb.instance.databases.where.first.functions.where: [
  0: {
    name: "secdef_fn"
    isSecurityDefiner: true
    schema: "appschema"
  }
]
```

**Tables with row-level security (CIS 4.7)**

Report which tables have row-level security enabled.

```shell
mql> postgresdb.instance.databases.where(name == "appdb").first.schemas.where(name == "appschema").first.tables { name rowSecurityEnabled }
postgresdb.instance.databases.where.first.schemas.where.first.tables: [
  0: {
    rowSecurityEnabled: true
    name: "t1"
  }
]
```

**Databases with pgvector (embedding stores)**

Find databases that have the pgvector extension installed, and read its version to check against pgvector advisories. An empty `pgvectorVersion` means it is not installed.

```shell
mql> postgresdb.instance.databases.where(pgvectorVersion != "") { name pgvectorVersion }
postgresdb.instance.databases.where: [
  0: {
    name: "postgres"
    pgvectorVersion: "0.8.6"
  }
]
```

## Verification

Confirm the connection with a single query:

```shell
mql shell postgresdb db.contoso.com --user postgres --ask-pass -c "postgresdb.instance { version }"
```

If a role's `passwordType` reads null, or `hbaRules` returns a permission error, the connecting role lacks the privilege to read `pg_authid` / `pg_hba_file_rules` (both superuser-only); use a more privileged auditing role and retry.
