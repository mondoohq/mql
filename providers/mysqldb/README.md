# MySQL Provider

The `mysqldb` provider connects to a MySQL, MariaDB, or Percona server and inventories it through read-only queries against `information_schema`, `performance_schema`, and the system catalogs. It exposes accounts, privileges, roles, schemas, routines, plugins, components, and configuration variables, so you can audit the server's security posture (the CIS MySQL benchmark) without touching the data.

The server flavor is detected automatically and reported as `mysqldb.instance.flavor` (`mysql`, `mariadb`, or `percona`), so one provider covers all three engines.

## Authentication

The provider authenticates with a MySQL user and password, and connects over TLS according to `--tls-mode`.

Arguments:

- `--host` - the server hostname or IP address (also accepted as the positional argument).
- `--port` - the server port (default `3306`).
- `--user` (`-u`) - the user to authenticate as.
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--database` - an optional default schema for the connection.
- `--tls-mode`:
  - `false` - plaintext, even when certificate flags are given.
  - `preferred` (default) - TLS when the server offers it, plaintext otherwise. The server is verified against `--tls-ca` when one is given. A server that offers TLS but fails the handshake (for example a YaSSL-built server limited to TLSv1.0) is an error; use `false` for such a server.
  - `skip-verify` - TLS required, server certificate not verified.
  - `true` - TLS required, server certificate verified against `--tls-ca` (or the system roots).
- `--tls-ca`, `--tls-cert`, `--tls-key` - paths to CA and client-certificate material for verified or mutual TLS.
- `--tls-server-name` - the name to verify in the server certificate when it differs from the host, for example when connecting by IP address.

The provider gives up on an unreachable server after 15 seconds and on an unresponsive one after 5 minutes per read.

```shell
mql shell mysqldb db.contoso.com --user root --ask-pass
```

> Prefer a least-privileged account for auditing. Read access to `mysql.user`, `information_schema`, and `performance_schema` is enough for the resources below; without it those collections return empty rather than failing the scan.

## Usage

Open an interactive shell against a server:

```shell
mql shell mysqldb --host db.contoso.com --user root --ask-pass
```

The host may also be given as the positional argument, and a verified-TLS connection adds the certificate flags:

```shell
mql shell mysqldb db.contoso.com --user auditor --ask-pass --tls-mode true --tls-ca ca.pem
```

## Discovery

By default the provider returns the server alone, the asset the benchmarks apply to. The `--discover` targets control whether each schema (database) is also emitted as its own `mysqldb-database` asset:

- `auto` (default) - the server only.
- `instance` - the server only.
- `none` - the server only.
- `all` - the server plus one asset per schema.
- `databases` - the server plus one asset per schema.

```shell
# Scan the server
cnspec scan mysqldb db.contoso.com --user auditor --ask-pass

# Scan the server and every schema
cnspec scan mysqldb db.contoso.com --user auditor --ask-pass --discover all
```

## Examples

**Server version and hardening settings**

Read the instance metadata and a few security-relevant variables at once.

```shell
mql> mysqldb.instance { version flavor requireSecureTransport localInfile }
mysqldb.instance: {
  version: "11.8.8-MariaDB-ubu2404"
  localInfile: true
  requireSecureTransport: false
  flavor: "mariadb"
}
```

**Anonymous or wildcard-host accounts (CIS 7.6 / 7.7)**

Find accounts that are anonymous or reachable from any host.

```shell
mql> mysqldb.instance.users.where(isAnonymous || isWildcardHost) { user host }
mysqldb.instance.users.where: [
  0: {
    host: "%"
    user: "root"
  }
]
```

**Accounts without a password (CIS 7.3)**

Find accounts that have no password set.

```shell
mql> mysqldb.instance.users.where(hasPassword == false) { user host authPlugin }
mysqldb.instance.users.where: [
  0: {
    host: "localhost"
    authPlugin: "mysql_native_password"
    user: "mariadb.sys"
  }
]
```

**Global privileges held by an account (CIS 5.x least-privilege)**

List the global (server-wide) privileges granted to an account, for reviewing over-broad grants such as `SUPER`, `FILE`, or `PROCESS`.

```shell
mql> mysqldb.instance.users.where(user == "appuser").first.privileges.where(scope == "GLOBAL") { privilegeType scope }
mysqldb.instance.users.where.first.privileges.where: [
  0: {
    scope: "GLOBAL"
    privilegeType: "PROCESS"
  }
]
```

**SECURITY DEFINER routines (CIS 5.10)**

List stored routines and whether each runs as its definer, a privilege-escalation surface when the definer is highly privileged.

```shell
mql> mysqldb.instance.schemas.where(name == "appdb").first.routines { name type securityType definer }
mysqldb.instance.schemas.where.first.routines: [
  0: {
    definer: "appuser@%"
    name: "secdef_proc"
    securityType: "DEFINER"
    type: "PROCEDURE"
  }
]
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell mysqldb db.contoso.com --user root --ask-pass -c "mysqldb.instance { version flavor }"
```

If `mysqldb.instance.users` comes back empty, the connecting account cannot read `mysql.user`; grant it read access (or use a more privileged auditing account) and retry.
