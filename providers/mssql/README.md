# Microsoft SQL Server Provider

The `mssql` provider connects to a Microsoft SQL Server instance over TDS and inventories it through read-only catalog queries (`sys.*` and `msdb.*`). It exposes server principals (logins and roles), permissions, databases and their users/roles, credentials, linked servers, SQL Agent proxies, audits, encryption keys, and surface-area configuration options, so you can audit the instance's security posture (the CIS SQL Server benchmark) without touching the data.

## Authentication

The provider authenticates with a SQL login, Windows (NTLM) integrated auth, or a Microsoft Entra ID access token, and connects with a configurable TDS encryption mode.

Arguments:

- `--host` - the instance hostname or IP address (also accepted as the positional argument).
- `--port` - the instance port (default `1433`).
- `--instance` - a named instance (resolved via SQL Browser when the port is unknown).
- `--user` (`-u`) - the login name (`sa`, `DOMAIN\user`, or a user principal name).
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--auth` - `sql` (default), `windows`, or `azure`.
- `--token` - a Microsoft Entra ID access token (for `--auth azure`).
- `--database` - scope the connection to a single database.
- `--encrypt` - `strict`, `mandatory` (default), `optional`, or `disable`.
- `--trust-server-certificate` - skip TLS certificate validation.

```shell
mql shell mssql sql.contoso.com --user sa --ask-pass
```

> Prefer a least-privileged login for auditing. `VIEW ANY DEFINITION` (or the `##MS_DefinitionReader##` role on 2022+) lets the provider see all server principals, permissions, credentials, audits, and every database's principals and keys. SQL Agent proxies (`msdb.dbo.sysproxies`, `sysproxylogin`, `sysproxysubsystem`) additionally need `sysadmin` or an msdb SQLAgent role.
>
> SQL Server lists only the catalog rows a login holds a permission on, without raising an error. In mql 14, a login without `VIEW ANY DEFINITION` therefore reads a subset of logins, roles, members, and permissions, and a refused msdb read comes back empty, so a check over them can pass on a server the scanner could not fully read. With the `StructuredErrors` feature enabled (the default from mql 15), those collections error and name the missing permission instead: `VIEW ANY DEFINITION` for the server catalog, `VIEW DEFINITION ON DATABASE::<name>` for a database's catalog, `VIEW ANY DATABASE` for `databases`, and `SELECT ON msdb.dbo.<table>` for proxies and backups.

## Usage

Open an interactive shell against an instance:

```shell
mql shell mssql sql.contoso.com --user sa --ask-pass
```

Named instance, or Windows/Entra authentication:

```shell
mql shell mssql sql.contoso.com --instance SQL2022 --auth windows --user 'CONTOSO\auditor' --ask-pass
mql shell mssql sql.contoso.com --auth azure --user auditor@contoso.com --token <access-token>
```

## Discovery

By default the provider scans the instance alone, because that is the asset the benchmarks and most policies apply to. Per-database `mssql-database` assets are opt-in. The `--discover` targets control which child assets are emitted:

- `auto` (default) - the instance only.
- `all` - the instance plus one asset per online database.
- `databases` - the instance plus one asset per online database.
- `instance` / `none` - the instance only.

```shell
# Scan the instance only
cnspec scan mssql sql.contoso.com --user auditor --ask-pass

# Scan the instance and every online database
cnspec scan mssql sql.contoso.com --user auditor --ask-pass --discover all
```

## Examples

**Server version and authentication mode**

Read the instance metadata, including whether mixed-mode (SQL + Windows) authentication is enabled.

```shell
mql> mssql.server { version edition isMixedModeAuthEnabled }
mssql.server: {
  isMixedModeAuthEnabled: true
  version: "Microsoft SQL Server 2022 (RTM-CU26) ... Developer Edition (64-bit) on Linux ..."
  edition: "Developer Edition (64-bit)"
}
```

**State of the `sa` login (CIS 2.13)**

Check whether the built-in `sa` login is disabled.

```shell
mql> mssql.server.logins.where(name == "sa") { name isDisabled }
mssql.server.logins.where: [
  0: {
    name: "sa"
    isDisabled: false
  }
]
```

**Surface-area configuration (CIS 2.x)**

Read a `sp_configure` option's running value, for example `clr enabled`.

```shell
mql> mssql.server.configurations.where(name == "clr enabled") { name valueInUse }
mssql.server.configurations.where: [
  0: {
    valueInUse: 0
    name: "clr enabled"
  }
]
```

**Trustworthy databases (CIS 2.9)**

Report the Trustworthy and TDE state of a database.

```shell
mql> mssql.server.databases.where(name == "TESTDB") { name isTrustworthy isEncrypted }
mssql.server.databases.where: [
  0: {
    isTrustworthy: false
    name: "TESTDB"
    isEncrypted: false
  }
]
```

**Backup encryption (CIS 7.3)**

List a database's backup history and whether each backup set is encrypted.

```shell
mql> mssql.server.databases.where(name == "TESTDB").first.backups { type isEncrypted keyAlgorithm }
mssql.server.databases.where.first.backups: [
  0: {
    type: "DATABASE"
    isEncrypted: true
    keyAlgorithm: "aes_256"
  }
]
```

## Verification

Confirm the connection with a single query:

```shell
mql shell mssql sql.contoso.com --user sa --ask-pass -c "mssql.server { version edition }"
```

If `mssql.server.logins` is missing principals you expect, or errors with a forbidden error, the login lacks `VIEW ANY DEFINITION`; grant it (or the `##MS_DefinitionReader##` role) and retry.
