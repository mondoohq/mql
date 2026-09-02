# ClickHouse Provider

The `clickhousedb` provider connects to a ClickHouse server and inventories it through read-only queries against the `system.*` tables. It exposes the server version and its users, roles, grants, settings profiles, quotas, clusters, and server settings, so you can audit the server's security posture without touching application data.

It uses the pure-Go [clickhouse-go](https://github.com/ClickHouse/clickhouse-go) driver, so it needs no native libraries.

## Authentication

The provider authenticates with a user and password over the ClickHouse native protocol.

Arguments:

- `--host` - the server hostname or IP address (also accepted as the positional argument).
- `--port` - the native protocol port (default `9000`, or `9440` for TLS).
- `--database` - the database to connect to (default `default`).
- `--user` - the user to authenticate as (default `default`).
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--tls` - connect over TLS.
- `--tls-insecure` - skip TLS certificate verification (testing only).

```shell
mql shell clickhousedb db.contoso.com --user auditor --ask-pass
```

> Prefer a least-privileged auditing user. Reading the access catalog needs `SELECT` on `system.*` and `SHOW ACCESS`, without access to any application data:
>
> ```sql
> CREATE USER auditor IDENTIFIED WITH sha256_password BY '<password>';
> GRANT SELECT ON system.* TO auditor;
> GRANT SHOW ACCESS ON *.* TO auditor;
> ```
>
> Reading users, roles, and grants requires SQL-driven access management to be enabled on the server. Without the catalog privileges, those collections come back empty (an access-denied error is treated as "not permitted") rather than failing the scan.

## Examples

**Server version**

```shell
mql> clickhousedb.instance { version }
clickhousedb.instance: {
  version: "24.8.4.13"
}
```

**Users that can log in without a password**

```shell
mql> clickhousedb.instance.users.where(hasPassword == false) { name authTypes }
clickhousedb.instance.users.where: [
  0: {
    name: "weakuser"
    authTypes: ["no_password"]
  }
]
```

**Users reachable from any host**

ClickHouse gates the origin of a connection on three independent lists and admits
the connection when any one of them matches, so `anyHost` reads all three. An
account pinned to a narrow IP range that also carries a host name pattern matching
every name is reachable from anywhere.

```shell
mql> clickhousedb.instance.users.where(anyHost) { name hostIps hostNamesRegexp hostNamesLike }
clickhousedb.instance.users.where: [
  0: { name: "default"           hostIps: ["::/0"]       hostNamesRegexp: []        hostNamesLike: [] }
  1: { name: "regexp_open_user"  hostIps: ["10.0.0.1"]   hostNamesRegexp: ["^.*$"]  hostNamesLike: [] }
]
```

**Roles and their privileges**

```shell
mql> clickhousedb.instance.roles { name grants }
clickhousedb.instance.roles: [
  0: {
    name: "analyst"
    grants: ["SELECT ON *.*"]
  }
]
```

**Users with a broad privilege**

```shell
mql> clickhousedb.instance.users.where(grants.any(_ == "SELECT ON *.* WITH GRANT OPTION")) { name }
```

**Security-relevant server settings**

```shell
mql> clickhousedb.instance.serverSettings.where(name == "tcp_port_secure") { name value }
```

## Verification

Confirm the connection with a single query:

```shell
mql shell clickhousedb db.contoso.com --user auditor --ask-pass -c "clickhousedb.instance { version }"
```

If `clickhousedb.instance.users` comes back empty, the server does not have SQL-driven access management enabled for the connecting user, or the user lacks `SHOW ACCESS`; enable it (or use a more privileged auditing account) and retry.

## Development

The integration tests live in `resources/integration_test.go` and are gated on the `CLICKHOUSE_TEST_*` environment, so they skip in CI and run only when you point them at a live server. `resources/testdata/seed.sql` holds the fixtures they assert on (a password-less user, a host-restricted user, a user opened up by a host name expression, a role with a broad grant).

To run the whole thing locally in one step, `resources/testdata/integration.sh` starts a throwaway ClickHouse container, loads the seed, runs the tests, and tears the container down (a few seconds once the image is cached):

```shell
providers/clickhousedb/resources/testdata/integration.sh
```

Or point the tests at a server you already have:

```shell
CLICKHOUSE_TEST_HOST=127.0.0.1:9000 CLICKHOUSE_TEST_USER=default CLICKHOUSE_TEST_PASSWORD=... \
  go test ./providers/clickhousedb/resources/ -run TestIntegration -v
```

## Notes

- Password material (`auth_params`) is never queried or exposed. Users report only how they authenticate (`authTypes`) and whether a credential is required (`hasPassword`).
- Users defined in the XML config file (`storage == "users_xml"`) are visible, but the file itself is not read by this provider.
