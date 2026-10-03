# MongoDB Provider

The `mongo` provider connects to a self-hosted MongoDB server and inventories it through read-only administrative commands (`buildInfo`, `getCmdLineOpts`, `getParameter`, `usersInfo`, `rolesInfo`, `listDatabases`). It exposes the server configuration, users, roles and their privileges, and databases, so you can audit the server's security posture (the CIS MongoDB benchmark) without touching the data.

It supports MongoDB 4.4 and later (the minimum the Go driver speaks); an older server fails to connect with a wire-version error. This is the provider for MongoDB servers you run yourself. For MongoDB Atlas (the managed SaaS) use the `mongodbatlas` provider, and for local `mongod.conf` file analysis use the `os` provider's `mongodb` resource.

## Authentication

The provider authenticates with a MongoDB user and password (SCRAM), and connects over TLS when `--tls` is set.

Arguments:

- `--host` - the server hostname or IP address (also accepted as the positional argument).
- `--port` - the server port (default `27017`).
- `--user` - the user to authenticate as.
- `--password` - the password, or `--ask-pass` to be prompted.
- `--auth-db` - the authentication database (default `admin`).
- `--tls` - connect over TLS.
- `--tls-ca` - path to a CA certificate to verify the server.
- `--tls-insecure` - skip server-certificate verification (testing only).

```shell
mql shell mongo db.contoso.com --user admin --ask-pass
```

> Prefer a least-privileged account for auditing. A user with the built-in `clusterMonitor` role plus read on the `admin` database is enough for the resources below; without those privileges the users, roles, and parameters collections return empty rather than failing the scan.

## Usage

Open an interactive shell against a server:

```shell
mql shell mongo --host db.contoso.com --user admin --ask-pass
```

The host may also be given as the positional argument, and a verified-TLS connection adds the CA flag:

```shell
mql shell mongo db.contoso.com --user auditor --ask-pass --tls --tls-ca ca.pem
```

## Discovery

By default the provider emits the server as its only asset. The `--discover` targets control whether each database also becomes its own `mongo-database` asset:

- `auto` (default) - the server asset only.
- `all` - the server plus one asset per database.
- `databases` - the server plus one asset per database.
- `instance` - the server asset only.
- `none` - the server asset only.

A database asset is a scope on the same server connection: `mongo.instance` on it still describes the whole server.

```shell
# Scan the server only
cnspec scan mongo db.contoso.com --user auditor --ask-pass

# Scan the server and every database
cnspec scan mongo db.contoso.com --user auditor --ask-pass --discover all
```

## Examples

**Server version and hardening settings**

Read the instance metadata and a few security-relevant settings at once.

```shell
mql> mongo.instance { version authorizationEnabled tlsMode javascriptEnabled }
mongo.instance: {
  version: "7.0.39"
  authorizationEnabled: true
  tlsMode: "disabled"
  javascriptEnabled: true
}
```

**Privileged accounts (CIS role least-privilege)**

Find users that hold a broad, cross-database, or administrative built-in role.

```shell
mql> mongo.instance.users.where(isPrivileged) { user db }
mongo.instance.users.where: [
  0: {
    user: "admin"
    db: "admin"
  }
  1: {
    user: "opsadmin"
    db: "admin"
  }
]
```

**Custom roles across every database**

List the non-built-in roles defined on the server, including those in databases that hold no data.

```shell
mql> mongo.instance.roles { role db isBuiltin }
mongo.instance.roles: [
  0: {
    role: "appReadMetrics"
    db: "appdb"
    isBuiltin: false
  }
]
```

**Privileges granted by a role**

Inspect the resource/action grants of a specific role, for reviewing over-broad access.

```shell
mql> mongo.instance.roles.where(role == "appReadMetrics").first.privileges { database collection actions }
mongo.instance.roles.where.first.privileges: [
  0: {
    database: "appdb"
    collection: "metrics"
    actions: ["find"]
  }
]
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell mongo db.contoso.com --user admin --ask-pass -c "mongo.instance { version authorizationEnabled }"
```

If `mongo.instance.users` comes back empty, the connecting account cannot read the user catalog; grant it `clusterMonitor` (or use a more privileged auditing account) and retry.
