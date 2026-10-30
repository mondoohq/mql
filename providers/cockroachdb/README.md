# CockroachDB Provider

The `cockroachdb` provider connects to a CockroachDB cluster over SQL and inventories it through read-only queries against `crdb_internal`, `pg_catalog`, system tables, and `SHOW` statements. It exposes the cluster version and whether it runs in insecure mode, its cluster settings and host-based authentication rules, roles with their password storage and session defaults, databases and tables with their privileges, nodes with their command line, certificates, and stores (including encryption at rest), and backup schedules, so you can audit a cluster's security configuration without touching its data.

## Prerequisites

The provider talks to any node of the cluster on its SQL port (26257 by default) and resolves the whole cluster from there.

What the connecting user can read decides what the provider can report:

| Reads | Needs |
| --- | --- |
| cluster id and version, roles, memberships, administrator status | nothing |
| databases, tables, privileges | a privilege on each database; without the `admin` role, CockroachDB leaves out what the user may not see, without an error |
| cluster settings and host-based authentication rules | `VIEWCLUSTERSETTING` |
| insecure mode, nodes, certificates, stores | `VIEWCLUSTERMETADATA` |
| role options, password storage, role session defaults, backup schedules | the `admin` role |

A least-privileged auditor without the `admin` role:

```sql
CREATE USER auditor;
GRANT SYSTEM VIEWCLUSTERSETTING, VIEWCLUSTERMETADATA TO auditor;
```

A field the user may not read reports an access-denied error naming the privilege, never an empty answer. Databases, tables, and privileges are the exception: CockroachDB itself filters them to what the user may see, so audit them as a member of the `admin` role.

## Authentication

Arguments:

- `[host]` or `--host` - the node to connect to.
- `--port` - the SQL port (default `26257`).
- `--user` - the user to authenticate as (default `root`).
- `--certs-dir` - a CockroachDB certificate directory, as `cockroach cert` writes it. The provider uses `ca.crt` and `client.<user>.crt`/`client.<user>.key` from it and verifies the server certificate (`--sslmode verify-full`).
- `--ask-pass` - prompt for a password (or `--password`).
- `--sslmode`, `--sslrootcert`, `--sslcert`, `--sslkey` - TLS settings, as for any PostgreSQL client. The default mode is `prefer`, or `verify-full` with `--certs-dir`.
- `--database` - the database to connect to (default `defaultdb`).

With client certificates:

```shell
mql shell cockroachdb localhost --certs-dir certs
```

With a password:

```shell
mql shell cockroachdb db.example.com --user auditor --ask-pass --sslmode verify-full --sslrootcert certs/ca.crt
```

## Usage

```shell
mql shell cockroachdb localhost --certs-dir certs
cnspec scan cockroachdb localhost --certs-dir certs
```

Each node of a cluster resolves to the same asset, identified by the cluster ID.

## Examples

**Cluster identity and insecure mode**

```shell
mql> cockroachdb.cluster { id version clusterVersion insecure }
cockroachdb.cluster: {
  clusterVersion: "25.4"
  version: "25.4.17"
  insecure: false
  id: "f360f812-a251-4c4b-981e-65bdbfea456c"
}
```

**Authentication logging and certificate revocation checks**

```shell
mql> cockroachdb.cluster.settings.where(name == /^(server.auth_log.sql_connections.enabled|security.ocsp.mode)$/) { name value isDefault }
cockroachdb.cluster.settings.where: [
  0: {
    name: "security.ocsp.mode"
    value: "off"
    isDefault: true
  }
  1: {
    name: "server.auth_log.sql_connections.enabled"
    value: "false"
    isDefault: true
  }
]
```

**Host-based authentication rules, in evaluation order**

```shell
mql> cockroachdb.cluster.hbaRules { position connectionType users address method }
cockroachdb.cluster.hbaRules: [
  0: {
    users: [
      0: "root"
    ]
    connectionType: "host"
    address: "all"
    method: "cert"
    position: 1
  }
  1: {
    users: [
      0: "app"
    ]
    connectionType: "hostssl"
    address: "10.0.0.0/8"
    method: "cert-scram-sha-256"
    position: 2
  }
  2: {
    users: [
      0: "all"
    ]
    connectionType: "host"
    address: "0.0.0.0/0"
    method: "cert-password"
    position: 3
  }
  3: {
    users: [
      0: "all"
    ]
    connectionType: "local"
    address: ""
    method: "password"
    position: 4
  }
]
```

**Administrators that can log in, and passwords still stored as bcrypt**

```shell
mql> cockroachdb.cluster.roles.where(isAdmin && canLogin) { name passwordHashMethod }
cockroachdb.cluster.roles.where: [
  0: {
    passwordHashMethod: ""
    name: "admin"
  }
  1: {
    passwordHashMethod: ""
    name: "root"
  }
]

mql> cockroachdb.cluster.roles.where(passwordHashMethod == "crdb-bcrypt") { name }
cockroachdb.cluster.roles.where: [
  0: {
    name: "legacy"
  }
]
```

**Login roles without an idle session timeout**

```shell
mql> cockroachdb.cluster.roles.where(canLogin && defaultSessionVariables["idle_in_session_timeout"] == null) { name }
cockroachdb.cluster.roles.where: [
  0: {
    name: "admin"
  }
  1: {
    name: "legacy"
  }
  2: {
    name: "root"
  }
]
```

**Certificate expiry and encryption at rest per node**

```shell
mql> cockroachdb.cluster.nodes { id version certificates { type expiresAt } stores { path encrypted } }
cockroachdb.cluster.nodes: [
  0: {
    certificates: [
      0: {
        expiresAt: 2036-10-26 16:46:17 +0100 CET
        type: "ca"
      }
      1: {
        expiresAt: 2031-10-23 17:46:17 +0200 CEST
        type: "node"
      }
    ]
    version: "25.4.17"
    id: 1
    stores: [
      0: {
        encrypted: false
        path: "/cockroach/cockroach-data"
      }
    ]
  }
]
```

**Unencrypted backup schedules**

```shell
mql> cockroachdb.cluster.backupSchedules.where(encrypted == false) { label recurrence statement }
cockroachdb.cluster.backupSchedules.where: [
  0: {
    statement: "BACKUP INTO 'nodelocal://1/plain' WITH OPTIONS (detached)"
    recurrence: "@daily"
    label: "plain"
  }
]
```

**Privileges granted to every role**

```shell
mql> cockroachdb.cluster.databases.where(name == "shop") { name grants.where(grantee == "public") { privilege } }
cockroachdb.cluster.databases.where: [
  0: {
    name: "shop"
    grants.where: [
      0: {
        privilege: "CONNECT"
      }
    ]
  }
]
```

## Development

Unit tests run with `go test ./...`. The integration tests in `resources/integration_test.go` run against a secure cluster seeded by `testdata/seed.sh`:

```shell
cockroach cert create-ca --certs-dir=certs --ca-key=certs/ca.key
cockroach cert create-node localhost 127.0.0.1 --certs-dir=certs --ca-key=certs/ca.key
cockroach cert create-client root --certs-dir=certs --ca-key=certs/ca.key
docker run -d --name crdb -p 127.0.0.1:26257:26257 -v $PWD/certs:/certs cockroachdb/cockroach:latest-v25.4 start-single-node --certs-dir=/certs
testdata/seed.sh | docker exec -i crdb ./cockroach sql --certs-dir=/certs --host=127.0.0.1
COCKROACHDB_TEST_HOST=127.0.0.1 COCKROACHDB_TEST_CERTS_DIR=$PWD/certs go test -run Integration ./resources/
```
