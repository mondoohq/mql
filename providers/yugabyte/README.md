# YugabyteDB Provider

The `yugabyte` provider queries a YugabyteDB cluster through one of its nodes:
the cluster's masters and tablet servers with their flags and health, and over
YSQL and YCQL the settings, roles, host-based authentication rules, databases,
tables with their privileges and row-level security, functions, and keyspaces.
It answers questions such as whether authentication and TLS are enforced,
which roles are superusers, whether a default password is still in place, and
which tables anyone may read.

## Prerequisites

The scanner needs to reach, on the node it connects to:

- the master HTTP port (7000) and the tablet server HTTP port (9000)
- the YSQL port (5433) and the YCQL port (9042)

Every other server's flags are read at the HTTP address the master reports for
it. A server the scanner cannot reach answers its own `flags` with an error;
the rest of the cluster is still read.

Connect to YSQL as a superuser to read everything: `pg_authid` (password
checks) and `pg_hba_file_rules` are superuser only. Reading YCQL roles needs
`SELECT` on `system_auth.roles`.

## Authentication

- `--user` and `--password` (or `--ask-pass`, or the `YUGABYTE_PASSWORD`
  environment variable) authenticate to YSQL and YCQL. Without `--user`, YSQL
  uses `yugabyte` and YCQL `cassandra`.
- `--ycql-user` and `--ycql-password` (or `YUGABYTE_YCQL_PASSWORD`) when YCQL
  uses other credentials than YSQL.
- `--sslrootcert` trusts the CA that signed the server certificates, for YSQL,
  YCQL, and HTTPS, and turns on TLS for YCQL. `--sslmode` (`require`,
  `verify-ca`, `verify-full`, default `verify-full` with a CA) decides what is
  checked for all three; use `verify-ca` when the node is reached at an address
  its certificate does not name. `--sslcert` and `--sslkey` give a client
  certificate.
- `--https` when the web servers are started with `webserver_certificate_file`.
  A cluster started with `yugabyted start --secure` encrypts YSQL and YCQL but
  keeps HTTP.

```shell
mql shell yugabyte localhost
YUGABYTE_PASSWORD=... mql shell yugabyte db.example.com --sslrootcert ca.crt
```

## Usage

A node in a container with published ports:

```shell
docker run -d --name yb -p 17000:7000 -p 19000:9000 -p 15433:5433 -p 19042:9042 \
  yugabytedb/yugabyte:2025.2.8.1-b8 bin/yugabyted start --background=false
mql shell yugabyte 127.0.0.1 --master-http-port 17000 --tserver-http-port 19000 \
  --ysql-port 15433 --ycql-port 19042
```

The master reports the node by its container name, which the host cannot
resolve. The provider reads the node's own pages at the host and the given
ports instead, once it has matched the node by its server UUID.

## Examples

**Authentication and TLS**

On a cluster started with `yugabyted start` and no further flags:

```shell
mql run yugabyte localhost -j -c 'yugabyte.cluster { ysql { authenticationEnabled tlsEnabled } ycql { authenticationEnabled } }'
[{"yugabyte.cluster":{"ycql":{"authenticationEnabled":false},"ysql":{"authenticationEnabled":false,"tlsEnabled":false}}}]
```

**Roles whose password is their name**

On a new cluster, the default superusers of both APIs:

```shell
mql> yugabyte.cluster.ysql.roles.where(passwordEqualsName) { name isSuperuser }
yugabyte.cluster.ysql.roles.where: [
  0: {
    name: "yugabyte"
    isSuperuser: true
  }
]
mql> yugabyte.cluster.ycql.roles.where(passwordEqualsName) { name }
yugabyte.cluster.ycql.roles.where: [
  0: {
    name: "cassandra"
  }
]
```

**Host-based authentication rules**

```shell
mql> yugabyte.cluster.ysql.hbaRules { lineNumber type users address method }
yugabyte.cluster.ysql.hbaRules: [
  0: {
    lineNumber: 4
    type: "host"
    users: ["all"]
    address: "all"
    method: "trust"
  }
  1: {
    lineNumber: 5
    type: "local"
    users: ["yugabyte"]
    address: ""
    method: "trust"
  }
]
```

**A flag on every tablet server**

```shell
mql> yugabyte.cluster.tservers { address flags.where(name == "use_node_to_node_encryption") { value type } }
yugabyte.cluster.tservers: [
  0: {
    flags.where: [
      0: {
        value: "false"
        type: "Default"
      }
    ]
    address: "fdac6ddb0721:9000"
  }
]
```

**Tables without row-level security that PUBLIC can read**

```shell
mql> yugabyte.cluster.ysql.tables.where(rowSecurity == false && grants.any(grantee == "PUBLIC" && privilege == "SELECT")) { schema name }
```

## Resources

`yugabyte.cluster` reaches everything: `masters` and `tservers` (each with its
`flags`), `health`, `ysql` (settings, roles, hbaRules, databases, extensions,
tables, functions, grants), and `ycql` (roles, keyspaces). Tables, functions,
extensions, and grants are those of the connected database (`--database`,
default `yugabyte`); settings and authentication rules are those of the tablet
server YSQL connects to.

## Troubleshooting

- `x509: cannot validate certificate for 127.0.0.1 because it doesn't contain
  any IP SANs`: the node's certificate names its host name. Connect by that
  name, or use `--sslmode verify-ca`.
- `Unable to locate leader master`: the masters have no leader (for example,
  half of them are down); cluster-wide data cannot be read until they elect
  one.
- `permission denied for table pg_authid`: password checks need a YSQL
  superuser.
