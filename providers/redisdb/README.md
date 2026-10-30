# Redis Provider

The `redisdb` provider connects to a Redis or Valkey server and inventories it through read-only commands (`INFO`, `CONFIG GET`, and the `ACL` commands). It exposes the server version and mode, its network and authentication posture (protected mode, bound interfaces, password, TLS), its access-control users, and its durability configuration, so you can audit the server's security posture without touching the data.

Redis and Valkey are both supported and detected automatically: `redisdb.instance.isValkey` reports which one, and `valkeyVersion` carries the Valkey version when applicable.

## Authentication

The provider authenticates with a password (legacy `requirepass`) or an ACL user and password (Redis 6+), and connects over TLS when `--tls` is set.

Arguments:

- `--host` - the server hostname or IP address (also accepted as the positional argument).
- `--port` - the server port (default `6379`).
- `--user` (`-u`) - the ACL user to authenticate as; omit for legacy password auth.
- `--password` (`-p`) - the password, or `--ask-pass` to be prompted.
- `--database` - the logical database index to select (default `0`).
- `--tls` - connect over TLS.
- `--tls-ca` - path to a CA certificate to verify the server.
- `--tls-cert`, `--tls-key` - client certificate and its key, for a server with `tls-auth-clients yes`. Either implies `--tls`.
- `--tls-insecure` - skip TLS certificate verification (testing only).

```shell
mql shell redisdb localhost --ask-pass
```

> The auditing credential needs to run `INFO` and `CONFIG GET` (the `default` user, or any user with `+@admin`/`+info`/`+config|get`), which is the common case for a `requirepass`-authenticated connection. Listing access-control users additionally needs `ACL LIST` and `ACL GETUSER`. A read-only auditing user needs:
>
> ```
> ACL SETUSER auditor on >password resetkeys resetchannels -@all +info +ping +config|get +acl|list +acl|getuser
> ```
>
> In mql 14, a command the credential may not run leaves its fields null (`CONFIG GET`: the posture fields and `config`) or its list empty (`ACL LIST`: `users`), so a check over them can pass on a server the scanner could not read. With the `StructuredErrors` feature enabled (the default from mql 15), those fields error instead and name the missing command (`+config|get`, `+acl|list`).

## Usage

Open an interactive shell against a server:

```shell
mql shell redisdb --host redis.contoso.com --ask-pass
```

The host may also be given as the positional argument, and a TLS connection adds the TLS flags:

```shell
mql shell redisdb redis.contoso.com --user auditor --ask-pass --tls --tls-ca ca.pem
```

Valkey is queried exactly the same way:

```shell
mql shell redisdb valkey.contoso.com --ask-pass
```

## Examples

**Server version and network/authentication posture**

Read the instance metadata and the security-relevant settings at once.

```shell
mql> redisdb.instance { version isValkey mode protectedMode bindsAllInterfaces requirepassSet tlsEnabled }
redisdb.instance: {
  version: "7.4.10"
  isValkey: false
  mode: "standalone"
  protectedMode: true
  bindsAllInterfaces: true
  requirepassSet: true
  tlsEnabled: false
}
```

**Access-control users and their command rules**

List the ACL users, whether each is the built-in default, and the command rules that govern it.

```shell
mql> redisdb.instance.users { name isDefault enabled nopass commandRules keyPatterns }
redisdb.instance.users: [
  0: {
    name: "auditor"
    isDefault: false
    enabled: true
    nopass: false
    commandRules: ["-@all", "+@read", "+@connection"]
    keyPatterns: ["app:*"]
  }
  1: {
    name: "default"
    isDefault: true
    enabled: true
    nopass: false
    commandRules: ["+@all"]
    keyPatterns: ["*"]
  }
]
```

**Passwordless or over-privileged default user**

A common finding: the default user is enabled with no password (anyone reaching the port authenticates as it) and still holds every command.

```shell
mql> redisdb.instance.users.where(isDefault) { nopass enabled commandRules }
redisdb.instance.users.where: [
  0: {
    nopass: false
    enabled: true
    commandRules: ["+@all"]
  }
]
```

**Durability configuration**

Inspect the persistence and eviction settings.

```shell
mql> redisdb.instance.config { rdbEnabled appendOnly appendFsync maxmemoryPolicy }
redisdb.instance.config: {
  rdbEnabled: true
  appendOnly: false
  appendFsync: "everysec"
  maxmemoryPolicy: "noeviction"
}
```

## Verification

Confirm the connection and permissions with a single query:

```shell
mql shell redisdb localhost --ask-pass -c "redisdb.instance { version protectedMode requirepassSet }"
```

If `redisdb.instance.users` comes back empty, or errors with a forbidden error, the connecting credential cannot read the ACL roster; authenticate as the `default` user or a user with `+acl|list` and `+acl|getuser` and retry. A null or forbidden `protectedMode` means the credential cannot run `CONFIG GET`.

## Notes

- `rename-command` remaps are a startup-only directive and are not readable over a connection (`CONFIG GET` does not return them), so the provider does not attempt to report them.
- On a server where `CONFIG` itself is renamed or removed (`rename-command CONFIG ""`), and on Sentinel, which has no `CONFIG` command, the fields read from `CONFIG GET` (`protectedMode`, `bind`, `bindsAllInterfaces`, `requirepassSet`, the ports, the TLS and ACL settings, and `config`) report an error saying so. The version, mode, and access-control users are still read.
