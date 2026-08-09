# Bitbucket Provider

The `bitbucket` provider connects to Bitbucket Cloud and inventories its
workspaces, projects, repositories, branch restrictions, deploy keys, and
the members and groups that hold access, through read-only queries against
the Bitbucket Cloud REST API 2.0.

## Client implementation note

This provider's HTTP client (`providers/bitbucket/connection/client.go`) is a
minimal, hand-written `net/http` client covering only the read endpoints the
`.lr` schema needs. Per [ADR-034](../../docs/adr/034-bitbucket-provider.md),
the intended production client is generated from Bitbucket's published
Swagger/OpenAPI 2.0 spec (`https://api.bitbucket.org/swagger.json`) via
`openapi-generator`; that generation step was out of scope for this change
and should replace the hand-written client before this provider is
considered production-hardened.

Two fields on `bitbucket.workspace` (`enforceTwoStepVerification`, plus
`ipAllowlistEnabled`/`ipAllowlist`) are read from the same
`GET /workspaces/{workspace}` response using field names that are not part
of Bitbucket's public REST API 2.0 documentation as of this writing; they
have not been verified against a live tenant with these workspace security
settings configured, so expect them to read as `false`/empty until that
verification happens.

## Prerequisites

None beyond network access to `api.bitbucket.org`.

## Authentication

Arguments:

- `--workspace` (or `BITBUCKET_WORKSPACE`) - the Bitbucket workspace slug to inventory.
- `--token` (or `BITBUCKET_TOKEN`) - a workspace or repository Access Token, sent as a Bearer token.
- `--username` (or `BITBUCKET_USERNAME`) and `--app-password` (or `BITBUCKET_APP_PASSWORD`) - an App Password, sent as HTTP Basic auth.

An Access Token takes precedence when both are configured.

```shell
mql shell bitbucket --workspace acme-corp --token <token>
```

```shell
mql shell bitbucket --workspace acme-corp --username jdoe --app-password <app-password>
```

## Usage

Open an interactive shell:

```shell
mql shell bitbucket
```

## Examples

**List repositories with their privacy and fork policy**

```shell
mql> bitbucket.workspace.repositories { fullName isPrivate forkPolicy mainBranch }
```

**Check branch restrictions on every repository**

```shell
mql> bitbucket.workspace.repositories { fullName branchRestrictions { kind pattern minApprovals } }
```

**Review deploy keys**

```shell
mql> bitbucket.workspace.repositories { fullName deployKeys { label lastUsed } }
```

## Resources

See the generated resource reference for `bitbucket.*`, derived from
`providers/bitbucket/resources/bitbucket.lr`.

## Troubleshooting

- `a Bitbucket workspace is required`: set `BITBUCKET_WORKSPACE` or pass `--workspace`.
- `Bitbucket credentials are required`: set `BITBUCKET_TOKEN`, or both `BITBUCKET_USERNAME` and `BITBUCKET_APP_PASSWORD`.
- A `401` from the API during connect means the token or App Password was rejected; regenerate it in Bitbucket's workspace settings.
