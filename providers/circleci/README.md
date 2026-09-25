# CircleCI Provider

The `circleci` provider connects to a CircleCI account through its API v2
and inventories organizations, projects, contexts, and checkout keys
through read-only queries. It's built to audit pipeline secrets exposure
(contexts, project environment variables), source access (checkout keys),
and pull-request build settings (forked-PR builds) across an
organization's CircleCI footprint.

The API client under `connection/` is a minimal, hand-written `net/http`
client covering only the read endpoints the schema needs. The production
intent per [ADR-035](../../docs/adr/035-circleci-provider.md) is a client
generated from CircleCI's published OpenAPI 3.0 spec
(`https://circleci.com/api/v2/openapi.json`), vendored the same way other
generated clients in this repo are; that generation step was out of scope
for the initial implementation.

## Prerequisites

A CircleCI personal or project API token with read access to the
organizations, projects, and contexts you want to query.

## Authentication

Arguments:

- `--token` - a CircleCI API token.

```shell
mql shell circleci --token <token>
```

> Create a personal API token from the CircleCI dashboard under
> **User Settings > Personal API Tokens**.

You can also use the environment variable `CIRCLECI_TOKEN` to provide
your token.

## Usage

Open an interactive shell:

```shell
mql shell circleci
```

## Discovery

The provider models a single asset per connected token; there are no
`--discover` child-asset targets in this initial release.

## Examples

**Current user and visible organizations**

```shell
mql> circleci.me
mql> circleci.organizations { name vcsType }
```

**Projects that hand secrets to forked pull request builds**

A project that both builds forked PRs and shares secrets with them lets an
external contributor's fork read the project's credentials.

```shell
mql> circleci.projects.where( buildForkPrs == true && forksReceiveSecretEnvVars == true ) { name }
```

**Checkout keys that are not repo-scoped**

A `user-key` inherits every repository the creating user can reach, not
just this project.

```shell
mql> circleci.projects.checkoutKeys.where( type != "deploy-key" ) { fingerprint type }
```

**Context environment variable names (values are never returned by the API)**

```shell
mql> circleci.contexts { name environmentVariables { variable } }
```

## Resources

See `resources/circleci.lr` for the full schema. Top-level resources:
`circleci`, `circleci.organization`, `circleci.project`,
`circleci.project.environmentVariable`, `circleci.checkoutKey`,
`circleci.context`, and `circleci.context.environmentVariable`.

## Verification

`circleci.me` confirms the token authenticates; `circleci.organizations`
confirms it can see at least one organization. An empty
`circleci.organizations` result with no error usually means the token is
valid but has not been granted access to any organization.

## Troubleshooting

- **"a valid CircleCI API token is required"** - set `CIRCLECI_TOKEN` or
  pass `--token`.
- **"unable to authenticate with CircleCI"** - the token was rejected by
  the API; regenerate it from the CircleCI dashboard.
