# Neon Provider

Query the configuration and security posture of your Neon Postgres
organizations, projects, and branches: what can reach a project's data over the
network, who has been granted access to it, which roles and databases exist on
each branch, and which outside identity providers are trusted to authenticate
against it.

## Prerequisites

A Neon API key. Create one under **Account settings > API keys** in the Neon
console.

A key is either personal or organization-scoped, and the two reach different
things:

- A **personal key** reaches the organizations your account belongs to, their
  projects, and your personal API keys. It can read an organization's member
  roster only where your account is an admin.
- An **organization key** reaches that organization's projects, member roster,
  and organization-scoped keys. It has no user behind it, so `currentUser` is
  null.

Reads the key is not entitled to come back null rather than empty.

## Authentication

Arguments:

- `--token` - the Neon API key.
- `--organization` - optional, restrict the scan to one organization (ID).

```shell
# flag
mql shell neon --token API_KEY

# environment variable (NEON_API_KEY or NEON_TOKEN)
export NEON_API_KEY=API_KEY
mql shell neon
```

## Usage

Open an interactive shell:

```shell
mql shell neon --token API_KEY
```

## Discovery

Connecting to `neon` discovers two kinds of assets:

- **`neon-organization`** - every organization the key can access.
- **`neon-project`** - every project of those organizations.

Scope discovery with `--discover`:

```shell
cnspec scan neon --token API_KEY --discover organizations
cnspec scan neon --token API_KEY --discover projects
```

Restrict the scan to one organization with `--organization`. The flag narrows
both discovery and plain queries, so the same connection sees the same
organizations either way:

```shell
cnspec scan neon --token API_KEY --organization org-example-12345678
```

## Examples

**Projects reachable from any address on the internet**

```shell
mql> neon.projects.where(blockPublicConnections == false && allowedIps.length == 0) { name regionId }
```

**Allowed-address lists that only constrain protected branches**

```shell
mql> neon.projects.where(allowedIpsProtectedBranchesOnly == true) { name allowedIps }
```

**Projects that retain role passwords**

```shell
mql> neon.projects.where(storePasswords == true) { name ownerEmail }
```

**Unprotected branches carrying a copy of the data**

```shell
mql> neon.projects { name branches.where(protected == false && initSource == "parent-data") { name createdAt } }
```

**Compute endpoints that accept connections without a password**

```shell
mql> neon.projects { name endpoints.where(passwordlessAccess == true) { id host type } }
```

**Projects shared with an outside account, excluding revoked grants**

```shell
mql> neon.projects { name permissions.where(revokedAt == null) { grantedToEmail grantedAt } }
```

**Outside identity providers trusted to authenticate database access**

```shell
mql> neon.projects { name jwksEndpoints { providerName jwksUrl roleNames } }
```

**API keys that have never been used**

```shell
mql> neon.apiKeys.where(lastUsedAt == null) { name createdAt }
mql> neon.organizations { name apiKeys.where(lastUsedAt == null) { name createdByName } }
```

**Organization admins**

```shell
mql> neon.organizations { name members.where(role == "admin") { email joinedAt } }
```

**Members without multi-factor authentication**

```shell
mql> neon.organizations { name members.where(hasMfa == false) { email role } }
```

**Organizations that do not require multi-factor authentication**

```shell
mql> neon.organizations.where(requireMfa == false) { name plan }
```

**Roles reachable with a password**

```shell
mql> neon.projects { branches { roles.where(authenticationMethod == "password") { name protected } } }
```

**Projects with no restore window**

```shell
mql> neon.projects.where(historyRetentionSeconds == 0) { name }
```

**Cross-resource traversal**

Projects, branches, endpoints, roles, and databases reference each other, so a
query can start from any of them and walk in either direction:

```shell
mql> neon.projects { branches { name parent { name } } }
mql> neon.projects { endpoints { host branch { name protected } } }
mql> neon.projects { branches { databases { name owner { name protected } } } }
mql> neon.projects { name defaultBranch { name protected } }
mql> neon.projects { jwksEndpoints { providerName branch { name } } }
```

A reference resolves through its project's already-fetched branch list, so
walking from many children back to their branch or project does not repeat API
calls.

## Verification

Confirm the key works and see what it can reach:

```shell
mql> neon.currentUser { email plan authProviders }
mql> neon.projects { id name regionId }
```

A null `currentUser` with a populated project list means the key is
organization-scoped, which is expected. An empty organization list means the
key was accepted but belongs to no organization, and since every project
belongs to one, the project list is empty too.

## Troubleshooting

**`a valid Neon API key is required`** - neither `--token` nor `NEON_API_KEY` /
`NEON_TOKEN` was set.

**`neon API /projects: 401 UNAUTHORIZED`** - the key was revoked or mistyped.

**`members` is null on an organization** - reading the roster takes
organization admin rights, and the key does not have them.

**`vpcEndpoints` is null** - private connectivity is a plan-gated feature and
the project's plan does not include it.

**`auditLogLevel` is null** - audit logging is plan-gated, and the project's
plan does not carry the setting.

**`--organization` returns nothing** - the value must be the organization ID
(`org-...`), not its display name. A value the key is not a member of leaves
both the organization and project lists empty rather than failing the scan.

## Notes

Role passwords are not exposed, even on a project with `storePasswords`
enabled where the API can return them.
