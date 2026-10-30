# JumpCloud Provider

The `jumpcloud` provider inventories a JumpCloud organization through read-only
queries: users, systems (enrolled devices), user and system groups, SSO
applications, policies, commands, RADIUS servers, and external directory
integrations. Membership and access relationships are exposed as typed
accessors, so an audit can traverse the directory graph (user to groups to
systems, group to members, application to the groups that grant access) without
correlating raw identifiers by hand.

## Authentication

Authenticate with a JumpCloud API key. Multi-tenant (MSP) administrators also
pass the organization id the key should act on.

Arguments:

- `--api-key` - a JumpCloud API key. Can also be supplied through the
  `JUMPCLOUD_API_KEY` environment variable.
- `--org-id` - the JumpCloud organization id. Required only for multi-tenant
  (MSP) API keys. Can also be supplied through the `JUMPCLOUD_ORG_ID`
  environment variable.

> You can generate an API key from the JumpCloud Admin Portal under your
> account profile ("API Settings"). The key inherits the privileges of the
> administrator who created it, so scope that administrator to read-only access
> when possible.

```shell
mql shell jumpcloud --api-key API_KEY
mql shell jumpcloud --api-key API_KEY --org-id ORG_ID
```

## Usage

Open an interactive shell:

```shell
mql shell jumpcloud --api-key API_KEY
```

## Examples

**Find active users without multi-factor authentication**

```shell
mql> jumpcloud.users.where(suspended == false && mfaConfigured == false) { email }
```

**Check that no system permits SSH root login**

```shell
mql> jumpcloud.systems.all(allowSshRootLogin == false)
```

**List systems missing full-disk encryption**

```shell
mql> jumpcloud.systems.where(fdeActive == false) { hostname os }
```

**Traverse the directory graph from a user to their groups and systems**

```shell
mql> jumpcloud.users {
       email
       userGroups { name }
       systems { hostname os }
     }
```

**Expand a user group to its members**

```shell
mql> jumpcloud.userGroups { name members { email } }
```

**See which user groups grant access to each SSO application**

```shell
mql> jumpcloud.applications { displayName userGroups { name } }
```

## Resources

The full list of resources and fields is generated from the `.lr` schema in
`resources/jumpcloud.lr`. The top-level `jumpcloud` resource exposes `users`,
`systems`, `userGroups`, `systemGroups`, `applications`, `policies`, `commands`,
`radiusServers`, and `directories`, and the user, system, group, and
application resources carry typed accessors for their membership and access
relationships.

## Verification

Confirm the connection and permissions work:

```shell
mql> jumpcloud.users.length
```

An error mentioning the organization id or an empty result generally means the
API key was rejected or lacks read access to the requested collection.
