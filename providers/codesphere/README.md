# Codesphere Provider

The `codesphere` provider queries a Codesphere installation, either the Codesphere cloud or a Private Cloud: its organizations, resource groups (formerly called teams), workspaces, custom domains, and the catalog of data centers, workspace plans, and base images. Use it to audit who has access, how workspaces and domains are exposed, and whether workspaces run on supported images and plans.

## Authentication

The provider authenticates with a Codesphere API token. Create one in the user settings of your Codesphere installation. The scan sees what the token's owner can see, so use a token of a user who is an admin of the resource groups (and organizations) you want to audit.

Arguments:

- `--token` - the API token. Defaults to the `CS_TOKEN` environment variable.
- `--api` - the API URL. Defaults to `CS_API`, then `https://cloud.codesphere.com/api`. Set it for a Private Cloud installation.
- `--org` - scan only one organization ID. Defaults to `CS_ORG_ID`.
- `--resource-group`, `-G` - scan only one resource group ID. Defaults to `CS_RESOURCE_GROUP_ID`.

The environment variables are the ones the `cs` CLI uses.

```shell
mql shell codesphere --token TOKEN
mql shell codesphere --token TOKEN --api https://codesphere.example.com/api
```

## Discovery

The connection itself is the installation asset: the catalog, resource groups outside any organization, and the SSH keys of the token's owner. Discovery adds:

- **`codesphere-resource-group`** - one asset per resource group (target `resource-groups`)
- **`codesphere-workspace`** - one asset per workspace (target `workspaces`)
- **`codesphere-organization`** - one asset per organization (target `organizations`), for membership checks. Listing members needs organization admin rights.

`auto` (the default) discovers resource groups and workspaces; `all` adds organizations.

```shell
cnspec scan codesphere --token TOKEN --discover all
cnspec scan codesphere --token TOKEN --discover workspaces --resource-group 1234
```

Asset identity includes the API host, because resource group and workspace IDs are only unique within one installation.

## Examples

**Members with pending invitations**

```shell
mql> codesphere.resourceGroups { name members.where(pending) { email createdAt } }
```

**Workspaces that are not restricted, with their dev domain**

```shell
mql> codesphere.workspaces.where(restricted == false) { name devDomain resourceGroup.name }
```

**Workspaces cloned from a public repository**

```shell
mql> codesphere.workspaces.where(isPrivateRepo == false && gitUrl != null) { name gitUrl }
```

**Custom domains that are not verified or have no certificate**

```shell
mql> codesphere.resourceGroups.customDomains.where(verified == false || certificateIssued == false) { name verificationReason certificateReason }
```

**Workspaces on a base image past its support date**

```shell
mql> codesphere.workspaces.where(baseImage.supportedUntil < time.now) { name baseImage.id }
```

## Verification

`codesphere.resourceGroups { name }` confirms the token works and lists what it can reach. A resource group missing from the list means the token's owner is not a member of it, nor an admin of its organization.

## Troubleshooting

- **401 on every field:** the token is invalid or expired, or it belongs to a different installation than `--api` points at.
- **403 on `members`:** listing organization members needs organization admin rights. The rest of the scan is unaffected.
- **Credentials in `gitUrl`:** a password or token embedded in a repository URL is replaced with `xxxxx`. Its presence is still visible in the URL.
