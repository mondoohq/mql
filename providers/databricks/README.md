# Databricks Provider

Query the security posture of a Databricks account and its workspaces.

## Connection model

The provider spans Databricks' two API planes:

- **Account plane** (`accounts.cloud.databricks.com`) is the entry point. Connecting
  to it exposes account-level identity and networking, and discovers every
  workspace in the account as a child asset.
- **Workspace plane** (a workspace URL) exposes that workspace's operational
  security surface. Each discovered workspace becomes its own asset, and you can
  also connect a single workspace directly.

Connecting to the account therefore fans out into one asset per workspace, each
scanned against its own workspace API.

## Authentication

The provider uses the official `databricks-sdk-go` unified auth.

### OAuth machine-to-machine (recommended)

Create an account-level service principal with an OAuth secret and grant it the
access you want to audit (account admin for full account coverage, plus
workspace entitlement for each workspace you want to reach).

```shell
mql shell databricks \
  --account-id <account-id> \
  --client-id <client-id> \
  --client-secret <client-secret>
```

### Personal access token (single workspace)

```shell
mql shell databricks --host <workspace-url> --token <pat>
```

### Environment variables

Any flag can be supplied through its environment variable instead:
`DATABRICKS_ACCOUNT_ID`, `DATABRICKS_HOST`, `DATABRICKS_CLIENT_ID`,
`DATABRICKS_CLIENT_SECRET`, `DATABRICKS_TOKEN`.

### Azure and GCP

For Azure- or GCP-hosted Databricks, point `--host` at the matching account
console host (`accounts.azuredatabricks.net` or `accounts.gcp.databricks.com`).
The workspace hosts are derived automatically during discovery.

## Discovery

Discovery is controlled with `--discover`:

- `auto` / `all` (default) discovers every workspace.
- `workspaces` is the explicit workspace target.

## Examples

Account plane:

```shell
# Service principals that are still active
mql shell databricks --account-id <id> --client-id <id> --client-secret <secret> \
  -c "databricks.servicePrincipals.where(active)"

# Workspaces not protected by a customer-managed key
cnspec run databricks ... \
  -c "databricks.workspaces.where(storageCustomerManagedKeyId == '')"
```

Workspace plane (run against a discovered workspace asset):

```shell
# Personal access tokens that never expire
cnspec run databricks --host <workspace-url> --token <pat> \
  -c "databricks.tokens.where(expiryTime == null)"

# Clusters without Unity Catalog isolation
cnspec run databricks ... \
  -c "databricks.clusters.where(dataSecurityMode == 'NONE')"

# Catalog grants to a principal
cnspec run databricks ... \
  -c "databricks.catalogs { name grants { principal privileges } }"
```
