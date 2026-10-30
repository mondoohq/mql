# MongoDB Atlas Provider

Query the security posture of a MongoDB Atlas organization and its projects.

## Connection model

Atlas has a two-level hierarchy that the provider spans:

- **Organization** is the entry point. Connecting to it exposes organization-wide
  security settings and identity, and discovers every project as a child asset.
- **Project** (also called a group) holds the operational security surface:
  clusters, database users, network access, encryption, auditing, private
  endpoints, and cloud-provider access.

Connecting to an organization therefore fans out into one asset per project,
each scanned against the same Atlas Admin API with a project scope. A single
project can also be connected directly with `--project-id`.

## Authentication

The provider uses the official `atlas-sdk-go` unified auth, with two options:

### Programmatic API key (recommended)

A public/private API key pair (HTTP Digest). Grant the key organization
read-only access to audit the whole organization.

```shell
mql shell mongodbatlas \
  --org-id <org-id> \
  --public-key <public-key> \
  --private-key <private-key>
```

### Service account (OAuth2)

```shell
mql shell mongodbatlas \
  --org-id <org-id> \
  --client-id <client-id> \
  --client-secret <client-secret>
```

### Environment variables

Any flag can be supplied through its environment variable instead:
`MONGODB_ATLAS_ORG_ID`, `MONGODB_ATLAS_PROJECT_ID`, `MONGODB_ATLAS_PUBLIC_KEY`,
`MONGODB_ATLAS_PRIVATE_KEY`, `MONGODB_ATLAS_CLIENT_ID`,
`MONGODB_ATLAS_CLIENT_SECRET`.

The organization id is derived automatically from the accessible organizations
when `--org-id` is omitted.

## Discovery

Discovery is controlled with `--discover`:

- `auto` / `all` (default) discovers every project.
- `projects` is the explicit project target.

## Examples

Organization plane:

```shell
# Organizations that do not require multi-factor authentication
mql shell mongodbatlas --org-id <id> --public-key <pub> --private-key <priv> \
  -c "mongodbatlas.multiFactorAuthRequired"

# API keys and their roles
cnspec run mongodbatlas ... -c "mongodbatlas.apiKeys { publicKey roles }"
```

Project plane (run against a discovered project asset):

```shell
# Clusters without customer-managed encryption at rest
cnspec run mongodbatlas --project-id <id> --public-key <pub> --private-key <priv> \
  -c "mongodbatlas.clusters.where(encryptionAtRestProvider == 'NONE')"

# Database users authenticating with SCRAM passwords rather than X.509 or IAM
cnspec run mongodbatlas ... \
  -c "mongodbatlas.databaseUsers.where(x509Type == 'NONE' && awsIAMType == 'NONE')"

# Open IP access list entries
cnspec run mongodbatlas ... \
  -c "mongodbatlas.ipAccessList.where(cidrBlock == '0.0.0.0/0')"
```
