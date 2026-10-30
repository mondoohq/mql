# DigitalOcean Provider

Query and assess your DigitalOcean account: Droplets, Kubernetes (DOKS), managed databases, Spaces, load balancers, firewalls, VPCs, App Platform, Functions, the container registry, GradientAI, and more.

## Prerequisites

You need a DigitalOcean **personal access token (PAT)**:

1. Go to **DigitalOcean Control Panel > API > Tokens** and generate a new token.
2. A **read-only** token is sufficient for inventory and assessment. DigitalOcean also supports [custom-scoped tokens](https://docs.digitalocean.com/reference/api/create-personal-access-token/) if you want to restrict the token to specific resource types.

Auditing **Spaces** buckets additionally requires a Spaces access key/secret pair (see below), because Spaces uses the S3-compatible API rather than the DigitalOcean API.

## Authentication

### Environment variables (recommended)

```bash
export DIGITALOCEAN_TOKEN="<your-api-token>"

# Optional — only needed to audit Spaces buckets (S3-compatible API):
export DIGITALOCEAN_SPACES_KEY="<spaces-access-key>"
export DIGITALOCEAN_SPACES_SECRET="<spaces-secret>"
# Optional — restrict Spaces bucket listing to a single region; otherwise
# the provider iterates the known Spaces regions:
export DIGITALOCEAN_SPACES_REGION="nyc3"
```

### CLI flag

```bash
cnspec shell digitalocean --token <api-token>
```

If `DIGITALOCEAN_TOKEN` is set, you can omit the flag:

```bash
cnspec shell digitalocean
```

## Discovery

The provider connects to the account as a single asset and can expand it into child assets. Pass discovery targets with `--discover`:

| Target | Expands into |
|---|---|
| `auto` (default) | The account asset |
| `all` | Everything below |
| `databases` | Managed database clusters |
| `kubernetes` | DOKS clusters |
| `loadbalancers` | Load balancers |
| `firewalls` | Cloud firewalls |
| `spaces-buckets` | Spaces buckets (requires Spaces credentials) |
| `gradientai-agents` | GradientAI agents |

```bash
cnspec shell digitalocean --discover all
```

### Filters

`--filters` narrows which objects become assets. The same filters apply to the
corresponding MQL listings, so a filtered scan and a plain query return the same
resources.

| Filter | Selects |
|---|---|
| `regions=nyc1,sfo3` | Only resources in the listed regions |
| `exclude:regions=ams3` | Drops resources in the listed regions |
| `tags=production,web` | Only resources carrying at least one of the listed tags |
| `exclude:tags=temporary` | Drops resources carrying any of the listed tags |

```bash
cnspec scan digitalocean --discover all --filters tags=production --filters exclude:regions=ams3
```

DigitalOcean tags are flat labels rather than key/value pairs, so the tag filters
take a list of tag names. Two consequences are worth knowing:

- **Cloud firewalls are account-global** and have no region, so a region filter
  never drops them — a global firewall applies in every selected region.
- **Spaces buckets cannot be tagged**, so an include-tag filter (`tags=...`)
  excludes every bucket.

## Examples

Launch an interactive shell and run queries:

```bash
cnspec shell digitalocean
```

List Droplets and flag any without a firewall:

```mql
digitalocean.droplets.where(missingFirewall)
```

Find internet-reachable Droplets:

```mql
digitalocean.droplets.where(exposure.internetReachable)
```

Check managed databases reachable from the internet:

```mql
digitalocean.databases.where(internetReachable)
```

Review what each managed-database user is authorized to do, beyond its
cluster-wide role:

```mql
digitalocean.databases { name engine users { name role authPlugin kafkaAcls opensearchAcls } }
```

See what actually sits in each project, including anything left in the default one:

```mql
digitalocean.projects { name isDefault resources { urn resourceType assignedAt } }
```

Review App Platform deployment history and configured alerts:

```mql
digitalocean.apps { name deployments { phase cause createdAt } alerts { rule disabled } }
```

Audit web-exported Functions that don't require an API key:

```mql
digitalocean.functionNamespaces.functions.where(webExported && requiresApiKey == false)
```

Inspect Kubernetes clusters and their node pools:

```mql
digitalocean.kubernetesClusters { name version nodePools { name size count } }
```

Find Kubernetes API servers reachable from any address:

```mql
digitalocean.kubernetesClusters.where(exposure.internetReachable) { name endpoint controlPlaneFirewallEnabled }
```

Find Spaces buckets anyone can read, and separate out those opened by policy
rather than by ACL:

```mql
digitalocean.spacesBuckets.where(isPublic) { name region publicReadAcl hasWildcardPolicy }
```

Find functions anyone on the internet can invoke, with the endpoint they answer on:

```mql
digitalocean.functionNamespaces.functions.where(isPublic) { name webUrl }
```

Find GradientAI agents and App Platform apps serving the internet:

```mql
digitalocean.gradientai.agents.where(isPublic) { name deploymentUrl }
digitalocean.apps.where(isPublic) { name liveUrl }
```

Find load balancer listeners accepting traffic in the clear, and inspect the
certificate each TLS listener presents:

```mql
digitalocean.loadBalancers.listeners.where(entryProtocol == "http" || entryProtocol == "tcp")
digitalocean.loadBalancers { name listeners { entryProtocol entryPort certificate { name notAfter state } } }
```

Find CORS policies that allow credentials from a permissive origin:

```mql
digitalocean.apps.where(corsPolicies.any(_["allowCredentials"] == true))
```

Find app environment variables held in plain text rather than encrypted:

```mql
digitalocean.apps { name envVars.where(_["type"] == "GENERAL") }
```

You can also run a policy scan:

```bash
cnspec scan digitalocean
```

## Notes

- **Spaces** resources return an empty list unless `DIGITALOCEAN_SPACES_KEY` and `DIGITALOCEAN_SPACES_SECRET` are set.
- **Functions** are backed by Apache OpenWhisk. Listing the functions (actions) deployed in a namespace reaches the namespace's Functions API host using credentials retrieved from the DigitalOcean API.
- Resources the token cannot read (for example, a scoped token) are handled gracefully where possible.
