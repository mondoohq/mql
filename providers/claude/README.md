# Claude Provider

The Claude provider queries the Claude Developer Platform API for security
posture, compliance, and AI Bill of Materials (AIBOM) data. It covers the
Models API (stable), Beta services (agents, environments, sessions, files,
skills, vaults, memory stores, message batches, user profiles), and the Admin
API (organizations, workspaces, members, invites, API keys, rate limits, usage,
cost, activities, encryption keys, compliance settings, and the Claude
Enterprise RBAC, spend limit, and plugin APIs).

## Authentication

The provider supports two authentication mechanisms for the standard API and a
separate admin key for organization management.

### Option 1: API Key

Create an API key in the [Claude Console](https://console.anthropic.com/) under
Settings > API Keys. Use a **read-only** key for least-privilege access.

```bash
# Via flag
mql shell claude --token sk-ant-api03-...

# Via environment variable
export ANTHROPIC_API_KEY=sk-ant-api03-...
mql shell claude
```

### Option 2: Workload Identity Federation (WIF)

WIF uses short-lived OIDC tokens instead of static API keys. This is the
recommended approach for CI/CD pipelines and cloud workloads. The Go SDK
auto-detects federation credentials from environment variables, or you can pass
them as flags.

**Prerequisites** (configured once in the Claude Console under Settings >
Service Accounts):

1. Create a **service account** (`svac_...`)
2. Register an **OIDC issuer** (your identity provider's URL and JWKS endpoint)
3. Create a **federation rule** (`fdrl_...`) that maps JWT claims to the service
   account

#### Google Cloud (local machine or GCE/Cloud Run)

```bash
# Generate an identity token with gcloud
gcloud auth print-identity-token \
  --audiences="https://api.anthropic.com" > /tmp/gcp-identity-token

# Use with flags
mql shell claude \
  --identity-token-file /tmp/gcp-identity-token \
  --federation-rule-id fdrl_... \
  --organization-id org_...

# Or use environment variables
export ANTHROPIC_IDENTITY_TOKEN_FILE=/tmp/gcp-identity-token
export ANTHROPIC_FEDERATION_RULE_ID=fdrl_...
export ANTHROPIC_ORGANIZATION_ID=org_...
mql shell claude
```

#### AWS (EC2, Lambda, ECS)

AWS workloads can use IAM role credentials to obtain identity tokens:

```bash
# The SDK reads the token from a file; write it from the AWS metadata endpoint
curl -s http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance \
  > /tmp/aws-identity-token

export ANTHROPIC_IDENTITY_TOKEN_FILE=/tmp/aws-identity-token
export ANTHROPIC_FEDERATION_RULE_ID=fdrl_...
export ANTHROPIC_ORGANIZATION_ID=org_...
mql shell claude
```

#### GitHub Actions

```yaml
permissions:
  id-token: write

steps:
  - uses: actions/github-script@v7
    id: token
    with:
      script: |
        const token = await core.getIDToken('https://api.anthropic.com');
        core.setOutput('token', token);

  - run: |
      echo "${{ steps.token.outputs.token }}" > /tmp/gh-identity-token
      mql shell claude \
        --identity-token-file /tmp/gh-identity-token \
        --federation-rule-id fdrl_... \
        --organization-id org_...
```

#### Kubernetes

Mount a projected service account token and point the provider at it:

```yaml
volumes:
  - name: anthropic-token
    projected:
      sources:
        - serviceAccountToken:
            audience: https://api.anthropic.com
            expirationSeconds: 3600
            path: token
```

```bash
export ANTHROPIC_IDENTITY_TOKEN_FILE=/var/run/secrets/anthropic.com/token
export ANTHROPIC_FEDERATION_RULE_ID=fdrl_...
export ANTHROPIC_ORGANIZATION_ID=org_...
mql shell claude
```

#### WIF Environment Variables

The Go SDK auto-detects these without any flags:

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_FEDERATION_RULE_ID` | Yes | Federation rule ID (`fdrl_...`) |
| `ANTHROPIC_ORGANIZATION_ID` | Yes | Organization ID |
| `ANTHROPIC_IDENTITY_TOKEN_FILE` | Yes* | Path to JWT file |
| `ANTHROPIC_IDENTITY_TOKEN` | Yes* | Literal JWT string (alternative to file) |
| `ANTHROPIC_SERVICE_ACCOUNT_ID` | No | Service account (`svac_...`) |
| `ANTHROPIC_WORKSPACE_ID` | No | Scope token to a workspace (`wrkspc_...`) |

*One of `ANTHROPIC_IDENTITY_TOKEN_FILE` or `ANTHROPIC_IDENTITY_TOKEN` is required.

### Admin API Key

Organization resources (workspaces, members, invites, API keys, rate limits,
usage, cost, activities, encryption keys, RBAC, spend limits, plugins) require
an Admin API key. RBAC groups and roles, effective spend limits, plugins, and
plugin marketplaces are available to Claude Enterprise organizations only; on
other organizations those fields report an error instead of an empty list. The plugin
endpoints need a key with the `read:plugins` or `read:org_audit` scope. Admin keys can only be
created by organization admins and are always read-write (no read-only option
exists). The provider uses only read operations.

```bash
# Via flag
mql shell claude --token sk-ant-api03-... --admin-token sk-ant-admin01-...

# Via environment variables
export ANTHROPIC_API_KEY=sk-ant-api03-...
export ANTHROPIC_ADMIN_API_KEY=sk-ant-admin01-...
mql shell claude
```

Admin keys work alongside both API key and WIF authentication for the standard
API.

## Usage

```bash
# Models and beta resources (API key or WIF)
mql shell claude --token sk-ant-api03-...
> claude.models { id displayName family maxTokens }
> claude.model(id: "claude-sonnet-4-6") { vendor family thinkingSupported }
> claude.agents { id name model }
> claude.environments { id name scope }
> claude.sessions { id title status }
> claude.files { id filename mimeType sizeBytes }
> claude.skills { id displayTitle source }
> claude.vaults { id displayName credentials { displayName } }
> claude.memoryStores { id name }
> claude.messageBatches { id processingStatus }
> claude.userProfiles { id name relationship }

# Organization resources (requires admin token)
mql shell claude --admin-token sk-ant-admin01-...
> claude.organization { id name }
> claude.organization.workspaces { id name workspaceGeo }
> claude.organization.members { id name email role }
> claude.organization.invites { id email role status }
> claude.organization.apiKeys { id name status createdBy { name } workspace { name } }
> claude.organization.rateLimits { groupType models requestsPerMinute }
> claude.organization.usageReport { startingAt model workspaceId outputTokens }
> claude.organization.costReport { startingAt amount costType workspaceId }
> claude.organization.externalKeys { id provider attached workspaces { name } }
> claude.organization.complianceApiState

# Claude Enterprise organizations only
> claude.organization.rbacGroups { name sourceType roles { name } members { email } }
> claude.organization.rbacRoles { name permissions { resourceType action } }
> claude.organization.effectiveSpendLimits { actorEmail period amount periodToDateSpend sourceType }
> claude.organization.plugins { name reach installationPreference contentScanAssessment components { type name } }
> claude.organization.pluginMarketplaces { name source syncStatus }

# Combined: both standard and admin resources
mql shell claude --token sk-ant-api03-... --admin-token sk-ant-admin01-...
```

## Discovery

When an admin token is provided, the provider discovers the organization and its
workspaces as separate assets with distinct platform IDs:

```bash
# Discover org + workspaces
mql shell claude --admin-token sk-ant-admin01-... --discover all
```

Discovery targets: `all`, `auto`, `organization`, `workspaces`.

## Resource Scoping

| Key type | Resources |
|----------|-----------|
| Standard API key / WIF | `claude.models`, `claude.agents`, `claude.environments`, `claude.sessions`, `claude.files`, `claude.skills`, `claude.vaults`, `claude.memoryStores`, `claude.messageBatches`, `claude.userProfiles` |
| Admin API key | `claude.organization` (workspaces, members, invites, apiKeys, rateLimits, usageReport, costReport, activities, externalKeys, complianceApiState, rbacGroups, rbacRoles, effectiveSpendLimits, plugins, pluginMarketplaces) |

Standard API keys are workspace-scoped — each key accesses resources in one
workspace. To scan multiple workspaces, either run separate scans per workspace
or use the admin key for organization-level visibility (the admin key cannot
access workspace-level standard API resources like models or agents).

## Credential Chain

When no explicit `--token` is provided, the SDK resolves credentials in this
order:

1. `ANTHROPIC_API_KEY` environment variable
2. `ANTHROPIC_AUTH_TOKEN` environment variable
3. `ANTHROPIC_PROFILE` named profile
4. WIF environment variables (`ANTHROPIC_FEDERATION_RULE_ID` + `ANTHROPIC_ORGANIZATION_ID` + identity token)
5. Default profile (`~/.config/anthropic/`)

## Verification

Verify your setup by running a few quick queries:

```bash
# Standard API key — list available models
mql shell claude --token sk-ant-api03-...
> claude.models { id displayName }

# Admin key — check organization info
mql shell claude --admin-token sk-ant-admin01-...
> claude.organization { id name }
> claude.organization.members { name email role }

# Combined — both standard and admin resources in one session
mql shell claude --token sk-ant-api03-... --admin-token sk-ant-admin01-...
> claude.models.length
> claude.organization.workspaces { name }
```

If any query returns an error, check the Troubleshooting section below.

## Troubleshooting

**"no credentials provided"** — No API key, admin key, or WIF configuration
was detected. Set `--token`, `--admin-token`, `ANTHROPIC_API_KEY`, or configure
WIF environment variables.

**"admin API key required"** — You queried an organization resource
(`claude.organization.*`) without providing `--admin-token` or setting
`ANTHROPIC_ADMIN_API_KEY`.

**"401 Unauthorized"** — The API key is invalid or revoked. Verify it in the
[Claude Console](https://console.anthropic.com/) under Settings > API Keys.

**"403 Forbidden"** — The key lacks permission for the requested resource. Admin
endpoints require an admin key; standard endpoints require a workspace-scoped
key. Compliance activity access may require a separate Compliance Access Key.

**"404 Not Found" on beta resources** — Some beta endpoints (e.g., user
profiles) are not available on all accounts or plans. The provider returns an
empty result with a "no data available" message rather than failing the scan.

**Empty workspace discovery** — Ensure you are using an admin token.
Standard API keys are workspace-scoped and cannot enumerate other workspaces.

**WIF "invalid federation rule"** — Verify the federation rule ID format
(`fdrl_...`) and that the rule is active in the Claude Console under
Settings > Service Accounts.

**WIF "identity token expired"** — OIDC tokens are short-lived (typically
one hour). Re-fetch the token from your identity provider before retrying.

## Security Considerations

- Use **read-only API keys** when possible — the provider only performs read
  operations
- Prefer **WIF over static API keys** in automated environments (CI/CD, cloud
  workloads) for short-lived credentials
- The Admin API key has no read-only option; the provider only calls GET/LIST
  endpoints but the key itself has write permissions — store it securely
- Identity token files should have restrictive permissions (`chmod 600`)
