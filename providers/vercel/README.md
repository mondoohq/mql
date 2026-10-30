# Vercel Provider

Query configuration and security posture of your Vercel teams and projects.

## Authentication

The provider authenticates with a Vercel API token. Create one at
<https://vercel.com/account/tokens>. Grant the token access to the teams you want
to scan.

Provide the token in one of two ways:

```bash
# flag
mql shell vercel --token <access_token>

# environment variable (VERCEL_TOKEN or VERCEL_API_TOKEN)
export VERCEL_TOKEN=<access_token>
mql shell vercel
```

## Discovery

Connecting to `vercel` discovers two kinds of assets:

- **`vercel-team`** — every team the token can access (one asset per team).
- **`vercel-project`** — every project within those teams.

Scope discovery with `--discover`:

```bash
cnspec scan vercel --token <access_token> --discover teams
cnspec scan vercel --token <access_token> --discover projects
```

Restrict to a single team with `--team` (slug or ID):

```bash
cnspec scan vercel --token <access_token> --team acme
```

## Examples

```coffee
# Teams that do not enforce SAML single sign-on
vercel.teams.where(samlEnforced == false) { slug name }

# Projects whose preview deployments are publicly reachable
vercel.projects.where(ssoProtectionDeploymentType == null && passwordProtectionDeploymentType == null) { name }

# Plaintext environment variables that look like secrets
vercel.projects {
  environmentVariables.where(type == "plain" && key.contains("KEY")) { key target }
}

# Non-expiring API tokens
vercel.accessTokens.where(expiresAt == null) { name origin }

# Webhooks and log drains delivering over cleartext endpoints
vercel.teams {
  webhooks.where(url.contains("http://")) { url }
  logDrains.where(url.contains("http://")) { name url }
}
```

## Notes

- Some resources (access groups, the configurable Web Application Firewall) are
  Enterprise-plan features. On Hobby and Pro plans they return empty or null
  rather than failing the scan.
- Environment variable values are never fetched; only key, type, and target are
  exposed.
- Personal-account projects (projects not owned by a team) are not currently
  discovered. Use a team-owned project or the `--team` flag.
