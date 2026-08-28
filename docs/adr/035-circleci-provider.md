# ADR-035: CircleCI Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

CircleCI is a widely used CI/CD platform, and the mql provider ecosystem already models adjacent CI/CD and SCM surfaces (GitHub, GitLab). CI/CD pipelines are a high-value security surface: they hold long-lived cloud credentials in contexts and project environment variables, they can be configured to build forked pull requests and (worse) hand those forked builds the org's secrets, and they hold deploy keys that grant repository access. None of that is currently queryable in mql. CircleCI's REST API v2 is stable, well-documented, and requires only a single API token, no OAuth flow, making it a good-sized addition comparable in scope to the DigitalOcean provider (ADR-003).

Unlike DigitalOcean, CircleCI has no official Go SDK, so this provider follows the client-selection priority ladder rather than defaulting to a hand-written HTTP layer. Rung 1 (official vendor SDK) does not apply: CircleCI does not publish one. Rung 2 applies: CircleCI publishes a machine-readable OpenAPI spec for API v2 at `https://circleci.com/api/v2/openapi.json` (also available as `openapi.yml`), described as OpenAPI 3.0.0 in its `info` block, not the older Swagger 2.0 format. Multiple third-party clients (`suzuki-shunsuke/go-circleci-v2-openapi-client` for Go, `cob16/circleci-typescript-axios` for TypeScript) are already generated straight from this spec via `openapi-generator`, confirming it is complete enough to codegen against. This ADR therefore calls for a generated client over both the hand-written `net/http` option (rung 3) and the community `github.com/grezar/go-circleci` client, which is hand-maintained rather than spec-generated and does not fully track the spec. Rung 2 also requires harmonizing the resource model with CircleCI's Terraform provider where one exists; see the alignment note below.

**Terraform provider alignment.** CircleCI publishes an official Terraform provider at [`CircleCI-Public/terraform-provider-circleci`](https://github.com/CircleCI-Public/terraform-provider-circleci), built on the HashiCorp plugin framework. As of this writing it is early-stage and exposes a single resource, `circleci_project`, with `name` and `organization_id` arguments; there is no official Terraform coverage yet for contexts, environment variables, or checkout keys. This ADR aligns `circleci.project`'s `name` field and its `organization()` reference (backed by `organization_id`) with that resource's shape, since that is the one place a documented naming precedent exists. The remaining resources (`circleci.context`, `circleci.checkoutKey`, the environment variable sub-resources) follow mql's own naming conventions in the absence of a Terraform precedent to harmonize with; revisit this alignment if the official provider's coverage grows.

A defining constraint shapes the resource model: CircleCI's API deliberately never returns environment variable values. Context environment variables return only the variable name, its context, and a creation timestamp. Project environment variables return the name and a masked value (the last four characters, e.g. `xxxx1234`). This is not a modeling gap to work around; it is the security boundary the API enforces, and the resource schema below mirrors it rather than inventing a `value` field that can never be populated.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `circleci` |
| **Provider ID** | `go.mondoo.com/mql/providers/circleci` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `circleci` |
| **Go SDK** | None official. Generated client via `openapi-generator` (`go` generator) from CircleCI's published OpenAPI 3.0.0 spec (`https://circleci.com/api/v2/openapi.json`); vendored under `providers/circleci/gen-client/`. The community `github.com/grezar/go-circleci` was considered and rejected (hand-maintained, incomplete spec coverage). |
| **API Type** | REST (CircleCI API v2) |
| **Auth** | Personal or project API token via the `Circle-Token` header (`CIRCLECI_TOKEN` env var or `--token` flag) |

---

## Directory Structure

```
providers/circleci/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── gen-client/                     # generated: openapi-generator output (vendored, not hand-edited)
│   ├── openapi.yml                 # pinned copy of CircleCI's published spec
│   ├── api_default.go
│   ├── client.go
│   ├── configuration.go
│   └── model_*.go
├── config/
│   └── config.go
├── connection/
│   └── connection.go
├── provider/
│   └── provider.go
└── resources/
    ├── circleci.lr
    ├── circleci.lr.go              # generated
    ├── circleci.lr.versions        # generated
    ├── discovery.go
    ├── circleci.go                 # root resource + current user
    ├── organization.go
    ├── project.go
    ├── context.go
    └── checkoutkey.go
```

---

## Resource Schema (`circleci.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/circleci"
option go_package = "go.mondoo.com/mql/v13/providers/circleci/resources"

// CircleCI CI/CD platform
//
// Root resource for a CircleCI account, reached through the token used to
// authenticate the connection. Provides the current authenticated user,
// the organizations the token can see, and the projects and contexts
// underneath them. Use it to audit pipeline secrets exposure (contexts,
// project environment variables), source access (checkout keys), and
// pull-request build settings (forked-PR builds, OIDC) across an
// organization's CircleCI footprint.
circleci {
  // Currently authenticated user
  me() circleci.user
  // Organizations the current token can see
  organizations() []circleci.organization
  // Projects across all visible organizations
  projects() []circleci.project
  // Contexts across all visible organizations
  contexts() []circleci.context
}

// CircleCI user account
private circleci.user @defaults("login") {
  // User ID
  id string
  // VCS login (GitHub or Bitbucket username)
  login string
  // Display name
  name string
}

// CircleCI organization
//
// A CircleCI organization as visible to the authenticated token, keyed by
// its `id` (a UUID, not the display slug). Organizations own projects and
// contexts. SSO enforcement and other identity-provider settings are
// configured in CircleCI's org-level UI and are not exposed by API v2, so
// this resource cannot confirm SSO is enforced; treat that as a manual
// control until CircleCI exposes it.
circleci.organization @defaults("name") {
  // Organization ID (UUID)
  id string
  // Organization name (slug)
  name string
  // VCS type backing the organization (github, bitbucket, circleci)
  vcsType string
  // Projects owned by the organization
  projects() []circleci.project
  // Contexts owned by the organization
  contexts() []circleci.context
}

// CircleCI project
//
// A CircleCI project, one per repository connected to an organization.
// The `id` field is the project's UUID. Exposes the project's version
// control linkage, its checkout keys (the deploy credentials CircleCI
// uses to clone the repository), its own environment variables, and the
// advanced settings that control whether forked pull requests can
// trigger builds and whether those builds receive the project's secrets.
circleci.project @defaults("name") {
  // Project ID (UUID)
  id string
  // Project name (repository name)
  name string
  // Organization that owns the project
  organization() circleci.organization
  // VCS provider info (provider, external ID)
  vcsInfo dict
  // Default branch
  defaultBranch string
  // Environment variables defined directly on the project
  environmentVariables() []circleci.project.environmentVariable
  // Checkout keys used to clone the repository
  checkoutKeys() []circleci.checkoutKey
  // Whether the project builds pull requests opened from forks
  buildForkPrs bool
  // Whether forked pull request builds receive the project's secret environment variables and context values
  forksReceiveSecretEnvVars bool
  // Whether only pull request commits trigger builds (as opposed to every push)
  buildPrsOnly bool
  // Whether project settings changes require organization admin permissions
  writeSettingsRequiresAdmin bool
  // Whether SSH access to build containers is disabled
  disableSsh bool
  // Whether the project's status is reported back to the VCS provider (commit statuses / checks)
  setGithubStatus bool
}

// CircleCI project environment variable
//
// A single environment variable set on a project, identified by its
// `name`. CircleCI's API never returns environment variable values; the
// `maskedValue` field holds only the truncated, non-secret suffix
// CircleCI itself returns (for example `xxxx1234`), which exists to help
// operators recognize which value is configured, not to reveal it. Treat
// the absence of a `value` field as intentional: it cannot be modeled
// because the API does not provide it.
private circleci.project.environmentVariable @defaults("name") {
  // Variable name
  name string
  // Project ID (parent)
  projectId string
  // Truncated, non-secret suffix of the value as returned by the API (e.g. "xxxx1234")
  maskedValue string
}

// CircleCI checkout key
//
// A deploy credential CircleCI uses to check out a project's source
// code, identified by its `fingerprint`. The `type` field is the
// security-relevant one: a `deploy-key` is scoped to the single
// repository, while a `user-key` inherits the permissions of the
// CircleCI user who created it, including access to every other
// repository that user can reach. Prefer deploy keys; a user-key on a
// project is broader access than the project itself needs.
circleci.checkoutKey @defaults("type fingerprint") {
  // Public key fingerprint (SHA256, colon-delimited)
  fingerprint string
  // Project ID (parent)
  projectId string
  // Key type: deploy-key (repo-scoped) or user-key (inherits the creating user's access)
  type string
  // Public key contents
  publicKey string
  // Whether CircleCI prefers this key when multiple keys are present
  preferred bool
  // Creation time
  createdAt time
}

// CircleCI context
//
// A named group of environment variables shared across projects, keyed
// by its `id`. Contexts are the preferred place to store long-lived
// cloud credentials because access to them can be restricted by security
// group, unlike project-level environment variables which any project
// collaborator can use. The `environmentVariables` field lists the
// variable names configured in the context; CircleCI's API never returns
// context environment variable values under any circumstance.
circleci.context @defaults("name") {
  // Context ID (UUID)
  id string
  // Context name
  name string
  // Organization that owns the context
  organization() circleci.organization
  // Creation time
  createdAt time
  // Environment variables configured in the context (names only, no values)
  environmentVariables() []circleci.context.environmentVariable
}

// CircleCI context environment variable
//
// A single environment variable name configured in a context, identified
// by `variable`. CircleCI's API does not return context environment
// variable values in any form, not even masked or truncated: contexts
// are the platform's mechanism for handing a value to a build without
// ever making it readable back out through the API. A security audit of
// contexts should focus on which variables exist and which security
// groups can access the context, not on inspecting values that are
// architecturally unavailable.
private circleci.context.environmentVariable @defaults("variable") {
  // Variable name
  variable string
  // Context ID (parent)
  contextId string
  // Creation time
  createdAt time
}
```

---

## Authentication

Single API token, same pattern as Shodan (`providers/shodan/connection/connection.go`) and DigitalOcean (`providers/digitalocean/connection/connection.go`), but configured through the generated client's `Configuration` type rather than an SDK-managed OAuth `http.Client`. `openapi-generator`'s Go target emits a `Configuration` struct that accepts default headers, which is where the `Circle-Token` header is set once for every request the generated client issues:

```go
type CircleciConnection struct {
    plugin.Connection
    Conf   *inventory.Config
    asset  *inventory.Asset
    client *genclient.APIClient
}

func NewCircleciConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*CircleciConnection, error) {
    conn := &CircleciConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    token := os.Getenv("CIRCLECI_TOKEN")
    if len(conf.Credentials) > 0 {
        for _, cred := range conf.Credentials {
            if cred.Type == vault.CredentialType_password {
                token = string(cred.Secret)
            }
        }
    }
    if token == "" {
        return nil, errors.New("a valid CircleCI token is required (set CIRCLECI_TOKEN or use --token)")
    }

    cfg := genclient.NewConfiguration()
    cfg.Servers = genclient.ServerConfigurations{{URL: "https://circleci.com/api/v2"}}
    cfg.AddDefaultHeader("Circle-Token", token)
    conn.client = genclient.NewAPIClient(cfg)

    // Fail fast: validate the token against /me before handing back a
    // connection that would otherwise surface auth failures lazily on
    // the first resource query.
    if _, _, err := conn.client.DefaultApi.GetCurrentUser(context.Background()).Execute(); err != nil {
        return nil, errors.Wrap(err, "unable to authenticate with CircleCI")
    }

    return conn, nil
}
```

---

## Implementation Patterns

### Client Generation

The generated client is vendored, not fetched at build time, so provider builds do not depend on CircleCI's server being reachable or the spec being unchanged mid-build:

```bash
# Pin a copy of the spec, then generate into gen-client/
curl -o providers/circleci/gen-client/openapi.yml https://circleci.com/api/v2/openapi.yml
docker run --rm -v "${PWD}:/local" openapitools/openapi-generator-cli:v7.x generate \
  -i /local/providers/circleci/gen-client/openapi.yml \
  -g go \
  -o /local/providers/circleci/gen-client \
  --package-name genclient
gofmt -w providers/circleci/gen-client
```

Re-run this whenever CircleCI's spec changes (new endpoints, new fields on existing responses); commit both the pinned `openapi.yml` and the regenerated `gen-client/` output, the same way `.lr.go` is committed rather than generated at build time. Because the preview-era v2 spec has a history of breaking changes upstream, diff the regenerated output against the previous vendored copy before adopting it, not just against compile errors.

### Paginated List (all list APIs)

CircleCI API v2 pagination is token-based, not page-number-based: a list response carries `items` plus a `next_page_token` string, and that token is round-tripped back as the `page-token` query parameter until the response stops returning one. The generated client models this as a `NextPageToken` field on each generated `*Response` struct and a `PageToken` builder method on each list call, so the loop only has to shuttle that token, not hand-roll query string construction:

```go
func (c *mqlCircleci) organizations() ([]any, error) {
    conn := c.MqlRuntime.Connection.(*connection.CircleciConnection)
    api := conn.Client().DefaultApi

    var all []any
    pageToken := genclient.PtrString("")
    for {
        req := api.CollaborationsList(context.Background())
        if *pageToken != "" {
            req = req.PageToken(*pageToken)
        }
        orgs, _, err := req.Execute()
        if err != nil {
            return nil, err
        }

        for _, o := range orgs.Items {
            r, err := CreateResource(c.MqlRuntime, "circleci.organization", map[string]*llx.RawData{
                "__id":    llx.StringData(o.Id),
                "id":      llx.StringData(o.Id),
                "name":    llx.StringData(o.Name),
                "vcsType": llx.StringData(o.VcsType),
            })
            if err != nil {
                return nil, err
            }
            all = append(all, r)
        }

        if orgs.NextPageToken == nil || *orgs.NextPageToken == "" {
            break
        }
        pageToken = orgs.NextPageToken
    }
    return all, nil
}
```

### Security-by-Design Modeling: Never Model a Value the API Never Returns

Both environment variable resources deliberately have no `value` field, and this is not an oversight to "fix" during implementation:

- `circleci.context.environmentVariable` — the List Environment Variables in Context endpoint returns only `variable`, `context_id`, and `created_at`. No value, masked or otherwise, exists anywhere in the response schema.
- `circleci.project.environmentVariable` — the project environment variables endpoint returns `name` and a `value` field that is already truncated by CircleCI to a non-secret suffix (e.g. `xxxx1234`); that field is exposed here as `maskedValue`, named to make clear it is not the real secret.

Do not add a full `value string` field to either resource "for completeness," and do not attempt to reconstruct or unmask the value client-side. If a future API version adds a genuine masked-value response for context variables, extend `circleci.context.environmentVariable` with the same `maskedValue` field used on the project resource, keeping the naming consistent, rather than retrofitting a `value` field onto either.

### Typed Resource References (via Internal struct)

Projects and contexts both reference an owning organization by ID; expose it as a typed accessor rather than a raw `organizationId` string, following the Step 1.5 typed-reference gate:

```go
type mqlCircleciProjectInternal struct {
    cacheOrgId string
}

func (p *mqlCircleciProject) organization() (*mqlCircleciOrganization, error) {
    if p.cacheOrgId == "" {
        p.Organization.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    r, err := NewResource(p.MqlRuntime, "circleci.organization",
        map[string]*llx.RawData{"id": llx.StringData(p.cacheOrgId)})
    if err != nil {
        return nil, err
    }
    return r.(*mqlCircleciOrganization), nil
}
```

`circleci.checkoutKey.projectId` and `circleci.project.environmentVariable.projectId` stay as raw strings rather than a `project()` accessor: they identify the parent the sub-resource was expanded from, and the parent is already reachable by navigating `circleci.project.checkoutKeys` / `circleci.project.environmentVariables` in the first place, so a back-reference accessor would only round-trip an ID the caller already has.

### Child Resource Expansion (project advanced settings)

CircleCI returns project advanced settings (`build_fork_prs`, `forks_receive_secret_env_vars`, `oidc_token_org_wide_enabled`, and friends) inline on the project detail response rather than as a separate collection, so they are flattened directly onto `circleci.project` as scalar fields per the "no single-scalar sub-resource" rule, not modeled as a `circleci.project.advancedSettings` sub-resource:

```go
func (p *mqlCircleciProject) populateFromModel(pj genclient.Project) error {
    settings := pj.AdvancedSettings
    p.BuildForkPrs = plugin.TValue[bool]{Data: settings.GetBuildForkPrs(), State: plugin.StateIsSet}
    p.ForksReceiveSecretEnvVars = plugin.TValue[bool]{Data: settings.GetForksReceiveSecretEnvVars(), State: plugin.StateIsSet}
    p.BuildPrsOnly = plugin.TValue[bool]{Data: settings.GetBuildPrsOnly(), State: plugin.StateIsSet}
    p.WriteSettingsRequiresAdmin = plugin.TValue[bool]{Data: settings.GetWriteSettingsRequiresAdmin(), State: plugin.StateIsSet}
    p.DisableSsh = plugin.TValue[bool]{Data: settings.GetDisableSsh(), State: plugin.StateIsSet}
    p.SetGithubStatus = plugin.TValue[bool]{Data: settings.GetSetGithubStatus(), State: plugin.StateIsSet}
    return nil
}
```

(`Get*` accessors on the generated model are `openapi-generator`'s standard nil-safe pattern for optional fields; prefer them over dereferencing the underlying `*bool` pointers directly, consistent with the "match SDK types faithfully" nil-handling rule.)

Org-wide OIDC configuration (`GET /org/{orgID}/oidc-custom-claims`) is a separate, org-scoped endpoint rather than a per-project field; a future iteration can add it as `circleci.organization.oidcCustomClaims dict` once the initial resource set ships, since it is not required for the MVP security policies below.

---

## Security Policies (MVP)

Ship as `mondoo-circleci-security.mql.yaml`:

**Pull Request Build Security:**
- Projects must not pass secret environment variables to forked pull request builds (`forksReceiveSecretEnvVars == false`)
- Projects that build forked pull requests should require an explicit review gate; flag `buildForkPrs == true && forksReceiveSecretEnvVars == true` as high severity

**Source Access Security:**
- Checkout keys must be deploy keys, not user keys (`type == "deploy-key"`), since a user-key on any one project grants that project's build access to every other repository the creating user can reach

**Project Settings Security:**
- Projects must require organization admin permissions to change settings (`writeSettingsRequiresAdmin == true`)
- Projects should have SSH access to build containers disabled unless explicitly needed for debugging (`disableSsh == true`)

**Context Security:**
- Contexts should be preferred over project-level environment variables for credentials that grant cloud access, since contexts support security-group restriction and project environment variables do not; this is a repo-hygiene check (does a project define its own environment variables at all) rather than a value check, since values are never visible
- Flag organizations with a high ratio of project environment variables to context environment variables as candidates for migrating credentials into contexts

**Organizational Notes (not directly queryable):**
- SSO enforcement is configured outside CircleCI API v2 and cannot be asserted from this provider; note it as an out-of-band control in policy documentation rather than a check
- Preferring OIDC (workload identity federation to AWS/GCP/Azure) over long-lived cloud keys stored in contexts is a design recommendation to surface in policy guidance text; API v2 does not expose which context variables are OIDC-adjacent versus static credentials, so it cannot be scored automatically in the MVP

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/circleci` in `go.work` list
4. **`Makefile`** — `circleci` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/circleci/resources/circleci.lr \
  --dist providers/circleci/resources

# Build and install
make providers/build/circleci && make providers/install/circleci

# Test
export CIRCLECI_TOKEN="cci-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mql shell circleci
> circleci.me
> circleci.organizations { name vcsType }
> circleci.projects { name buildForkPrs forksReceiveSecretEnvVars writeSettingsRequiresAdmin }
> circleci.projects.where( forksReceiveSecretEnvVars == true ) { name }
> circleci.contexts { name environmentVariables { variable } }
> circleci.projects.checkoutKeys { type fingerprint }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/circleci --provider-id circleci --provider-name "CircleCI"` then `cd providers/circleci && go mod tidy`
2. Pin the OpenAPI spec and generate `gen-client/` (see Client Generation above); commit both
3. Root + `me()` (validates auth against `/me` through the generated client)
4. Organizations (via `/me/collaborations`, validates org visibility)
5. Projects (core resource, includes flattened advanced settings, aligned with `circleci_project` in the Terraform provider)
6. Checkout keys (critical for source-access security policies)
7. Contexts + context environment variables (names only)
8. Project environment variables (masked values only)
9. Security policies
10. Discovery
11. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [CircleCI API v2 Documentation](https://circleci.com/docs/api/v2/)
- [CircleCI API v2 OpenAPI spec (OpenAPI 3.0.0)](https://circleci.com/api/v2/openapi.json) (also `openapi.yml`) — source spec for the generated client
- [CircleCI-Public/terraform-provider-circleci](https://github.com/CircleCI-Public/terraform-provider-circleci) — official Terraform provider, harmonization target for `circleci.project` naming
- [suzuki-shunsuke/go-circleci-v2-openapi-client](https://github.com/suzuki-shunsuke/go-circleci-v2-openapi-client) — prior art generating a Go client from the same spec via `openapi-generator`
- [OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) — codegen tool used to produce `gen-client/`
- [go-circleci community Go SDK](https://github.com/grezar/go-circleci) — considered, not used (see Context)
- [CircleCI: Using Contexts](https://circleci.com/docs/guides/security/contexts/)
- [CircleCI: Setting Project API Features](https://support.circleci.com/hc/en-us/articles/14992602955675-Setting-Project-API-Features)
- [CircleCI: Trigger Pipelines on Forked Pull Requests with API v2](https://support.circleci.com/hc/en-us/articles/360049841151-Trigger-Pipelines-on-Forked-Pull-Requests-with-CircleCI-API-v2)
- [CircleCI: OIDC Tokens with Custom Claims](https://circleci.com/docs/guides/permissions-authentication/oidc-tokens-with-custom-claims/)
- Reference providers: `providers/shodan/`, `providers/tailscale/`, `providers/digitalocean/`
