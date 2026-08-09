# ADR-034: Bitbucket Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Bitbucket Cloud is a widely used source-code hosting and CI/CD platform (part of the Atlassian suite) and, alongside GitHub and GitLab, rounds out coverage of the three major hosted Git platforms in mql. Its REST API 2.0 is well-documented and stable, covering workspaces, projects, repositories, branch restrictions, deploy keys, and permissions, and Atlassian publishes a machine-readable Swagger/OpenAPI description of the full surface, which this provider builds its client from rather than a hand-written HTTP layer (see "Client selection" below).

Bitbucket Cloud's security surface is organized around **workspaces** (the top-level container that used to be called a "team"), which enforce account-wide settings such as two-step verification and IP allowlisting; **projects**, which group related repositories and can carry inherited branch restrictions; and **repositories**, whose privacy, fork policy, branch restrictions, deploy keys, and default reviewers are the primary levers for repo-level hardening. This mirrors the modeling already done for `github` (organization / repository / branch protection) and `gitlab` (group / project / protected branch), so this ADR follows the same shape while matching Bitbucket's own vocabulary (workspace, not organization; branch restriction, not branch protection rule).

Authentication uses either a workspace- or repository-scoped **Access Token** (bearer, the currently recommended method) or the older **App Password** (HTTP Basic auth with a Bitbucket username), which keeps the connection story as simple as GitHub's and GitLab's personal-access-token flows.

**Client selection.** Atlassian does not publish an official Bitbucket Cloud Go SDK (rung 1 of the client-selection ladder is empty), so this provider does not use a vendor SDK. Bitbucket Cloud does publish a machine-readable API description at `https://api.bitbucket.org/swagger.json` (Swagger/OpenAPI 2.0, not 3.0 — Atlassian has not republished it as OpenAPI v3), so per rung 2 the provider generates its client from that spec rather than hand-writing HTTP calls or depending on the community `ktrysmt/go-bitbucket` package. Per rung 2(a), the resource and field modeling below is harmonized with the community Terraform provider `DrFaust92/terraform-provider-bitbucket` (`registry.terraform.io/providers/DrFaust92/bitbucket`) so cnspec and Terraform describe the same Bitbucket objects the same way; see "Terraform provider alignment" below.

**Terraform provider alignment.** `DrFaust92/terraform-provider-bitbucket` is the most actively maintained community Terraform provider for Bitbucket Cloud and models the same objects this ADR covers: `bitbucket_repository` (`is_private`, `fork_policy`, `mainbranch`, `project_key`), `bitbucket_branch_restriction` (`kind`, `pattern`, `value` for the minimum-approvals count), and `bitbucket_workspace_membership`/`bitbucket_group`. This ADR's `.lr` schema mirrors that vocabulary (`isPrivate`, `forkPolicy`, `mainBranch`, `kind`, `pattern`, `minApprovals`) rather than inventing parallel names, so a user who already has Bitbucket infrastructure described in Terraform can map cnspec query results back to `.tf` resources field-for-field.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `bitbucket` |
| **Provider ID** | `go.mondoo.com/mql/providers/bitbucket` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `bitbucket` |
| **Go SDK** | None official; client generated from the Bitbucket Cloud OpenAPI/Swagger 2.0 spec (`https://api.bitbucket.org/swagger.json`) via `openapi-generator` into `providers/bitbucket/internal/bbapi` (rung 2 of the client-selection ladder — see Context) |
| **API Type** | REST (Bitbucket Cloud API 2.0) |
| **Auth** | Workspace/repository Access Token (Bearer, `BITBUCKET_TOKEN` env var or `--token` flag) or App Password (Basic auth, `BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD` env vars or `--username`/`--app-password` flags); `BITBUCKET_WORKSPACE` env var or `--workspace` flag selects the default workspace to scan |

---

## Directory Structure

```
providers/bitbucket/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── config/
│   └── config.go
├── openapi/
│   └── swagger.json                # fetched Bitbucket Cloud API spec, checked in
├── internal/
│   └── bbapi/                      # generated client (openapi-generator), not hand-edited
├── connection/
│   └── connection.go
├── provider/
│   └── provider.go
└── resources/
    ├── bitbucket.lr
    ├── bitbucket.lr.go              # generated
    ├── bitbucket.lr.versions        # generated
    ├── discovery.go
    ├── bitbucket.go                 # root resource
    ├── bitbucket_workspace.go
    ├── bitbucket_project.go
    ├── bitbucket_repository.go
    ├── bitbucket_branchrestriction.go
    ├── bitbucket_deploykey.go
    ├── bitbucket_reviewer.go
    ├── bitbucket_user.go
    └── bitbucket_group.go
```

---

## Resource Schema (`bitbucket.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/bitbucket"
option go_package = "go.mondoo.com/mql/v13/providers/bitbucket/resources"

// Bitbucket
//
// Namespace root for Bitbucket Cloud queries, exposing workspaces,
// projects, repositories, branch restrictions, deploy keys, and the
// members and groups that hold access across the connected account.
bitbucket {
  // Workspace selected by the connection (BITBUCKET_WORKSPACE or --workspace)
  workspace() bitbucket.workspace
  // All workspaces the authenticated identity can access
  workspaces() []bitbucket.workspace
}

// Bitbucket workspace
//
// Top-level container for projects and repositories, keyed by its slug
// (for example `bitbucket.workspace(slug: "acme-corp")`). Workspace-wide
// settings are the primary control surface for account hardening: whether
// two-step verification is enforced for all members, whether an IP
// allowlist restricts access, and whether the workspace itself is
// private. Query `projects`, `repositories`, `members`, and `groups` to
// drill into what the workspace contains and who can reach it.
bitbucket.workspace @defaults("slug name") {
  // Workspace UUID
  id string
  // Workspace slug (URL-safe identifier)
  slug string
  // Workspace display name
  name string
  // Whether the workspace is private
  isPrivate bool
  // Whether two-step verification (2FA) is required for all workspace members
  enforceTwoStepVerification bool
  // Whether access to the workspace is restricted by an IP allowlist
  ipAllowlistEnabled bool
  // CIDR ranges permitted to access the workspace when the IP allowlist is enabled
  ipAllowlist []string
  // Creation time
  createdOn time
  // Projects in the workspace
  projects() []bitbucket.project
  // Repositories in the workspace
  repositories() []bitbucket.repository
  // Members of the workspace
  members() []bitbucket.member
  // Groups defined in the workspace
  groups() []bitbucket.group
}

// Bitbucket project
//
// Container that groups related repositories within a workspace, keyed
// by its key (for example `bitbucket.project(key: "ENG")`). Branch
// restrictions set at the project level are inherited by every
// repository in it unless a repository overrides them, which makes the
// project the place to check for organization-wide merge and push
// policy before looking at individual repositories.
bitbucket.project @defaults("key name") {
  // Project UUID
  id string
  // Project key
  key string
  // Project name
  name string
  // Whether the project is private
  isPrivate bool
  // Description
  description string
  // Workspace that owns this project
  workspace() bitbucket.workspace
  // Creation time
  createdOn time
  // Update time
  updatedOn time
  // Repositories in this project
  repositories() []bitbucket.repository
}

// Bitbucket repository
//
// Git repository hosted in a workspace, keyed by its full name (for
// example `bitbucket.repository(fullName: "acme-corp/api-service")`).
// Covers privacy (`isPrivate`), the default `mainBranch`, `forkPolicy`,
// and size, plus the security-relevant sub-resources `branchRestrictions`
// (required approvals, force-push and delete prevention), `deployKeys`,
// and `defaultReviewers`.
bitbucket.repository @defaults("fullName isPrivate") {
  // Repository UUID
  id string
  // Repository slug
  slug string
  // Full name (workspace/repo-slug)
  fullName string
  // Repository name
  name string
  // Description
  description string
  // Whether the repository is private
  isPrivate bool
  // Fork policy
  //
  // One of allow_forks (unrestricted forking), no_public_forks (forks
  // must be private), or no_forks (forking disabled entirely).
  forkPolicy string
  // Primary programming language detected by Bitbucket
  language string
  // Repository size in bytes
  size int
  // Whether the issue tracker is enabled
  hasIssues bool
  // Whether the wiki is enabled
  hasWiki bool
  // Name of the default (main) branch
  mainBranch string
  // Project this repository belongs to
  project() bitbucket.project
  // Workspace that owns this repository
  workspace() bitbucket.workspace
  // Creation time
  createdOn time
  // Update time
  updatedOn time
  // Branch restrictions configured on this repository
  branchRestrictions() []bitbucket.repository.branchRestriction
  // Deploy keys registered on this repository
  deployKeys() []bitbucket.deployKey
  // Default reviewers required on pull requests
  defaultReviewers() []bitbucket.member
}

// Bitbucket branch restriction
//
// A single merge or push rule applied to branches matching `pattern` on
// a repository (for example all restrictions where `pattern == "main"`).
// The `kind` field identifies what the rule restricts: `push` and
// `force` gate who can push or force-push, `delete` prevents branch
// deletion, `restrict_merges` limits who can merge, and
// `require_approvals_to_merge` (together with `minApprovals`) enforces a
// minimum reviewer count before a pull request can merge.
private bitbucket.repository.branchRestriction @defaults("kind pattern") {
  // Restriction ID
  id int
  // Repository this restriction applies to
  repository() bitbucket.repository
  // Restriction kind
  //
  // One of push, force, delete, restrict_merges,
  // require_tasks_to_be_completed, require_approvals_to_merge,
  // require_default_reviewer_approvals_to_merge, or
  // require_no_changes_requested.
  kind string
  // Branch name or glob pattern this restriction matches
  pattern string
  // Minimum number of approvals required (require_approvals_to_merge and
  // require_default_reviewer_approvals_to_merge)
  minApprovals int
  // Users exempted from this restriction
  users() []bitbucket.member
  // Groups exempted from this restriction
  groups() []bitbucket.group
}

// Bitbucket deploy key
//
// An SSH public key granted read (or read-write) access to clone a
// single repository without a full user account, commonly used by CI/CD
// systems and external integrations. A deploy key that is unexpectedly
// present, or one whose `label` doesn't map to a known integration, is a
// standing access path worth auditing independently of workspace and
// repository membership.
bitbucket.deployKey @defaults("label") {
  // Deploy key ID
  id int
  // Repository this key is registered on
  repository() bitbucket.repository
  // Label describing the key's purpose
  label string
  // Public key contents
  key string
  // Creation time
  createdOn time
  // Last time the key was used
  lastUsed time
}

// Bitbucket workspace or repository member
//
// A user with access to a workspace or repository, keyed by their
// account UUID (for example `bitbucket.member(id: "{...}")`). Combine
// with `permission` when read through
// `bitbucket.workspace.members` or `bitbucket.repository.defaultReviewers`
// to audit who holds admin or write access and flag accounts that no
// longer need it.
bitbucket.member @defaults("displayName") {
  // Account UUID
  id string
  // Username
  username string
  // Display name
  displayName string
  // Account type (user or team)
  accountType string
  // Permission level granted to this member
  //
  // One of read, write, or admin.
  permission string
}

// Bitbucket group
//
// A named collection of workspace members, keyed by its slug (for
// example `bitbucket.group(slug: "administrators")`). Groups are the
// unit branch restrictions and repository permissions reference instead
// of individual users, so auditing group membership surfaces broad
// grants that a per-user view would miss.
bitbucket.group @defaults("slug name") {
  // Group slug
  slug string
  // Group name
  name string
  // Workspace this group belongs to
  workspace() bitbucket.workspace
  // Default permission new repositories grant to this group
  permission string
  // Members of this group
  members() []bitbucket.member
}
```

---

## Authentication

No vendor SDK exists to carry auth, so the generated `bbapi` client is configured with a plain `http.RoundTripper` that sets the `Authorization` header: Bearer Access Token (preferred) or HTTP Basic App Password. This is the same credential-resolution shape as `providers/gitlab/connection/connection.go`, just wired into `bbapi.Configuration.HTTPClient` instead of an SDK constructor:

```go
type BitbucketConnection struct {
    plugin.Connection
    Conf      *inventory.Config
    asset     *inventory.Asset
    client    *bbapi.APIClient
    workspace string
}

// bitbucketAuthTransport injects either a bearer Access Token or HTTP Basic
// App Password credentials into every request made by the generated client.
type bitbucketAuthTransport struct {
    base        http.RoundTripper
    token       string // Access Token, sent as "Bearer <token>"
    username    string // App Password username (Basic auth)
    appPassword string // App Password secret (Basic auth)
}

func (t *bitbucketAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    req = req.Clone(req.Context())
    if t.token != "" {
        req.Header.Set("Authorization", "Bearer "+t.token)
    } else {
        req.SetBasicAuth(t.username, t.appPassword)
    }
    return t.base.RoundTrip(req)
}

func NewBitbucketConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*BitbucketConnection, error) {
    conn := &BitbucketConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    workspace := os.Getenv("BITBUCKET_WORKSPACE")
    if ws := conf.Options["workspace"]; ws != "" {
        workspace = ws
    }
    if workspace == "" {
        return nil, errors.New("a Bitbucket workspace is required (set BITBUCKET_WORKSPACE or use --workspace)")
    }
    conn.workspace = workspace

    token := os.Getenv("BITBUCKET_TOKEN")
    for _, cred := range conf.Credentials {
        if cred.Type == vault.CredentialType_bearer {
            token = string(cred.Secret)
        }
    }

    transport := &bitbucketAuthTransport{base: http.DefaultTransport}
    if token != "" {
        // workspace or repository Access Token
        transport.token = token
    } else {
        username := os.Getenv("BITBUCKET_USERNAME")
        appPassword := os.Getenv("BITBUCKET_APP_PASSWORD")
        for _, cred := range conf.Credentials {
            if cred.Type == vault.CredentialType_password {
                appPassword = string(cred.Secret)
            }
        }
        if username == "" || appPassword == "" {
            return nil, errors.New(
                "Bitbucket credentials are required: set BITBUCKET_TOKEN, " +
                    "or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD (or the matching flags)")
        }
        // legacy App Password
        transport.username, transport.appPassword = username, appPassword
    }

    cfg := bbapi.NewConfiguration()
    cfg.HTTPClient = &http.Client{Transport: transport}
    conn.client = bbapi.NewAPIClient(cfg)

    return conn, nil
}

func (c *BitbucketConnection) Client() *bbapi.APIClient { return c.client }
func (c *BitbucketConnection) Workspace() string        { return c.workspace }
```

`bbapi` is generated at build time (not committed as hand-written source) by `openapi-generator-cli generate -i https://api.bitbucket.org/swagger.json -g go -o providers/bitbucket/internal/bbapi --package-name bbapi`, pinned to a fetched copy of the spec checked into `providers/bitbucket/openapi/swagger.json` so builds are reproducible and reviewable diffs show spec changes explicitly.

---

## Implementation Patterns

### Paginated List (all list APIs)

Bitbucket Cloud API 2.0 pagination is page-based: request `page`/`pagelen`, and the response body carries a `next` URL when more pages remain. The generated `bbapi` types model each paginated response as `Paginated<Thing>` with a `Next *string` field (a nullable full URL, per the swagger spec) alongside `Values []<Thing>`; walk it until `Next` is nil, passing `page`/`pagelen` as request options on the first call and letting the `next` URL (which already embeds the following page number) drive the rest:

```go
func (b *mqlBitbucketWorkspace) repositories() ([]any, error) {
    conn := b.MqlRuntime.Connection.(*connection.BitbucketConnection)
    client := conn.Client()
    ctx := context.Background()

    var all []any
    req := client.RepositoriesApi.RepositoriesWorkspaceGet(ctx, b.Slug.Data).Pagelen(100)
    for {
        page, _, err := req.Execute()
        if err != nil {
            return nil, err
        }
        for _, r := range page.GetValues() {
            mqlRepo, err := CreateResource(b.MqlRuntime, "bitbucket.repository", map[string]*llx.RawData{
                "id":         llx.StringData(r.GetUuid()),
                "slug":       llx.StringData(r.GetSlug()),
                "fullName":   llx.StringData(r.GetFullName()),
                "name":       llx.StringData(r.GetName()),
                "isPrivate":  llx.BoolData(r.GetIsPrivate()),
                "forkPolicy": llx.StringData(r.GetForkPolicy()),
                "mainBranch": llx.StringData(r.Mainbranch.GetName()),
                // ...
            })
            if err != nil {
                return nil, err
            }
            all = append(all, mqlRepo)
        }
        if page.Next == nil || *page.Next == "" {
            break
        }
        // the generated client accepts the literal "next" URL to fetch the
        // following page without re-deriving page/pagelen by hand
        req = client.RepositoriesApi.RepositoriesWorkspaceGetFromUrl(ctx, *page.Next)
    }
    return all, nil
}
```

### Typed Resource References (via Internal struct)

A repository is returned by the list API with its project embedded only as a key/UUID pair; expose it as a typed `project()` accessor instead of a raw `projectKey string` field:

```go
type mqlBitbucketRepositoryInternal struct {
    cacheWorkspaceSlug string
    cacheProjectKey    string
}

func (r *mqlBitbucketRepository) project() (*mqlBitbucketProject, error) {
    if r.cacheProjectKey == "" {
        r.Project.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    mqlProject, err := NewResource(r.MqlRuntime, "bitbucket.project", map[string]*llx.RawData{
        "workspace": llx.StringData(r.cacheWorkspaceSlug),
        "key":       llx.StringData(r.cacheProjectKey),
    })
    if err != nil {
        return nil, err
    }
    return mqlProject.(*mqlBitbucketProject), nil
}
```

`initBitbucketProject` reads `workspace` + `key` (both required for the underlying `GET /2.0/workspaces/{workspace}/projects/{project_key}` operation) and returns a not-found error, not a blank resource, when the lookup fails.

### Branch Restriction Merge-Check Expansion

The branch-restrictions list operation returns one entry per `kind` per `pattern`; map each entry straight to a `bitbucket.repository.branchRestriction` row using the API's own numeric restriction `id` as `__id` (already stable and unique per repository, so no composite key is needed):

```go
func (r *mqlBitbucketRepository) branchRestrictions() ([]any, error) {
    conn := r.MqlRuntime.Connection.(*connection.BitbucketConnection)
    ctx := context.Background()

    var all []any
    req := conn.Client().BranchRestrictionsApi.
        RepositoriesWorkspaceRepoSlugBranchRestrictionsGet(ctx, conn.Workspace(), r.Slug.Data)
    for {
        page, _, err := req.Execute()
        if err != nil {
            return nil, err
        }
        for _, br := range page.GetValues() {
            mqlBr, err := CreateResource(r.MqlRuntime, "bitbucket.repository.branchRestriction", map[string]*llx.RawData{
                "__id":         llx.StringData(strconv.FormatInt(br.GetId(), 10)),
                "id":           llx.IntData(br.GetId()),
                "kind":         llx.StringData(br.GetKind()),
                "pattern":      llx.StringData(br.GetPattern()),
                "minApprovals": llx.IntData(br.GetValue()),
            })
            if err != nil {
                return nil, err
            }
            all = append(all, mqlBr)
        }
        if page.Next == nil || *page.Next == "" {
            break
        }
        req = conn.Client().BranchRestrictionsApi.
            RepositoriesWorkspaceRepoSlugBranchRestrictionsGetFromUrl(ctx, *page.Next)
    }
    return all, nil
}
```

---

## Security Policies (MVP)

Ship as `mondoo-bitbucket-security.mql.yaml`:

**Workspace Security:**
- Workspaces must enforce two-step verification for all members
- Workspaces with sensitive repositories should restrict access with an IP allowlist

**Repository Visibility:**
- Repositories must not be public unless explicitly intended (flag any `isPrivate == false` repository for review)
- Repositories should restrict forking (`forkPolicy != "allow_forks"`) unless forking is an intended workflow

**Branch Protection:**
- The main branch must have a branch restriction of kind `require_approvals_to_merge` with `minApprovals >= 1`
- The main branch must have a branch restriction of kind `push` or `restrict_merges` limiting who can push directly
- The main branch must have a branch restriction of kind `force` preventing force-pushes
- The main branch must have a branch restriction of kind `delete` preventing branch deletion

**Access Hygiene:**
- Deploy keys must be reviewed periodically; any key with no `lastUsed` activity in 90+ days should be flagged as stale
- Repository and workspace admin permissions should be held by the minimum necessary set of members and groups (no stale admin access)

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/bitbucket` in `go.work` list
4. **`Makefile`** — `bitbucket` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/bitbucket/resources/bitbucket.lr \
  --dist providers/bitbucket/resources

# Build and install
make providers/build/bitbucket && make providers/install/bitbucket

# Test (Access Token)
export BITBUCKET_WORKSPACE="acme-corp"
export BITBUCKET_TOKEN="xxxxxxxxxxxxxxxx"
mql shell bitbucket

# Test (App Password)
export BITBUCKET_WORKSPACE="acme-corp"
export BITBUCKET_USERNAME="jdoe"
export BITBUCKET_APP_PASSWORD="xxxxxxxxxxxxxxxx"
mql shell bitbucket

> bitbucket.workspace
> bitbucket.workspace.repositories { fullName isPrivate forkPolicy mainBranch }
> bitbucket.workspace.repositories { fullName branchRestrictions { kind pattern minApprovals } }
> bitbucket.workspace.repositories { fullName deployKeys { label lastUsed } }
> bitbucket.workspace { enforceTwoStepVerification ipAllowlistEnabled }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/bitbucket --provider-id bitbucket --provider-name "Bitbucket"` then `cd providers/bitbucket && go mod tidy`
2. Root + Workspace (validates auth, covers `enforceTwoStepVerification` and `ipAllowlistEnabled`)
3. Projects (needed before repositories can resolve `project()`)
4. Repositories (core inventory: privacy, fork policy, main branch)
5. Branch Restrictions (critical for security policies)
6. Deploy Keys
7. Members + Groups (default reviewers, permission auditing)
8. Security policies
9. Discovery
10. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Bitbucket Cloud REST API 2.0](https://developer.atlassian.com/cloud/bitbucket/rest/intro/)
- [Bitbucket Cloud REST API - Workspaces](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-workspaces/)
- [Bitbucket Cloud REST API - Repositories](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/)
- [Bitbucket Cloud REST API - Branch restrictions](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-branch-restrictions/)
- [How to create/edit branch restrictions via API](https://support.atlassian.com/bitbucket-cloud/kb/how-to-create-edit-branch-restrictions-in-bitbucket-cloud-repositories-via-api/)
- [Enable two-step verification (workspace enforcement)](https://support.atlassian.com/bitbucket-cloud/docs/enable-two-step-verification/)
- [Set repository privacy and forking options](https://support.atlassian.com/bitbucket-cloud/docs/set-repository-privacy-and-forking-options/)
- [Bitbucket Cloud OpenAPI/Swagger 2.0 spec](https://api.bitbucket.org/swagger.json)
- [DrFaust92/terraform-provider-bitbucket](https://github.com/DrFaust92/terraform-provider-bitbucket) ([Terraform Registry docs](https://registry.terraform.io/providers/DrFaust92/bitbucket/latest/docs)) — client-selection rung 2(a) alignment source (see Context)
- [openapi-generator](https://github.com/OpenAPITools/openapi-generator) (`-g go`) — used to produce `providers/bitbucket/internal/bbapi` from the spec above
- Reference providers: `providers/github/`, `providers/gitlab/`
