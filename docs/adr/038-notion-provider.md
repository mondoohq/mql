# ADR-038: Notion Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Notion is a widely used workspace and knowledge-base product, reachable through a
well-documented REST API (`https://api.notion.com/v1`). Authentication is a
single bearer token (an "internal integration" secret, prefixed `secret_`),
with no OAuth flow required for the single-workspace, admin-installed use case
this ADR targets. That makes Notion a good candidate for a small,
self-contained provider in the same spirit as `digitalocean` and `tailscale`:
one credential, a handful of list/search endpoints, and a security-relevant
surface (public sharing exposure, integration and bot ownership, content
staleness) that maps cleanly onto MQL resources and cnspec policies.

**Client selection.** mql's provider client priority is (1) an official
vendor Go SDK, (2) failing that, harmonizing with the vendor's own Terraform
provider plus a client generated from the vendor's OpenAPI v3 spec, and only
(3) failing both, a hand-written or community client, stated with
justification. Notion lands on rung 3:

1. **No official vendor Go SDK.** Notion publishes and maintains official SDKs
   for [JavaScript](https://github.com/makenotion/notion-sdk-js) and
   [Python](https://github.com/makenotion/notion-sdk-py) only. There is no
   `github.com/makenotion/...` Go module, official or otherwise.
2. **No OpenAPI v3 spec, and no official Terraform provider to harmonize
   with.** Notion does not publish a formal OpenAPI v3 (or v2) specification
   for the public API, so a generated client is not an option. Terraform
   Registry does list Notion providers (`ketion-so/notion`,
   `theostanton/notion`, `delize/notion`), but all three are third-party,
   community-published (none under a `notion` or `makenotion` namespace, and
   Notion does not list an official provider on its own integrations page).
   With no vendor-authored Terraform provider to align field names or
   resource boundaries against, rung 2 does not apply here; this resource
   schema is derived directly from the REST API's own JSON shapes instead.
3. **Rung 3, justified: `github.com/jomei/notionapi`.** This is the de-facto
   community Go client for the Notion API (actively maintained, typed request
   and response structs for users, search, databases, and pages, and correct
   handling of the `Notion-Version` header). It is preferred here over a
   hand-rolled `net/http` client because it already models Notion's paginated
   list/search response shapes and the `person`/`bot` user discriminator this
   ADR's resources depend on, which a hand-written client would otherwise have
   to duplicate with no corresponding upstream to track API changes against.
   If it ever falls out of maintenance, the fallback is a local `net/http`
   client scoped to the handful of endpoints this provider uses.

**API scope reality, read before implementing.** Notion's public REST API is a
*content-integration* API, not a workspace administration API. An internal
integration token can only see:

- Its own bot identity (`GET /v1/users/me`).
- The workspace's members and bots (`GET /v1/users`), each returned as either a
  `person` (with `email` when the integration has the email-read capability) or
  a `bot` (with an `owner` of type `workspace` or `user`).
- Pages and databases the integration was explicitly connected to through
  Notion's per-page "Connections" sharing UI, discoverable only via
  `POST /v1/search` (there is no "list every page in the workspace" endpoint;
  an unshared page is invisible to the integration, not merely restricted).
- Whatever each visible page/database object reports: `url`, `public_url`
  (populated only if the page or database was published to the web through
  Notion Sites), `last_edited_time`, `archived`, `in_trash`, and its `parent`
  reference.

What it does **not** expose, at any tier reachable from this token type:

- The read/insert/update/comment **capabilities** granted to the integration
  itself. Those are configured on the integration's settings page in the
  Notion admin console and are not returned by any REST endpoint. A "is this
  integration over-privileged" check can assert on what *is* visible (bot
  ownership) but cannot machine-verify granted capabilities; that stays a
  manual review step.
- Member **role** (owner, member, guest). The base `/v1/users` response has no
  role field, so a guest cannot be distinguished from a full member through
  this API.
- Workspace-wide governance: enforced SSO, allowed email domains, member
  provisioning and deprovisioning, and audit-log events. These require
  Notion's **Enterprise-tier SCIM and Audit Log APIs**, which are separate
  products with separate tokens and are out of scope for this ADR. Every
  policy check below that depends on them is marked "Enterprise tier /
  future" so the base OSS provider does not overpromise what it can verify.

Notion also rate-limits to roughly 3 requests/second average per integration,
which matters for the paginated list/search patterns below but does not change
the resource model.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `notion` |
| **Provider ID** | `go.mondoo.com/mql/providers/notion` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `notion` |
| **Go SDK** | `github.com/jomei/notionapi` (community; rung-3 fallback, see Context: no official vendor Go SDK, no OpenAPI v3 spec, no official Terraform provider) |
| **API Type** | REST (Notion API, versioned via the `Notion-Version` header) |
| **Auth** | Internal integration token (`NOTION_TOKEN` env var or `--token` flag) |

---

## Directory Structure

```
providers/notion/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── config/
│   └── config.go
├── connection/
│   └── connection.go
├── provider/
│   └── provider.go
└── resources/
    ├── notion.lr
    ├── notion.lr.go              # generated
    ├── notion.lr.versions        # generated
    ├── discovery.go
    ├── notion.go                 # root resource + bot + workspace
    ├── user.go
    ├── database.go
    └── page.go
```

---

## Resource Schema (`notion.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/notion"
option go_package = "go.mondoo.com/mql/providers/notion/resources"

// Notion workspace integration
//
// Root of a Notion integration connected through an internal integration
// token. Exposes the bot identity of the integration itself, the workspace
// members and bots visible to it, and the pages and databases the
// integration has been given access to through Notion's per-page sharing
// model. The Notion REST API is scoped to content an integration has been
// explicitly connected to; it does not provide workspace-wide
// administration data such as SSO enforcement or member provisioning, which
// requires the separate Enterprise SCIM and Audit Log APIs.
notion {
  // The integration's own bot identity and owning workspace
  bot() notion.bot
  // Workspace as seen through this integration's connected content
  workspace() notion.workspace
  // Workspace members and bots visible to this integration
  users() []notion.user
  // Databases visible to this integration through Notion's sharing model
  databases() []notion.database
  // Pages visible to this integration through Notion's sharing model
  pages() []notion.page
}

// Notion integration's bot identity
//
// The bot user that represents this integration's internal integration
// token, returned by Notion's users/me endpoint. The ownerType field is the
// resource's key security signal: an integration owned by workspace
// survives the departure of whoever created it, while one owned by user is
// tied to that person's account and typically loses access when they
// leave. Notion's public API does not report the read, insert, update, or
// comment capabilities granted to an integration, those are configured on
// the integration's settings page and must be reviewed there.
notion.bot @defaults("id name ownerType") {
  // Bot user ID
  id string
  // Integration display name
  name string
  // Avatar image URL
  avatarUrl string
  // Owner type of the integration, either 'workspace' or 'user'
  ownerType string
  // Individual owner of the integration, set only when ownerType is 'user'
  owner() notion.user
  // Name of the workspace this integration is installed in
  workspaceName string
}

// Notion workspace as seen through a connected integration
//
// Workspace-level information visible to an internal integration, keyed by
// name, for example notion.workspace(name: "Acme Corp"). Notion's REST API
// has no dedicated workspace endpoint: the name comes from the
// integration's own bot identity. Settings that require full workspace
// administration, such as enforced SSO, allowed email domains, or member
// provisioning, are only available through the separate Enterprise SCIM
// and Audit Log APIs and are not modeled here; they would land on this
// resource once that integration exists.
notion.workspace @defaults("name") {
  // Workspace name, from the integration's bot identity
  name string
  // Number of workspace members and bots visible to this integration
  userCount() int
  // Number of databases visible to this integration
  databaseCount() int
  // Number of pages visible to this integration
  pageCount() int
}

// Notion workspace member or bot
//
// A user visible to the integration through Notion's users endpoint,
// selected by id, for example notion.user(id: "a1b2c3d4..."). Covers both
// human workspace members (type == "person") and bot users representing
// other integrations installed in the same workspace (type == "bot"). The
// email field is populated only for person-type users, and only when the
// integration was granted the "read user information with email"
// capability, otherwise it is empty. Bot-type users additionally expose
// botOwnerType and botOwner, mirroring the fields on notion.bot, since a
// workspace can contain bots belonging to integrations other than this
// one. Notion's base API does not report a member/guest role, so this
// resource cannot distinguish a guest from a full workspace member.
notion.user @defaults("id name type") {
  init(id string)
  // User ID
  id string
  // Display name
  name string
  // Avatar image URL
  avatarUrl string
  // User type, either 'person' or 'bot'
  type string
  // Email address, populated only for person-type users when the integration can read it
  email string
  // Owner type of a bot-type user, either 'workspace' or 'user', empty for person-type users
  botOwnerType string
  // Individual owner of a bot-type user, set only when botOwnerType is 'user'
  botOwner() notion.user
}

// Notion database
//
// A database visible to the integration, discovered through Notion's
// search endpoint and selected by id, for example
// notion.database(id: "a1b2c3d4..."). Exposes sharing exposure through
// publicUrl (set only when the database has been published to the web via
// Notion Sites) and edit recency through lastEditedTime, the two signals
// most security audits need: is this content publicly reachable, and is
// it actively maintained or abandoned. The parentPage reference resolves
// the page a database is nested under, when there is one.
notion.database @defaults("id title") {
  init(id string)
  // Database ID
  id string
  // Database title
  title string
  // Notion URL for viewing the database in the app
  url string
  // Public URL if the database has been published to the web, empty otherwise
  publicUrl string
  // Whether the database has been published to the web and is reachable without a Notion account
  isPubliclyShared() bool
  // Creation time
  createdTime time
  // Last edit time
  lastEditedTime time
  // Whether the database is archived
  archived bool
  // Whether the database is in the trash
  inTrash bool
  // Parent page, set only when the database is nested under a page rather than the workspace or a block
  parentPage() notion.page
}

// Notion page
//
// A page visible to the integration, discovered through Notion's search
// endpoint and selected by id, for example notion.page(id: "a1b2c3d4...").
// Like notion.database, its publicUrl and lastEditedTime are the primary
// security signals: public sharing exposure and content staleness. The
// parentDatabase and parentPage references resolve the page's container,
// when the API reports one; a page can otherwise sit directly under the
// workspace or a block. The properties field carries the page's raw
// property values as Notion returns them, since fully modeling every
// Notion property type (including relation properties that point at other
// pages) is out of scope for this initial resource set.
notion.page @defaults("id title") {
  init(id string)
  // Page ID
  id string
  // Page title, extracted from the title-type property
  title string
  // Notion URL for viewing the page in the app
  url string
  // Public URL if the page has been published to the web, empty otherwise
  publicUrl string
  // Whether the page has been published to the web and is reachable without a Notion account
  isPubliclyShared() bool
  // Creation time
  createdTime time
  // Last edit time
  lastEditedTime time
  // Whether the page is archived
  archived bool
  // Whether the page is in the trash
  inTrash bool
  // Parent database, set only when the page is a row of a database
  parentDatabase() notion.database
  // Parent page, set only when the page is nested under another page
  parentPage() notion.page
  // Raw page properties as returned by the API, keyed by property name
  properties dict
}
```

---

## Authentication

Single bearer token, following the same pattern as `digitalocean` and
`shodan` (`providers/digitalocean/connection/connection.go`), plus the
mandatory `Notion-Version` header the API rejects requests without:

```go
package connection

import (
    "context"
    "os"

    "github.com/cockroachdb/errors"
    "github.com/jomei/notionapi"

    "go.mondoo.com/mql/providers-sdk/v1/inventory"
    "go.mondoo.com/mql/providers-sdk/v1/plugin"
    "go.mondoo.com/mql/providers-sdk/v1/vault"
)

// notionAPIVersion pins the Notion-Version header. The community SDK sends
// it on every request once configured here; bump it deliberately, since a
// version bump can change response shapes.
const notionAPIVersion = "2022-06-28"

type NotionConnection struct {
    plugin.Connection
    Conf    *inventory.Config
    asset   *inventory.Asset
    client  *notionapi.Client
    botUser *notionapi.User // captured during Verify(), backs notion.bot
}

func NewNotionConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NotionConnection, error) {
    conn := &NotionConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    token := os.Getenv("NOTION_TOKEN")
    if len(conf.Credentials) > 0 {
        for _, cred := range conf.Credentials {
            if cred.Type == vault.CredentialType_password {
                token = string(cred.Secret)
            }
        }
    }
    if token == "" {
        return nil, errors.New("a valid Notion internal integration token is required " +
            "(set NOTION_TOKEN or use --token)")
    }

    conn.client = notionapi.NewClient(notionapi.Token(token),
        notionapi.WithVersion(notionAPIVersion))

    return conn, nil
}

// Verify calls users/me, the cheapest authenticated endpoint Notion offers,
// to confirm the token is valid and to capture the integration's own bot
// identity up front so notion.bot never needs a second round trip.
func (n *NotionConnection) Verify() error {
    me, err := n.client.User.Me(context.Background())
    if err != nil {
        if apiErr, ok := err.(*notionapi.Error); ok && apiErr.Status == 401 {
            return errors.New("invalid Notion integration token, verify the token and try again")
        }
        return err
    }
    n.botUser = me
    return nil
}

func (n *NotionConnection) Client() *notionapi.Client { return n.client }
func (n *NotionConnection) BotUser() *notionapi.User  { return n.botUser }
func (n *NotionConnection) Asset() *inventory.Asset   { return n.asset }
func (n *NotionConnection) Name() string              { return "notion" }
```

---

## Implementation Patterns

### Paginated Search (pages and databases)

Notion has no "list all pages" endpoint; `POST /v1/search` is the only way to
enumerate content, filtered by `object: "page"` or `object: "database"` and
paginated with `start_cursor` / `has_more` / `next_cursor`, capped at 100
results per page:

```go
func (n *mqlNotion) pages() ([]any, error) {
    conn := n.MqlRuntime.Connection.(*connection.NotionConnection)
    client := conn.Client()

    var all []any
    cursor := notionapi.Cursor("")
    for {
        resp, err := client.Search.Do(context.Background(), &notionapi.SearchRequest{
            Filter:      notionapi.SearchFilter{Property: "object", Value: "page"},
            StartCursor: cursor,
            PageSize:    100,
        })
        if err != nil {
            return nil, err
        }

        for _, result := range resp.Results {
            page, ok := result.(*notionapi.Page)
            if !ok {
                continue
            }
            r, err := mqlNotionPageFromAPI(n.MqlRuntime, page)
            if err != nil {
                return nil, err
            }
            all = append(all, r)
        }

        if !resp.HasMore || resp.NextCursor == "" {
            break
        }
        cursor = resp.NextCursor
    }
    return all, nil
}
```

`mqlNotionPageFromAPI` is a shared helper (used by both the search-based
lister above and the `init` lazy loader below) that maps a
`*notionapi.Page` to `CreateResource("notion.page", ...)`, setting `__id` to
the page's UUID and populating `cacheParentDatabaseId` /
`cacheParentPageId` on the Internal struct from `page.Parent`.

### Typed Resource References (via Internal struct)

A page's parent is reported as a discriminated union (`parent.type` is one
of `database_id`, `page_id`, `workspace`, or `block_id`). Only the first two
resolve to a typed reference; the others leave the field null:

```go
type mqlNotionPageInternal struct {
    cacheParentDatabaseId string
    cacheParentPageId     string
}

func (p *mqlNotionPage) parentDatabase() (*mqlNotionDatabase, error) {
    if p.cacheParentDatabaseId == "" {
        p.ParentDatabase.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    r, err := NewResource(p.MqlRuntime, "notion.database",
        map[string]*llx.RawData{"id": llx.StringData(p.cacheParentDatabaseId)})
    if err != nil {
        return nil, err
    }
    return r.(*mqlNotionDatabase), nil
}

func (p *mqlNotionPage) parentPage() (*mqlNotionPage, error) {
    if p.cacheParentPageId == "" {
        p.ParentPage.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    r, err := NewResource(p.MqlRuntime, "notion.page",
        map[string]*llx.RawData{"id": llx.StringData(p.cacheParentPageId)})
    if err != nil {
        return nil, err
    }
    return r.(*mqlNotionPage), nil
}
```

### Lazy Loading by ID (`init`)

`notion.page(id: "...")`, `notion.database(id: "...")`, and
`notion.user(id: "...")` all fetch on demand via `NewResource`, following the
codebase's `init` convention. `initNotionPage` calls `GET /v1/pages/{id}`
directly rather than falling through to search, since a page can be visible
by ID even when `properties` filtering makes it hard to `search` for by
title:

```go
func initNotionPage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
    if len(args) > 2 {
        return args, nil, nil
    }
    idRaw, ok := args["id"]
    if !ok {
        return nil, nil, errors.New("notion.page requires an id")
    }
    id := idRaw.Value.(string)

    conn := runtime.Connection.(*connection.NotionConnection)
    page, err := conn.Client().Page.Get(context.Background(), notionapi.PageID(id))
    if err != nil {
        return nil, nil, errors.Wrapf(err, "notion.page with id %q not found", id)
    }

    r, err := mqlNotionPageFromAPI(runtime, page)
    if err != nil {
        return nil, nil, err
    }
    return nil, r, nil
}
```

### The `Notion-Version` Header

Every request, including ones made outside the SDK's built-in methods (for
example a future raw HTTP call against an endpoint the SDK has not wrapped
yet), must carry `Notion-Version: 2022-06-28`. Its absence is a hard 400, not
a warning. `notionapi.WithVersion` on the client (see Authentication above)
covers every SDK-mediated call; any hand-rolled request needs the header set
explicitly.

### Sharing Exposure and Staleness (`isPubliclyShared`)

`isPubliclyShared()` follows the codebase convention that this predicate name
means "reachable from the internet." It is computed, not stored, so a future
change in how Notion reports publication status only touches one function:

```go
func (p *mqlNotionPage) isPubliclyShared() (bool, error) {
    return p.PublicUrl.Data != "", nil
}
```

---

## Security Policies (MVP)

Ship as `mondoo-notion-security.mql.yaml`. Every check below runs against
the base internal-integration token; none require Enterprise APIs.

**Content Exposure:**
- Pages must not have a `publicUrl` set (flags Notion Sites publication)
  ```
  notion.pages.where( archived == false && inTrash == false ) {
    publicUrl == empty
  }
  ```
- Databases must not have a `publicUrl` set, same rationale

**Integration and Bot Ownership:**
- The integration's own bot (`notion.bot.ownerType`) must be `workspace`, not
  `user`, so access survives the departure of whoever installed it
- Any other bot user found in `notion.users` (`botOwnerType`) should likewise
  be `workspace`-owned; a `user`-owned bot belonging to someone who has left
  the organization is a common source of orphaned, unmonitored access
- Integration capability hygiene (read/insert/update/comment scopes) is a
  **manual review item**, not an automated check: the base API does not
  return an integration's granted capabilities (see Context). The policy
  ships a documentation-only control pointing reviewers at the integration's
  settings page rather than a `mql:` assertion that cannot be verified.

**Content Lifecycle:**
- Pages and databases whose `lastEditedTime` is older than a configurable
  threshold (default 180 days) should be flagged for staleness review, since
  forgotten pages are a common place for stale public links or outdated
  sharing grants to linger unnoticed
  ```
  notion.pages.where( archived == false ) {
    lastEditedTime > time.now - 180 * time.day
  }
  ```

**Enterprise tier / future (not implemented in the base OSS policy):**
- Guest vs. full-member distinction across `notion.users`, requires the
  Enterprise SCIM Users API (base `/v1/users` has no role field)
- Enforced SSO across the workspace, requires Enterprise SSO configuration
  data, not exposed to any REST token
- Allowed email domain restrictions, Enterprise workspace setting, no REST
  equivalent
- Member provisioning and deprovisioning audit trail, requires the
  Enterprise Audit Log API
- These are tracked as follow-up work once mql gains an Enterprise SCIM/Audit
  Log connection mode; they must not be represented as passing checks against
  data the base provider cannot see.

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/notion` in `go.work` list
4. **`Makefile`** — `notion` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/notion/resources/notion.lr \
  --dist providers/notion/resources

# Build and install
make providers/build/notion && make providers/install/notion

# Test
export NOTION_TOKEN="secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mql shell notion
> notion.bot { id name ownerType workspaceName }
> notion.workspace { name userCount databaseCount pageCount }
> notion.users { id name type email botOwnerType }
> notion.pages.where( publicUrl != empty ) { title url publicUrl lastEditedTime }
> notion.databases { title publicUrl lastEditedTime parentPage { title } }
```

Since `notion` is a brand-new, unreleased provider, every entry in
`notion.lr.versions` for this initial PR is `13.0.0`, not `13.0.1`; the
"next patch version" rule in the resource development guide only applies to
fields added after a version has actually shipped.

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/notion --provider-id notion --provider-name "Notion"` then `cd providers/notion && go mod tidy`
2. Root + Bot (`users/me`, validates auth and captures the integration's own identity)
3. Workspace (thin wrapper around the bot's `workspace_name` plus derived counts)
4. Users (`/v1/users`, person vs. bot, email and bot ownership)
5. Databases (search-discovered, `publicUrl`/`isPubliclyShared`, `parentPage`)
6. Pages (search-discovered, `publicUrl`/`isPubliclyShared`, `parentDatabase`, `parentPage`, raw `properties`)
7. Security policies (public sharing, bot ownership, staleness; document the capability-review gap)
8. Discovery (`discovery.go`, wired through `conn.Filters` per the discovery-filter gate for any future tag/name filtering)
9. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Notion API Reference](https://developers.notion.com/reference/intro)
- [Notion API Authentication](https://developers.notion.com/reference/authentication)
- [Notion API Pagination](https://developers.notion.com/reference/intro#pagination)
- [jomei/notionapi Go SDK](https://github.com/jomei/notionapi) (rung-3 community client, see Context: Client selection)
- [notion-sdk-js](https://github.com/makenotion/notion-sdk-js) / [notion-sdk-py](https://github.com/makenotion/notion-sdk-py) (official vendor SDKs, JS/Python only; no official Go SDK exists, rung 1 does not apply)
- Community Terraform providers checked for rung 2 (none official, so not used to harmonize this schema): [ketion-so/notion](https://registry.terraform.io/providers/ketion-so/notion/latest), [theostanton/notion](https://registry.terraform.io/providers/theostanton/notion/latest), [delize/notion](https://registry.terraform.io/providers/delize/notion/latest)
- [Notion Enterprise SCIM API](https://developers.notion.com/reference/scim-overview) (future work, not used by this provider)
- Reference providers: `providers/tailscale/`, `providers/digitalocean/`
