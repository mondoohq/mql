# ADR-033: Zoom Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Zoom is a widely deployed video-conferencing and collaboration SaaS product, and its account-level configuration is a common source of security findings: meetings left without waiting rooms or passcodes, cloud recordings stored unencrypted, external/guest participants allowed into internal meetings, SSO not enforced for the workforce, and admin-equivalent roles handed out too broadly. Unlike AWS/Azure/GCP, Zoom has no IAM hierarchy or resource graph to model; the value of a provider here is almost entirely in exposing **account-level and user-level security posture** through a small, focused resource set that cnspec can assert against.

Zoom's REST API v2 authenticates via **Server-to-Server OAuth** (account ID + client ID + client secret exchanged for a short-lived Bearer token, no user interaction and no refresh token).

**Client selection (priority ladder):** (1) There is **no official Zoom server-side Go SDK** — the Go packages that exist for Zoom in the wild (`oxidecomputer/third-party-api-clients`, assorted one-off wrappers) are third-party, not vendor-published, so rung 1 is unavailable. (2) Zoom does publish an API specification for the REST API v2 at [`github.com/zoom/api`](https://github.com/zoom/api) (`openapi.v2.json`, mirrored under `marketplace.zoom.us`); this repo lands on rung 2 and generates the client from that spec rather than hand-writing one. One correction to flag: despite the filename, the published spec is **Swagger 2.0 / OpenAPI 2.0** (`"swagger": "2.0"` at the document root, confirmed by fetching the raw file), not OpenAPI v3 — Zoom's "OAS 3.0/3.1" support referenced in its docs is for *uploading* custom app specs to the Marketplace Build Flow, not for the API's own published spec. The spec is converted to OpenAPI v3 as a vendoring step before codegen (see Implementation Patterns).

**Terraform provider alignment:** Zoom does not publish an official Terraform provider. The Terraform Registry only lists community-maintained ones (`folio-sec/zoom`, `CleverTap/zoom`, `fceller/zoom`, `chaurasia-namrata/zoomus`), none backed by Zoom itself or affiliated with the `zoom` GitHub org — so there is no vendor provider to harmonize resource/field naming with under rung 2(a). This ADR's resource and field naming is instead traced directly to the object shapes in Zoom's own OpenAPI spec (`github.com/zoom/api`), which is also the source of truth for the generated client.

This ADR follows the DigitalOcean provider ADR (`docs/adr/006-digitalocean-provider.md`) as the template for structure and level of detail.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `zoom` |
| **Provider ID** | `go.mondoo.com/mql/providers/zoom` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `zoom` |
| **Go SDK** | None official. Generated client from Zoom's published OpenAPI spec (`github.com/zoom/api`, Swagger 2.0 converted to OAS 3 for codegen); `golang.org/x/oauth2/clientcredentials` for the Server-to-Server OAuth token exchange |
| **API Type** | REST (Zoom API v2, `https://api.zoom.us/v2`) |
| **Auth** | Server-to-Server OAuth: account ID, client ID, client secret (`ZOOM_ACCOUNT_ID` / `ZOOM_CLIENT_ID` / `ZOOM_CLIENT_SECRET` env vars, or `--account-id` / `--client-id` / `--client-secret` flags) |

---

## Directory Structure

```
providers/zoom/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── client/
│   ├── openapi.yaml             # vendored, converted to OAS 3 from github.com/zoom/api's openapi.v2.json
│   ├── generate.go              # go:generate directive driving oapi-codegen
│   └── zoomapi.gen.go           # generated Go client — DO NOT EDIT
├── config/
│   └── config.go
├── connection/
│   ├── connection.go
│   └── authentication.go
├── provider/
│   └── provider.go
└── resources/
    ├── zoom.lr
    ├── zoom.lr.go                  # generated
    ├── zoom.lr.versions            # generated
    ├── discovery.go
    ├── zoom.go                     # root resource
    ├── account.go                  # account settings, lazy-loaded
    ├── sso.go
    ├── user.go
    ├── role.go
    └── group.go
```

---

## Resource Schema (`zoom.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/zoom"
option go_package = "go.mondoo.com/mql/providers/zoom/resources"

// Zoom account
//
// Entry point for a Zoom account reached through Server-to-Server OAuth.
// Exposes the account's security-relevant configuration (`account`), its
// users, the roles those users can hold, and the groups they belong to.
// Groups and roles both carry their own meeting-security overrides and
// membership lists, so admin-equivalent access and account-wide meeting
// defaults can be audited from a single query surface.
zoom {
  // Account-level settings, including meeting, recording, and sign-in security
  account() zoom.account
  // Users provisioned on the account
  users() []zoom.user
  // Roles that can be assigned to users
  roles() []zoom.role
  // User groups, each with its own meeting-security overrides
  groups() []zoom.group
}

// Zoom account settings
//
// Account-wide configuration reached through the authenticated
// Server-to-Server OAuth account, selected by `id` (the Zoom account ID
// tied to the credentials used to connect). Covers the meeting-security
// defaults applied to every meeting on the account (waiting room,
// passcode requirements, encryption type), cloud-recording encryption,
// whether only authenticated or account-internal users may join
// meetings, and the sign-in session timeout enforced for the workforce.
// The `sso` field carries the account's single sign-on configuration.
zoom.account @defaults("id accountName") {
  // Zoom account ID
  id string
  // Account (company) name
  accountName string
  // Email address of the account owner
  ownerEmail string
  // Whether the waiting room is enabled by default for new meetings
  meetingWaitingRoomEnabled bool
  // Whether a passcode is required to join meetings by default
  meetingPasscodeRequired bool
  // Whether a passcode is required to join a user's Personal Meeting ID (PMI)
  meetingPmiPasscodeRequired bool
  // Default meeting encryption type
  //
  // One of `enhanced_encryption` (encrypted in transit and at rest on
  // Zoom's servers) or `end_to_end_encryption` (E2EE, only the meeting
  // participants hold the decryption keys).
  meetingEncryptionType string
  // Whether end-to-end encryption (E2EE) is available to hosts on this account
  meetingE2eeAvailable bool
  // Whether meetings require participants to be authenticated before joining
  meetingAuthenticationRequired bool
  // Whether meeting participation is restricted to users signed in on this account (blocks external/guest participants)
  meetingOnlyAccountUsersCanJoin bool
  // Whether cloud recording is enabled for the account
  cloudRecordingEnabled bool
  // Whether cloud recordings are encrypted at rest
  cloudRecordingEncryptionEnabled bool
  // Sign-in session timeout, in minutes, before a user is forced to re-authenticate (0 means no timeout is enforced)
  signInSessionTimeoutMinutes int
  // Single sign-on configuration for the account
  sso() zoom.account.sso
}

// Zoom single sign-on (SSO) configuration
//
// Account-wide SSO settings: whether SSO is enabled, the email domains
// provisioned through it, whether group membership is synced from the
// identity provider, and the identity provider's issuer and login URL.
private zoom.account.sso @defaults("enabled") {
  // Whether SSO is enabled for the account
  enabled bool
  // Email domains provisioned through SSO
  domains []string
  // Whether group membership is mapped from the identity provider
  groupMappingEnabled bool
  // Identity provider issuer URL
  idpIssuer string
  // Identity provider single sign-on URL
  idpSsoUrl string
}

// Zoom user
//
// A single user provisioned on the account, selected by `id`, for
// example `zoom.user(id: "z9f8...")`. Carries the user's licensing
// `type`, `status`, and sign-in method (`loginType` and `ssoLinked`),
// along with the `role` that governs their admin privileges and the
// `groups` whose meeting-security overrides apply to their meetings.
zoom.user @defaults("id email type") {
  init(id? string)
  // Zoom user ID
  id string
  // User's email address
  email string
  // First name
  firstName string
  // Last name
  lastName string
  // Display name
  displayName string
  // License type
  //
  // 1 (Basic), 2 (Licensed), or 99 (None, for API-created users on some
  // plans). Check the Zoom Users API docs for the current complete set.
  type int
  // Account status
  //
  // One of `active`, `inactive`, or `pending`.
  status string
  // Whether the user's email address has been verified
  verified bool
  // Sign-in method
  //
  // 1 (Google OAuth), 24 (Apple), 27 (Microsoft OAuth), 99 (API), 100
  // (SSO), or 101 (Zoom Work Email), among others. Check the Zoom Users
  // API docs for the current complete set.
  loginType int
  // Whether the user authenticates through the account's SSO configuration
  ssoLinked bool
  // Timestamp of the user's last login
  lastLoginTime time
  // Timestamp the user was created
  createdAt time
  // Role ID assigned to the user
  //
  // Deprecated in favor of role.
  roleId string @maturity("deprecated")
  // Role assigned to the user, governing their admin privileges
  role() zoom.role
  // Group IDs the user belongs to
  //
  // Deprecated in favor of groups.
  groupIds []string @maturity("deprecated")
  // Groups the user belongs to
  groups() []zoom.group
}

// Zoom role
//
// A role that can be assigned to users, selected by `id`, for example
// `zoom.role(id: "0")`. The built-in `Owner` and `Admin` roles carry
// full account privileges; custom roles carry whatever subset of
// `privileges` was granted to them. Use `members` to audit how many
// users hold admin-equivalent access.
zoom.role @defaults("id name") {
  // Role ID
  id string
  // Role name
  name string
  // Role description
  description string
  // Number of users assigned this role
  totalMembers int
  // Privileges (permission scopes) granted by this role
  privileges []string
  // Users assigned this role
  members() []zoom.user
}

// Zoom group
//
// A user group, selected by `id`, for example `zoom.group(id: "abc")`.
// Groups carry their own meeting-security overrides
// (`settingsWaitingRoomEnabled`, `settingsMeetingPasscodeRequired`,
// `settingsE2eeAvailable`, `settingsOnlyAuthenticatedUsersCanJoin`) that
// take precedence over the account defaults in `zoom.account` for
// members of the group, so a group's members can end up on a weaker (or
// stronger) meeting-security posture than the account as a whole.
zoom.group @defaults("id name") {
  // Group ID
  id string
  // Group name
  name string
  // Number of users in the group
  totalMembers int
  // Users in the group
  members() []zoom.user
  // Whether the waiting room is enabled by default for the group's meetings
  settingsWaitingRoomEnabled bool
  // Whether a passcode is required to join the group's meetings
  settingsMeetingPasscodeRequired bool
  // Whether end-to-end encryption (E2EE) is available to the group's hosts
  settingsE2eeAvailable bool
  // Whether the group's meetings are restricted to users signed in on this account
  settingsOnlyAuthenticatedUsersCanJoin bool
}
```

**Typed-reference gate applied:** `roleId` and `groupIds` are the only fields in this schema that point at other modeled resources, and both got typed accessors (`role()`, `groups()`) per [CLAUDE.md §1.5](../../CLAUDE.md#step-15-typed-reference-gate-do-this-before-you-generate-code); the raw fields are kept (deprecated) only because `role`/`group` list views are still useful for quick joins without triggering the lazy resolve. `zoom.account.sso` uses the hidden-`__id` singleton pattern (no `id` field) since its cache key (`<accountId>/sso`) is purely internal, not something a user would query by.

---

## Authentication

Server-to-Server OAuth exchanges account ID + client ID + client secret for a Bearer token good for one hour, with **no refresh token** — a new token must be requested from `https://zoom.us/oauth/token` on expiry. `golang.org/x/oauth2/clientcredentials` implements RFC 6749's standard `client_credentials` grant by default, but its `Config.EndpointParams` is explicitly allowed to override `grant_type` ("Allow grant_type to be overridden to allow interoperability with non-compliant implementations" — verified against the current `golang/oauth2` source), which is exactly what Zoom's `account_credentials` variant needs. That means no custom `TokenSource` is required: `clientcredentials.Config` handles the exchange, the one-hour expiry, and the re-fetch-on-expiry (it wraps itself in `oauth2.ReuseTokenSource` internally):

```go
// connection/connection.go

type ZoomConnection struct {
    plugin.Connection
    Conf      *inventory.Config
    asset     *inventory.Asset
    accountID string
    client    *zoomapi.ClientWithResponses // generated client, see client/
}

func NewZoomConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ZoomConnection, error) {
    conn := &ZoomConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    accountID, ok := GetAccountID(conf)
    if !ok {
        return nil, errors.New("a Zoom account ID is required, set ZOOM_ACCOUNT_ID or use --account-id")
    }
    clientID, ok := GetClientID(conf)
    if !ok {
        return nil, errors.New("a Zoom client ID is required, set ZOOM_CLIENT_ID or use --client-id")
    }
    clientSecret, ok := GetClientSecret(conf)
    if !ok {
        return nil, errors.New("a Zoom client secret is required, set ZOOM_CLIENT_SECRET or use --client-secret")
    }
    conn.accountID = accountID

    oauthCfg := &clientcredentials.Config{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        TokenURL:     "https://zoom.us/oauth/token",
        AuthStyle:    oauth2.AuthStyleInHeader, // client_id:client_secret as HTTP Basic auth
        EndpointParams: url.Values{
            "grant_type": {"account_credentials"},
            "account_id": {accountID},
        },
    }
    httpClient := oauthCfg.Client(context.Background())

    genClient, err := zoomapi.NewClientWithResponses("https://api.zoom.us/v2", zoomapi.WithHTTPClient(httpClient))
    if err != nil {
        return nil, err
    }
    conn.client = genClient

    return conn, nil
}

func (c *ZoomConnection) Name() string { return "zoom" }
func (c *ZoomConnection) Asset() *inventory.Asset { return c.asset }
func (c *ZoomConnection) Client() *zoomapi.ClientWithResponses { return c.client }
func (c *ZoomConnection) AccountID() string { return c.accountID }
```

`connection/authentication.go` follows the Tailscale provider's split (`providers/tailscale/connection/authentication.go`): `GetAccountID`/`GetClientID`/`GetClientSecret` each check the env var first, then the CLI flag, then (for the secret only) a `vault.CredentialType_password` credential, matching the option-precedence pattern already established there.

---

## Implementation Patterns

### Client Generation (OpenAPI v2 → v3 → Go)

Zoom's published spec (`github.com/zoom/api/openapi.v2.json`) is Swagger 2.0; `oapi-codegen` (the generator already acceptable for Go per the project's tooling posture, producing a typed `ClientWithResponses` plus request/response structs) requires OpenAPI 3.x input. `client/generate.go` vendors the spec and converts it as a `go:generate` step before invoking the generator:

```go
// client/generate.go

//go:generate go run github.com/getkin/kin-openapi/cmd/openapi2conv@latest -i zoom-openapi-v2.json -o openapi.yaml
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest -generate types,client -package client -o zoomapi.gen.go openapi.yaml
```

The converted `openapi.yaml` and the generated `zoomapi.gen.go` are committed (same policy as other generated code in this repo, e.g. `.lr.go`) so the build doesn't depend on network access to `github.com/zoom/api` at compile time; re-running the `go:generate` step to pick up upstream spec changes is a deliberate, reviewed update, not part of `make providers/build/zoom`.

### Paginated List (`page_size` + `next_page_token`)

Zoom list endpoints (`/users`, `/groups`, `/roles`) use `page_size` (max 300) and `next_page_token` (valid 15 minutes) rather than offset paging. The generated client's `ListUsersWithResponse` exposes both as typed params:

```go
func (z *mqlZoom) users() ([]any, error) {
    conn := z.MqlRuntime.Connection.(*connection.ZoomConnection)
    client := conn.Client()

    var all []any
    var nextPageToken *string
    status := zoomapi.ListUsersParamsStatusActive
    pageSize := 300
    for {
        resp, err := client.ListUsersWithResponse(context.Background(), &zoomapi.ListUsersParams{
            PageSize:      &pageSize,
            Status:        &status,
            NextPageToken: nextPageToken,
        })
        if err != nil {
            return nil, err
        }
        if resp.JSON200 == nil {
            return nil, fmt.Errorf("zoom: list users failed with status %d", resp.StatusCode())
        }

        for _, u := range resp.JSON200.Users {
            r, err := CreateResource(z.MqlRuntime, "zoom.user", map[string]*llx.RawData{
                "__id":     llx.StringData(*u.Id),
                "id":       llx.StringData(*u.Id),
                "email":    llx.StringData(*u.Email),
                "type":     llx.IntDataPtr(u.Type),
                "status":   llx.StringDataPtr((*string)(u.Status)),
                "roleId":   llx.StringDataPtr(u.RoleId),
                "groupIds": llx.ArrayData(convert.SliceAnyToInterface(convert.SliceStrToInterface(u.GroupIds)), types.String),
                // ...
            })
            if err != nil {
                return nil, err
            }
            all = append(all, r)
        }

        if resp.JSON200.NextPageToken == nil || *resp.JSON200.NextPageToken == "" {
            break
        }
        nextPageToken = resp.JSON200.NextPageToken
    }
    return all, nil
}
```

### Account Settings Lazy Fetch (double-check locking)

A single `GET /accounts/{accountId}/settings` call (`client.GetAccountSettingsWithResponse`) populates every meeting-security, recording, and sign-in field on `zoom.account`, so all of those computed methods share one cached fetch, per the [CLAUDE.md pattern](../../CLAUDE.md#step-3-implementation-strategies):

```go
type mqlZoomAccountInternal struct {
    fetched  bool
    settings *zoomapi.AccountSettings
    lock     sync.Mutex
}

func (a *mqlZoomAccount) fetchSettings() (*zoomapi.AccountSettings, error) {
    if a.fetched {
        return a.settings, nil
    }
    a.lock.Lock()
    defer a.lock.Unlock()
    if a.fetched {
        return a.settings, nil
    }

    conn := a.MqlRuntime.Connection.(*connection.ZoomConnection)
    resp, err := conn.Client().GetAccountSettingsWithResponse(context.Background(), conn.AccountID(), nil)
    if err != nil {
        return nil, err
    }
    if resp.JSON200 == nil {
        return nil, fmt.Errorf("zoom: get account settings failed with status %d", resp.StatusCode())
    }
    a.settings = resp.JSON200
    a.fetched = true
    return a.settings, nil
}

func (a *mqlZoomAccount) meetingWaitingRoomEnabled() (bool, error) {
    s, err := a.fetchSettings()
    if err != nil {
        return false, err
    }
    return convert.ToValue(s.MeetingSecurity.WaitingRoom), nil
}

func (a *mqlZoomAccount) meetingPasscodeRequired() (bool, error) {
    s, err := a.fetchSettings()
    if err != nil {
        return false, err
    }
    return convert.ToValue(s.MeetingSecurity.MeetingPasswordRequirement), nil
}

// cloudRecordingEnabled, cloudRecordingEncryptionEnabled, meetingEncryptionType,
// meetingE2eeAvailable, meetingAuthenticationRequired, meetingOnlyAccountUsersCanJoin,
// and signInSessionTimeoutMinutes all call fetchSettings() the same way, reading their
// respective field off the generated zoomapi.AccountSettings struct.
```

### Typed Resource References (via Internal struct)

`zoom.user` caches the raw `roleId` and `groupIds` from list/init time and resolves them lazily:

```go
type mqlZoomUserInternal struct {
    cacheRoleId   string
    cacheGroupIds []string
}

func (u *mqlZoomUser) role() (*mqlZoomRole, error) {
    if u.cacheRoleId == "" {
        u.Role.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    r, err := NewResource(u.MqlRuntime, "zoom.role", map[string]*llx.RawData{
        "id": llx.StringData(u.cacheRoleId),
    })
    if err != nil {
        return nil, err
    }
    return r.(*mqlZoomRole), nil
}

func (u *mqlZoomUser) groups() ([]any, error) {
    var all []any
    for _, id := range u.cacheGroupIds {
        r, err := NewResource(u.MqlRuntime, "zoom.group", map[string]*llx.RawData{
            "id": llx.StringData(id),
        })
        if err != nil {
            return nil, err
        }
        all = append(all, r)
    }
    return all, nil
}
```

### Cross-References (role/group membership, avoiding N+1)

`GET /roles/{roleId}/members` and `GET /groups/{groupId}/members` exist per-role/per-group (`client.ListRoleMembersWithResponse`, `client.ListGroupMembersWithResponse`), so `members()` is a direct paginated call rather than an in-memory filter over all users (unlike the DigitalOcean VPC/droplet cross-reference, Zoom's membership endpoints are already scoped server-side — no need to list every user and filter locally).

---

## Security Policies (MVP)

Ship as `mondoo-zoom-security.mql.yaml`:

**Meeting Security:**
- Meetings must have the waiting room enabled by default (`zoom.account.meetingWaitingRoomEnabled == true`)
- Meetings must require a passcode (`zoom.account.meetingPasscodeRequired == true`)
- Personal Meeting IDs must require a passcode (`zoom.account.meetingPmiPasscodeRequired == true`)
- End-to-end encryption must be available to hosts (`zoom.account.meetingE2eeAvailable == true`)
- Meeting participation must be restricted to authenticated / account-internal users (`zoom.account.meetingOnlyAccountUsersCanJoin == true`)

**Recording Security:**
- Cloud recordings must be encrypted at rest (`zoom.account.cloudRecordingEncryptionEnabled == true`)

**Identity & Access:**
- Single sign-on must be enabled for the account (`zoom.account.sso.enabled == true`)
- Sign-in sessions must time out within a bounded window (`zoom.account.signInSessionTimeoutMinutes > 0 && zoom.account.signInSessionTimeoutMinutes <= 480`)
- Membership in the `Owner` and `Admin` roles must be kept small (`zoom.roles.where(name == "Owner" || name == "Admin").all(totalMembers <= 3)`)
- Active users must be linked to SSO rather than local passwords (`zoom.users.where(status == "active").all(ssoLinked == true)`)

**Group-Level Overrides:**
- Group meeting-security overrides must not be weaker than the account defaults (waiting room, passcode, and authenticated-only-join all still enabled at the group level)

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/zoom` in `go.work` list
4. **`Makefile`** — `zoom` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/zoom/resources/zoom.lr \
  --dist providers/zoom/resources

# Build and install
make providers/build/zoom && make providers/install/zoom

# Test
export ZOOM_ACCOUNT_ID="xxxxxxxxxxxxxxxxxxxx"
export ZOOM_CLIENT_ID="xxxxxxxxxxxxxxxxxxxx"
export ZOOM_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mql shell zoom
> zoom.account { meetingWaitingRoomEnabled meetingPasscodeRequired meetingE2eeAvailable cloudRecordingEncryptionEnabled }
> zoom.account.sso { enabled domains groupMappingEnabled }
> zoom.users { email type status ssoLinked role { name } }
> zoom.roles { name totalMembers members { email } }
> zoom.groups { name settingsWaitingRoomEnabled settingsMeetingPasscodeRequired }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/zoom --provider-id zoom --provider-name "Zoom"` then `cd providers/zoom && go mod tidy`
1a. Vendor Zoom's OpenAPI spec, convert Swagger 2.0 → OAS 3, run `oapi-codegen` to produce `client/zoomapi.gen.go`; commit the converted spec and generated client
2. Server-to-Server OAuth connection via `clientcredentials.Config` + generated client (validates auth against `GET /users/me`)
3. Root + Account (meeting security, recording, sign-in fields — the core security surface)
4. SSO configuration
5. Users (with `role`/`groups` typed accessors)
6. Roles (with `members()`)
7. Groups (with `members()` and group-level security overrides)
8. Security policies
9. Discovery
10. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Zoom Server-to-Server OAuth](https://developers.zoom.us/docs/internal-apps/s2s-oauth/)
- [Zoom API Reference](https://developers.zoom.us/docs/api/)
- [Zoom Users API](https://developers.zoom.us/docs/api/users/)
- [Zoom Account API](https://developers.zoom.us/docs/api/rest/reference/account/methods/)
- [Zoom API Pagination](https://developers.zoom.us/docs/api/pagination/)
- [Meeting API Security Enhancements](https://developers.zoom.us/docs/api/references/meeting-api-security-enhancements/)
- [Zoom OpenAPI spec (`openapi.v2.json`, Swagger 2.0)](https://github.com/zoom/api/blob/master/openapi.v2.json) — vendor-published spec used for client generation; verified `"swagger": "2.0"` at the document root
- [`golang/oauth2` issue #283](https://github.com/golang/oauth2/issues/283) and [`clientcredentials.go`](https://github.com/golang/oauth2/blob/master/clientcredentials/clientcredentials.go) — confirms `EndpointParams["grant_type"]` override is supported, enabling Zoom's `account_credentials` grant through the standard package
- [`kin-openapi` `openapi2conv`](https://github.com/getkin/kin-openapi) — Swagger 2.0 → OpenAPI 3 converter used in the vendoring step
- [`oapi-codegen`](https://github.com/oapi-codegen/oapi-codegen) — OpenAPI v3 → Go client/types generator
- No official Zoom Terraform provider exists; community providers surveyed and not used as a naming source: [`folio-sec/zoom`](https://registry.terraform.io/providers/folio-sec/zoom/latest), [`CleverTap/zoom`](https://registry.terraform.io/providers/CleverTap/zoom/latest), [`fceller/zoom`](https://registry.terraform.io/providers/fceller/zoom/latest)
- Reference providers: `providers/shodan/`, `providers/tailscale/`, `providers/digitalocean/`
