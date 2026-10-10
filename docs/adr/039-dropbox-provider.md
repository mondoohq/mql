# ADR-039: Dropbox Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Dropbox Business (the team-plan tier of Dropbox) exposes a REST API for team administration: enumerating members, groups, linked devices, linked third-party apps, and team-wide security settings (SSO enforcement, two-step verification requirements, sharing restrictions, file-transfer limits). Unlike the personal Dropbox API, every Business endpoint lives under the `/2/team/...` namespace and is authorized with a team-scoped OAuth access token issued to a Dropbox Business App, not a per-user token. There is no complex resource graph to model (no IAM policy trees, no networking) and pagination follows one consistent `*/list` + `*/list/continue` cursor shape across almost every list endpoint, making this a good candidate for a small, security-focused provider: the goal is visibility into team security posture (who has 2FA, whether SSO is required, which devices and third-party apps are linked to member accounts), not general file/content access.

**Client selection.** Per the provider client-selection priority ladder (1: official vendor Go SDK, 2: harmonize with the vendor's Terraform provider + generate from OpenAPI v3, 3: hand-written `net/http` client as a last resort), this ADR lands on rung 1: `dropbox-sdk-go-unofficial` lives in the `dropbox` GitHub org and is machine-generated from Dropbox's own Stone API spec, making it the vendor SDK despite the "unofficial" name in its module path (a historical artifact of it predating Dropbox formally adopting the repo). A web search for a mainstream Dropbox Business Terraform provider turned up nothing: the only public listing (`callensm/dropbox` on the Terraform Registry) is a small, independently maintained, individual-author provider covering personal file/folder resources, not the `team/...` Business admin surface this ADR needs, and it is not vendor-published — so rung 2 (Terraform harmonization) does not apply here, it was checked and found inapplicable rather than skipped.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `dropbox` |
| **Provider ID** | `go.mondoo.com/mql/providers/dropbox` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `dropbox` |
| **Go SDK** | `github.com/dropbox/dropbox-sdk-go-unofficial/v6` (vendor-hosted, generated from Dropbox's official Stone API spec; "unofficial" is a legacy naming artifact, not a provenance warning) |
| **API Type** | REST (Dropbox Business API v2, `team/...` endpoints) |
| **Auth** | Dropbox Business access token, scoped OAuth (Team Information, Team Auditing, Team Member Management) (`DROPBOX_TEAM_TOKEN` env var or `--token` flag) |

---

## Directory Structure

```
providers/dropbox/
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
    ├── dropbox.lr
    ├── dropbox.lr.go              # generated
    ├── dropbox.lr.versions        # generated
    ├── discovery.go
    ├── dropbox.go                 # root resource
    ├── team.go
    ├── member.go
    ├── group.go
    ├── device.go
    ├── linkedapp.go
    └── pagination.go              # generic cursor-paginated list helper
```

---

## Resource Schema (`dropbox.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/dropbox"
option go_package = "go.mondoo.com/mql/providers/dropbox/resources"

// Dropbox Business team
//
// Root of a Dropbox Business team account, reachable through a
// team-scoped access token. Exposes the team's identity and size via
// `team`, the members enrolled in it, the groups used to manage sharing
// and permissions, the devices linked to member accounts, and the
// third-party apps members have authorized. Use this resource to audit
// a team's overall security posture: authentication requirements,
// external sharing exposure, and the devices and apps with standing
// access to team data.
dropbox {
  // Team information (name, member counts, team-wide feature values)
  team() dropbox.team
  // Team members
  members() []dropbox.member
  // Team-managed groups
  groups() []dropbox.group
  // Devices linked to team member accounts
  devices() []dropbox.device
  // Third-party apps linked to team member accounts
  linkedApps() []dropbox.linkedApp
}

// Dropbox Business team account
//
// Team-wide identity and configuration returned by `team/get_info` and
// `team/features/get_values`. Carries the settings that shape a team's
// authentication and sharing posture: whether single sign-on is
// required, the file-upload API rate limit, and the team's member
// counts. There is one `team` per Dropbox Business account.
private dropbox.team @defaults("name") {
  // Team name
  name string
  // Team ID
  id string
  // Number of licensed users
  numLicensedUsers int
  // Number of members who have joined the team
  numProvisionedUsers int
  // Number of members with an active (non-suspended) account
  numUsedLicenses int
  // Whether single sign-on is required for all members to log in
  ssoRequired bool
  // Single sign-on enforcement state as returned by the API (e.g. "disabled", "optional", "required")
  ssoState string
  // Whether team folders are available on this team's plan
  teamFoldersAvailable bool
  // Whether team members can share files and folders outside the team
  externalSharingAllowed bool
  // Whether team members can create publicly accessible shared links
  publicSharingAllowed bool
  // Whether two-step verification is required for all team members
  twoStepVerificationRequired bool
  // Upload API rate limit in requests per minute, 0 when no limit is configured
  uploadApiRateLimit int
}

// Dropbox Business team member
//
// A single member enrolled in the team, selected by `teamMemberId` as
// returned by `team/members/list`. Carries the member's login email,
// role, account status, and two-step verification state, the security
// signals most relevant to auditing account takeover risk across a
// team. The `secondaryEmails` field lists additional verified addresses
// tied to the same account.
dropbox.member @defaults("email status") {
  // Team member ID
  teamMemberId string
  // Primary login email address
  email string
  // Whether the primary email has been verified
  emailVerified bool
  // Member's display name
  displayName string
  // Account status: active, invited, or suspended
  status string
  // Membership type: full member or a limited "bounced_pending" invite state
  membershipType string
  // Role name assigned to the member (e.g. team_admin, user_management_admin, member_only)
  role string
  // Whether the member has enabled two-step verification
  twoFactorEnabled bool
  // Additional verified email addresses linked to the account
  secondaryEmails []string
  // Timestamp the member joined the team
  joinedAt time
  // Devices linked to this member's account
  devices() []dropbox.device
  // Third-party apps this member has linked
  linkedApps() []dropbox.linkedApp
}

// Dropbox Business group
//
// A team-managed group used to organize members for sharing and
// permission assignment, selected by `groupId` as returned by
// `team/groups/list`. Groups created and managed within the admin
// console (`management_type` of `user_managed` or `company_managed`)
// are distinguished from groups synced in from an external identity
// provider.
dropbox.group @defaults("name memberCount") {
  // Group ID
  groupId string
  // Group name
  name string
  // Whether the group's membership is externally synced from an identity provider
  externalId bool
  // Number of members in the group
  memberCount int
  // Group management type: user_managed, company_managed, or system_managed
  managementType string
}

// Device linked to a Dropbox Business member account
//
// A single client session or linked device for a team member, as
// returned by `team/devices/list_members_devices`. Covers both desktop
// and mobile clients as well as active web sessions, distinguished by
// `clientType`. Use `lastActivity` to find stale sessions that should
// be revoked.
dropbox.device @defaults("clientType hostName") {
  // Session or device ID
  id string
  // Client type: desktop, mobile, or web
  clientType string
  // Device or session display name
  hostName string
  // Client application version, empty for web sessions
  clientVersion string
  // Platform the client runs on (e.g. Windows, macOS, iOS, Android)
  platform string
  // IP address the session was last seen from
  ipAddress string
  // Country the session was last seen from
  country string
  // Whether the device's local storage is encrypted, when reported by the client
  isDeleteOnUnlinkSupported bool
  // Timestamp the client was linked to the account
  createdAt time
  // Timestamp of the client's last recorded activity
  lastActivity time
}

// Third-party app linked to a Dropbox Business member account
//
// An OAuth application a team member has authorized against their
// Dropbox account, as returned by
// `team/linked_apps/list_members_linked_apps`. Use this to audit the
// blast radius of third-party integrations with standing access to
// team content.
dropbox.linkedApp @defaults("appName publisherName") {
  // App ID
  appId string
  // App display name
  appName string
  // App publisher name
  publisherName string
  // Publisher's URL, empty when not provided by the app
  publisherUrl string
  // Timestamp the member linked the app
  linked time
  // Whether the app was granted access to the member's entire Dropbox, not just an app folder
  isAppFolder bool
}
```

---

## Authentication

Single team-scoped access token, following the Shodan single-token pattern (`providers/shodan/connection/connection.go`):

```go
type DropboxConnection struct {
    plugin.Connection
    Conf   *inventory.Config
    asset  *inventory.Asset
    client team.Client
}

func NewDropboxConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DropboxConnection, error) {
    conn := &DropboxConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    token := os.Getenv("DROPBOX_TEAM_TOKEN")
    if len(conf.Credentials) > 0 {
        for _, cred := range conf.Credentials {
            if cred.Type == vault.CredentialType_password {
                token = string(cred.Secret)
            }
        }
    }
    if token == "" {
        return nil, errors.New("a valid Dropbox Business team access token is required (set DROPBOX_TEAM_TOKEN or use --token)")
    }

    config := dropbox.Config{
        Token:    token,
        LogLevel: dropbox.LogOff,
    }
    conn.client = team.New(config)

    return conn, nil
}
```

Notes:
- The token must come from a Dropbox **Business App** (App Console, "Scoped access" with team-level permission type). A regular per-user app token is rejected by every `team/...` endpoint with an `invalid_access_token` error.
- Required scopes for the resources modeled here: `team_info.read` (`team/get_info`, `team/features/get_values`), `members.read` (`team/members/list`), `groups.read` (`team/groups/list`), and `sessions.list` (`team/devices/list_members_devices`, `team/linked_apps/list_members_linked_apps`). No write scopes are needed since this provider is read-only.

---

## Implementation Patterns

### Generic Cursor Pagination (`*/list` + `*/list/continue`)

Nearly every Dropbox Business list endpoint follows the same two-call shape: an initial `X/list` call that accepts a page-size limit and returns a `cursor` plus `has_more`, followed by repeated `X/list/continue` calls (taking only the cursor) until `has_more` is false. Model this once and reuse it:

```go
// pagination.go

// pagedFetch abstracts the Dropbox "list" + "list/continue" cursor pattern.
// first calls the initial X/list endpoint; next calls X/list/continue with
// the returned cursor. Both return the page's items, the next cursor, and
// whether more pages remain.
func pagedFetch[T any](
    first func() ([]T, string, bool, error),
    next func(cursor string) ([]T, string, bool, error),
) ([]T, error) {
    items, cursor, hasMore, err := first()
    if err != nil {
        return nil, err
    }
    all := append([]T{}, items...)
    for hasMore {
        items, cursor, hasMore, err = next(cursor)
        if err != nil {
            return nil, err
        }
        all = append(all, items...)
    }
    return all, nil
}
```

Usage for members:

```go
func (d *mqlDropbox) members() ([]any, error) {
    conn := d.MqlRuntime.Connection.(*connection.DropboxConnection)
    client := conn.Client()

    members, err := pagedFetch(
        func() ([]*team.TeamMemberInfo, string, bool, error) {
            resp, err := client.MembersListV2(&team.MembersListArg{Limit: 1000})
            if err != nil {
                return nil, "", false, err
            }
            return resp.Members, resp.Cursor, resp.HasMore, nil
        },
        func(cursor string) ([]*team.TeamMemberInfo, string, bool, error) {
            resp, err := client.MembersListContinueV2(&team.MembersListContinueArg{Cursor: cursor})
            if err != nil {
                return nil, "", false, err
            }
            return resp.Members, resp.Cursor, resp.HasMore, nil
        },
    )
    if err != nil {
        return nil, err
    }

    var all []any
    for _, m := range members {
        r, err := CreateResource(d.MqlRuntime, "dropbox.member", map[string]*llx.RawData{
            "teamMemberId":     llx.StringData(m.Profile.TeamMemberId),
            "email":            llx.StringData(m.Profile.Email),
            "emailVerified":    llx.BoolData(m.Profile.EmailVerified),
            "displayName":      llx.StringData(m.Profile.Name.DisplayName),
            "status":           llx.StringData(m.Profile.Status.Tag),
            "membershipType":   llx.StringData(m.Profile.MembershipType.Tag),
            "role":             llx.StringData(roleName(m.Role)),
            "twoFactorEnabled": llx.BoolData(m.Profile.Secondary2Fa),
            "secondaryEmails":  llx.ArrayData(convert.SliceAnyToInterface(secondaryEmails(m.Profile.SecondaryEmails)), types.String),
            "joinedAt":         llx.TimeDataPtr(m.Profile.JoinedOn),
        })
        if err != nil {
            return nil, err
        }
        all = append(all, r)
    }
    return all, nil
}
```

### Team Settings from `team/features/get_values`

Some security-relevant settings (SSO state, upload rate limit) are not part of `team/get_info` and require a separate `team/features/get_values` call requesting specific feature values. Fetch and cache these once alongside `team/get_info` when the `team()` accessor is first resolved:

```go
func (d *mqlDropbox) team() (*mqlDropboxTeam, error) {
    conn := d.MqlRuntime.Connection.(*connection.DropboxConnection)
    client := conn.Client()

    info, err := client.GetInfo()
    if err != nil {
        return nil, err
    }

    features, err := client.FeaturesGetValues(&team.FeaturesGetValuesBatchArg{
        Features: []*team.Feature{
            &team.Feature{Tagged: mkTag("upload_api_rate_limit")},
            &team.Feature{Tagged: mkTag("has_team_selective_sync")},
        },
    })
    if err != nil {
        // feature values are a nice-to-have; degrade gracefully rather than
        // failing the whole team() resolution
        log.Warn().Err(err).Msg("failed to fetch dropbox team feature values")
    }

    r, err := CreateResource(d.MqlRuntime, "dropbox.team", map[string]*llx.RawData{
        "__id":                 llx.StringData(info.TeamId),
        "id":                   llx.StringData(info.TeamId),
        "name":                 llx.StringData(info.Name),
        "numLicensedUsers":     llx.IntData(int64(info.NumLicensedUsers)),
        "numProvisionedUsers":  llx.IntData(int64(info.NumProvisionedUsers)),
        "uploadApiRateLimit":   llx.IntData(uploadRateLimitFrom(features)),
        // ssoState/ssoRequired/twoStepVerificationRequired come from
        // team/team_policies exposed on GetInfo's policies field, or a
        // second features batch, depending on the app's granted scopes.
    })
    if err != nil {
        return nil, err
    }
    return r.(*mqlDropboxTeam), nil
}
```

### Member-Scoped Sub-Resources (devices, linked apps)

`team/devices/list_members_devices` and `team/linked_apps/list_members_linked_apps` both return their results grouped by `team_member_id` in a single paginated call, not one call per member. Fetch once, cache in an `Internal` struct on the root resource, and let both `dropbox.devices()` (flat, team-wide) and `dropbox.member.devices()` (filtered) read from the same cache:

```go
type mqlDropboxInternal struct {
    devicesOnce   sync.Once
    devicesByUser map[string][]any
    devicesErr    error
}

func (d *mqlDropbox) fetchDevicesByUser() (map[string][]any, error) {
    d.devicesOnce.Do(func() {
        conn := d.MqlRuntime.Connection.(*connection.DropboxConnection)
        client := conn.Client()
        result := map[string][]any{}

        pages, err := pagedFetch(
            func() ([]*team.MembersListMemberDevicesResult, string, bool, error) { /* ... */ },
            func(cursor string) ([]*team.MembersListMemberDevicesResult, string, bool, error) { /* ... */ },
        )
        if err != nil {
            d.devicesErr = err
            return
        }
        for _, page := range pages {
            for _, dev := range page.ActiveWebSessions {
                r, err := CreateResource(d.MqlRuntime, "dropbox.device", map[string]*llx.RawData{
                    "__id":       llx.StringData(page.TeamMemberId + "/" + dev.SessionId),
                    "id":         llx.StringData(dev.SessionId),
                    "clientType": llx.StringData("web"),
                    // ...
                })
                if err != nil {
                    d.devicesErr = err
                    return
                }
                result[page.TeamMemberId] = append(result[page.TeamMemberId], r)
            }
            // same pattern for DesktopClients and MobileClientSessions
        }
        d.devicesByUser = result
    })
    return d.devicesByUser, d.devicesErr
}
```

---

## Security Policies (MVP)

Ship as `mondoo-dropbox-security.mql.yaml`:

**Authentication:**
- Team members must have two-step verification enabled
- Team must require single sign-on (`ssoRequired == true`)
- Suspended or long-pending invited members must be reviewed and removed

**Access Governance:**
- Number of `team_admin` role members must be limited (principle of least privilege)
- Team must not allow unrestricted external sharing
- Team must not allow public shared links, or must restrict them to view-only

**Third-Party Exposure:**
- Linked third-party apps must be reviewed; apps with full-account access (`isAppFolder == false`) flagged for scrutiny
- Linked devices must be reviewed; sessions with stale `lastActivity` flagged for revocation

**Example checks:**

```yaml
- uid: dropbox-members-2fa-enabled
  title: Ensure all team members have two-step verification enabled
  mql: |
    dropbox.members.all(twoFactorEnabled == true)

- uid: dropbox-sso-required
  title: Ensure the team requires single sign-on
  mql: |
    dropbox.team.ssoRequired == true

- uid: dropbox-external-sharing-restricted
  title: Ensure external sharing is restricted
  mql: |
    dropbox.team.externalSharingAllowed == false

- uid: dropbox-admin-count-limited
  title: Ensure the number of team admins is limited
  mql: |
    dropbox.members.where(role == "team_admin").length <= 3

- uid: dropbox-no-stale-invited-members
  title: Ensure invited members are not left pending indefinitely
  mql: |
    dropbox.members.where(status == "invited").length == 0
```

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/dropbox` in `go.work` list
4. **`Makefile`** — `dropbox` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/dropbox/resources/dropbox.lr \
  --dist providers/dropbox/resources

# Build and install
make providers/build/dropbox && make providers/install/dropbox

# Test
export DROPBOX_TEAM_TOKEN="sl.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mql shell dropbox
> dropbox.team { name numLicensedUsers ssoRequired twoStepVerificationRequired }
> dropbox.members { email status role twoFactorEnabled }
> dropbox.groups { name memberCount managementType }
> dropbox.devices { clientType hostName lastActivity }
> dropbox.linkedApps { appName publisherName isAppFolder }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/dropbox --provider-id dropbox --provider-name "Dropbox"` then `cd providers/dropbox && go mod tidy`
2. Root + Team (validates auth, exercises `team/get_info` and `team/features/get_values`)
3. Generic cursor pagination helper (`pagination.go`), shared by every list resource
4. Members (core security resource: 2FA, role, status)
5. Groups
6. Devices (member-scoped fetch-once cache, exposed both flat and per-member)
7. Linked Apps (same member-scoped cache pattern as Devices)
8. Security policies
9. Discovery
10. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Dropbox Business API Reference](https://www.dropbox.com/developers/documentation/http/teams)
- [DBX Team Administration Guide](https://docs.dropboxapi.com/dropbox-api/docs/team-administration)
- [dropbox-sdk-go-unofficial (v6)](https://github.com/dropbox/dropbox-sdk-go-unofficial) — hosted under the `dropbox` GitHub org, generated from the official Stone API spec (rung 1 of the client-selection ladder)
- [Dropbox App Console (scoped team apps)](https://www.dropbox.com/developers/apps)
- [`callensm/dropbox` Terraform provider](https://registry.terraform.io/providers/callensm/dropbox/latest/docs) — checked for rung-2 harmonization; independently maintained, personal-Dropbox scope, not a mainstream vendor Business provider, so not applicable here
- Reference providers: `providers/shodan/`, `providers/tailscale/`
