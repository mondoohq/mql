# ADR-037: Bitwarden Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Bitwarden is a widely deployed password manager used by organizations to store and share credentials, and its **organization-level governance settings** (two-step login enforcement, SSO requirements, master password strength, member lifecycle, personal-vault restrictions) are exactly the kind of posture data cnspec customers already ask to audit for every other identity system in the fleet (Okta, Google Workspace, Microsoft Entra ID). Bitwarden exposes this governance surface through its **Public API**, a small REST API scoped to a single organization and authenticated with an organization API key via OAuth2 client-credentials.

**Client selection.** Following the house priority ladder (vendor Go SDK, then Terraform-alignment plus OpenAPI-generated client, then hand-written `net/http` only as a last resort), this ADR verified each rung before choosing:

1. **Official vendor SDK, `github.com/bitwarden/sdk-go`, does exist but does not cover this surface.** Its client interface (`NewBitwardenClient`, `AccessTokenLogin`, then `Projects`/`Secrets` sub-clients with Create/List/Get/Update/Delete) wraps only **Secrets Manager**, Bitwarden's machine-secrets product. It has no methods for organization members, policies, collections, groups, or events, so it cannot serve this provider and rung 1 is not available.
2. **No vendor SDK covers governance, so this provider lands on rung 2:** a client generated from Bitwarden's own **Public API OpenAPI v3 spec** (`bitwarden/docs` repo, `api/specs/public/swagger.json`, served live from the Swagger UI at `https://bitwarden.com/help/api/`), generated with `oapi-codegen` at build time rather than hand-written per-endpoint request/response structs. The generated client is wired to an OAuth2 `clientcredentials`-backed `*http.Client`, so the auth flow from the original draft is unchanged; only the request/response layer moves from hand-rolled structs to codegen. See the **Terraform provider alignment** note below for how this ADR's resource/field naming was cross-checked, and References for the codegen tool and spec location.

**Terraform provider alignment.** [`OneSignal/terraform-provider-bitwarden`](https://github.com/OneSignal/terraform-provider-bitwarden) targets the same surface as this ADR (its README states it is "for managing users and groups in Bitwarden for an organisation") and authenticates the same way, with a `client_id`/`client_secret` pair against the Public API. Its `bitwarden_group` resource's field set (`name`, with member management tracked as a follow-up) matches the `bitwarden.group` shape below. (`maxlaverse/terraform-provider-bitwarden`, the other community provider, was also checked but drives the Bitwarden CLI/embedded vault client against Password Manager items, not the Public API's organization governance endpoints, so it isn't the alignment reference here.) No Bitwarden Terraform provider is broad enough to mirror wholesale, so this ADR's schema follows the Public API's own resource shapes directly, checked against OneSignal's naming where they overlap.

**This provider reads organization governance only.** It authenticates as an organization, not a user, and the Public API it talks to has no endpoints for vault items, folders, ciphers, attachments, or Sends content — ownership and policy metadata only, never secret material. There is intentionally no code path in this provider that can retrieve a vault item, a password, or a Send's payload. Every resource below is metadata about *how the organization is configured*, not what its members store in it.

The Public API is available to Bitwarden Teams and Enterprise organizations (not Free/Families), and it is a distinct credential from a user's personal API key. Self-hosted Bitwarden deployments expose the same API surface at a customer-configured base URL, so the provider takes the API and identity URLs as overridable configuration rather than hardcoding the cloud endpoints.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `bitwarden` |
| **Provider ID** | `go.mondoo.com/mql/providers/bitwarden` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `bitwarden` |
| **Go SDK** | No vendor SDK covers this surface (`bitwarden/sdk-go` is Secrets-Manager-only); client generated via `oapi-codegen` from Bitwarden's Public API OpenAPI v3 spec, wired to `golang.org/x/oauth2/clientcredentials` |
| **API Type** | REST (Bitwarden Public API, `https://api.bitwarden.com`, self-hosted override supported) |
| **Auth** | Organization API key, OAuth2 client-credentials grant (`BITWARDEN_CLIENT_ID` / `BITWARDEN_CLIENT_SECRET` env vars or `--client-id` / `--client-secret` flags; optional `BITWARDEN_API_URL` / `BITWARDEN_IDENTITY_URL` for self-hosted) |

---

## Directory Structure

```
providers/bitwarden/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── config/
│   └── config.go
├── openapi/
│   ├── public-api.swagger.json     # vendored copy of bitwarden/docs' spec, pinned by hash
│   └── client.gen.go               # generated by oapi-codegen, do not hand-edit
├── connection/
│   ├── connection.go
│   └── client.go                   # thin wrapper: oauth2 http.Client -> openapi.ClientWithResponses
├── provider/
│   └── provider.go
└── resources/
    ├── bitwarden.lr
    ├── bitwarden.lr.go              # generated
    ├── bitwarden.lr.versions        # generated
    ├── discovery.go
    ├── bitwarden.go                 # root resource + organization
    ├── bitwarden_policy.go
    ├── bitwarden_member.go
    ├── bitwarden_collection.go
    └── bitwarden_group.go
```

`openapi/client.gen.go` is produced by `oapi-codegen -generate types,client -package openapi openapi/public-api.swagger.json`, invoked from `go generate` (`gen/main.go`), the same "generate, then commit the output" treatment as `.lr.go`: never hand-edit it, regenerate after bumping the vendored spec.

---

## Resource Schema (`bitwarden.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/bitwarden"
option go_package = "go.mondoo.com/mql/providers/bitwarden/resources"

// Bitwarden organization
//
// The root resource for a Bitwarden Teams or Enterprise organization,
// reached through an organization API key. It exposes governance state
// only: the organization's own settings, its security policies, its
// members, and the collections and groups used to structure vault
// access. Vault item contents, folders, and Send payloads are never
// read by this provider; the Bitwarden Public API this provider talks
// to has no endpoint for them.
bitwarden {
  // Security policies configured for the organization
  policies() []bitwarden.policy
  // Members of the organization
  members() []bitwarden.member
  // Collections used to group and share vault items
  collections() []bitwarden.collection
  // Groups used to assign collection access to multiple members at once
  groups() []bitwarden.group
}

// The organization's own account-level settings are exposed as a standalone
// top-level resource, `bitwarden.organization`, rather than an accessor on the
// `bitwarden` root. There is exactly one organization per connection (the one
// the API key authenticates as), so the resource is a singleton whose init
// reads GET /organization/subscription on demand and keys itself on the
// organization UUID. Query it directly, e.g. `bitwarden.organization { name
// seats useSso }`.

// Bitwarden organization
//
// Account-level settings for the organization the connection
// authenticates as: its name, seat allocation, and whether single
// sign-on or two-step login are available to it. The `id` field is
// the organization's UUID, the same value embedded in the
// `organization.<uuid>` client ID used to authenticate.
bitwarden.organization @defaults("name seats useSso use2fa") {
  // Organization UUID
  id string
  // Organization name
  name string
  // Number of seats purchased for the organization
  seats int
  // Number of seats currently occupied by confirmed or invited members
  occupiedSeats int
  // Maximum number of collections allowed, or null if unlimited
  maxCollections int
  // Maximum storage in gigabytes allowed, or null if unlimited
  maxStorageGb int
  // Whether the organization is enabled (not suspended or disabled)
  enabled bool
  // Whether the organization has single sign-on available
  useSso bool
  // Whether the organization has two-step login (2FA) available
  use2fa bool
  // Whether the organization has directory sync (SCIM) available
  useDirectory bool
  // Whether the organization has event logging available
  useEvents bool
  // Whether the organization has custom member roles available
  useCustomPermissions bool
  // Whether the organization has policy enforcement available
  usePolicies bool
  // Whether the organization has Bitwarden Send available
  useSend bool
  // Whether the organization has API access available
  useApi bool
  // Whether reset password enrollment is available for members
  useResetPassword bool
  // Subscription plan name (e.g. "Teams (Annually)", "Enterprise (Annually)")
  planName string
  // Business name shown on the subscription
  businessName string
}

// Bitwarden organization security policy
//
// A single organization-wide security policy as exposed by the
// Bitwarden Public API. The `policyType` field selects which control
// this policy enforces, for example `masterPassword`,
// `twoFactorAuthentication`, `requireSso`, `singleOrg`,
// `organizationDataOwnership` (personal-vault-ownership restriction),
// `sendOptions`, `passwordGenerator`, or `disablePersonalVaultExport`.
// The `enabled` field is the on/off switch; `data` carries the
// policy-specific configuration, whose shape depends on `policyType`:
// `masterPassword` carries `minComplexity`, `minLength`, `requireUpper`,
// `requireLower`, `requireNumbers`, and `requireSpecial`; `sendOptions`
// carries `disableHideEmail`; `resetPassword` carries
// `autoEnrollEnabled`; other types carry an empty object.
bitwarden.policy @defaults("policyType enabled") {
  // Policy UUID
  id string
  // Policy type
  //
  // One of masterPassword, twoFactorAuthentication, passwordGenerator,
  // singleOrg, requireSso, organizationDataOwnership (the current name
  // for what the Bitwarden UI still labels personal ownership),
  // disableSend, sendOptions, resetPassword, maximumVaultTimeout,
  // disablePersonalVaultExport, activateAutofill, automaticAppLogIn,
  // freeFamiliesSponsorshipPolicy, removeUnlockWithPin,
  // restrictedItemTypesPolicy, uriMatchDefaults, autotypeDefaultSetting,
  // automaticUserConfirmation, blockClaimedDomainAccountCreation,
  // organizationUserNotification, sendControls, or fillAssist.
  policyType string
  // Whether the policy is enabled
  enabled bool
  // Policy-specific configuration, shaped by policyType
  data dict
}

// Bitwarden organization member
//
// A user's membership in the organization: their role, invitation
// status, and security posture. The `email` field is the member's
// invited or confirmed email address and is the natural selection key,
// for example `bitwarden.members.where(email == "user@example.com")`.
bitwarden.member @defaults("email role status") {
  // Member UUID
  id string
  // Underlying Bitwarden user ID, null until the invitation is accepted
  userId string
  // Display name
  name string
  // Email address
  email string
  // Organization role
  //
  // One of owner, admin, user, or custom.
  role string
  // Invitation and confirmation status
  //
  // One of invited, accepted, confirmed, staged, or revoked. Only
  // confirmed members have completed enrollment and hold working
  // access to shared collections; invited and accepted members are
  // mid-onboarding.
  status string
  // Whether the member has two-factor authentication enabled
  twoFactorEnabled bool
  // Whether the member is enrolled in admin password reset
  resetPasswordEnrolled bool
  // Whether the member has access to all collections
  accessAllCollections bool
  // External identifier from a directory sync (SCIM) integration
  externalId string
  // Collections the member has explicit access to
  collections() []bitwarden.collection
  // Groups the member belongs to
  groups() []bitwarden.group
}

// Bitwarden collection
//
// A named grouping of vault items shared with specific members and
// groups. Only the sharing structure is exposed here (which groups and
// members can reach the collection, and with what permissions); the
// items inside a collection are not.
bitwarden.collection @defaults("name") {
  // Collection UUID
  id string
  // Collection name
  name string
  // External identifier from a directory sync (SCIM) integration
  externalId string
  // Groups granted access to this collection
  groups() []bitwarden.group
  // Members granted explicit access to this collection
  members() []bitwarden.member
}

// Bitwarden group
//
// A named set of members used to assign collection access in bulk,
// as an alternative to granting each member individually. The `name`
// field is the natural selection key, for example
// `bitwarden.groups.where(name == "Engineering")`.
bitwarden.group @defaults("name") {
  // Group UUID
  id string
  // Group name
  name string
  // Whether members of this group have access to all collections
  accessAll bool
  // External identifier from a directory sync (SCIM) integration
  externalId string
  // Members belonging to this group
  members() []bitwarden.member
  // Collections this group has access to
  collections() []bitwarden.collection
}
```

---

## Authentication

Organization API key exchanged for a bearer token via OAuth2 client-credentials. The token flow is identical to the original SDK-less draft; what changes under the rung-2 decision is that the resulting `*http.Client` is handed to the **generated** `openapi.ClientWithResponses` instead of a hand-rolled REST wrapper (see `providers/shodan/connection/connection.go` for the overall connection-struct shape; this one substitutes a token source plus a generated client for a static-token client):

```go
package connection

import (
    "context"
    "errors"
    "os"

    "go.mondoo.com/mql/providers/bitwarden/openapi"
    "go.mondoo.com/mql/providers-sdk/v1/inventory"
    "go.mondoo.com/mql/providers-sdk/v1/plugin"
    "go.mondoo.com/mql/providers-sdk/v1/vault"
    "golang.org/x/oauth2/clientcredentials"
)

const (
    defaultApiUrl      = "https://api.bitwarden.com"
    defaultIdentityUrl = "https://identity.bitwarden.com/connect/token"
)

type BitwardenConnection struct {
    plugin.Connection
    Conf   *inventory.Config
    asset  *inventory.Asset
    client *openapi.ClientWithResponses // generated from the Public API OpenAPI spec
    orgID  string
}

func NewBitwardenConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*BitwardenConnection, error) {
    conn := &BitwardenConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    clientID := os.Getenv("BITWARDEN_CLIENT_ID")
    clientSecret := os.Getenv("BITWARDEN_CLIENT_SECRET")
    for _, cred := range conf.Credentials {
        if cred.Type == vault.CredentialType_password {
            clientSecret = string(cred.Secret)
        }
    }
    if v, ok := conf.Options["client-id"]; ok {
        clientID = v
    }
    if clientID == "" || clientSecret == "" {
        return nil, errors.New(
            "a Bitwarden organization client ID and client secret are required " +
                "(set BITWARDEN_CLIENT_ID / BITWARDEN_CLIENT_SECRET or use --client-id / --client-secret)")
    }

    apiUrl := firstNonEmpty(conf.Options["api-url"], os.Getenv("BITWARDEN_API_URL"), defaultApiUrl)
    identityUrl := firstNonEmpty(conf.Options["identity-url"], os.Getenv("BITWARDEN_IDENTITY_URL"), defaultIdentityUrl)

    // client_id has the form "organization.<uuid>"; extract the org UUID
    // for use as the __id of the root organization resource.
    orgID := orgIDFromClientID(clientID)

    oauthConf := &clientcredentials.Config{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        TokenURL:     identityUrl,
        Scopes:       []string{"api.organization"},
    }

    genClient, err := openapi.NewClientWithResponses(apiUrl,
        openapi.WithHTTPClient(oauthConf.Client(context.Background())))
    if err != nil {
        return nil, err
    }
    conn.client = genClient
    conn.orgID = orgID

    return conn, nil
}
```

`connection/client.go` stays thin: it exposes `conn.Client() *openapi.ClientWithResponses` and a handful of typed convenience wrappers (e.g. `conn.ListMembers(ctx)`) that call the generated `*WithResponse` methods and unwrap the `.JSON200`/error branches those methods return, so resource code never touches raw `*http.Response` bodies.

---

## Implementation Patterns

### Token Exchange (once per connection, transparently refreshed)

`clientcredentials.Config.Client(ctx)` returns an `*http.Client` that fetches and caches the bearer token on first use and transparently refreshes it when it nears the 3600-second expiry, so no manual token bookkeeping is needed in the resource code. That client is the one wired into `openapi.NewClientWithResponses` at connection time, so every generated method (`GetPublicMembersWithResponse`, `GetPublicPoliciesWithResponse`, ...) is already authenticated.

### Simple List (most endpoints; `{ object: "list", data: [...] }`, via the generated client)

The Public API is small and its list endpoints are effectively unpaginated for the volumes a single organization has (a `continuationToken` field exists in the response envelope for very large result sets, but organization member/collection/group/policy counts rarely approach it). The generated `openapi.ListResponseModel[T]` type models that envelope; follow its `ContinuationToken` when present rather than assuming a single page:

```go
func (b *mqlBitwarden) members() ([]any, error) {
    conn := b.MqlRuntime.Connection.(*connection.BitwardenConnection)

    var all []any
    var token *string
    for {
        resp, err := conn.Client().GetPublicMembersWithResponse(context.Background(),
            &openapi.GetPublicMembersParams{ContinuationToken: token})
        if err != nil {
            return nil, err
        }
        if resp.JSON200 == nil {
            return nil, fmt.Errorf("bitwarden: unexpected response listing members: %s", resp.Status())
        }
        for _, m := range resp.JSON200.Data {
            r, err := CreateResource(b.MqlRuntime, "bitwarden.member", map[string]*llx.RawData{
                "__id":                  llx.StringData(m.Id.String()),
                "id":                    llx.StringData(m.Id.String()),
                "userId":                llx.StringDataPtr(uuidStrPtr(m.UserId)),
                "name":                  llx.StringDataPtr(m.Name),
                "email":                 llx.StringData(m.Email),
                "role":                  llx.StringData(roleName(m.Type)),
                "status":                llx.StringData(statusName(m.Status)),
                "twoFactorEnabled":      llx.BoolData(m.TwoFactorEnabled),
                "resetPasswordEnrolled": llx.BoolData(m.ResetPasswordEnrolled),
                "accessAllCollections":  llx.BoolData(m.AccessAll),
                "externalId":            llx.StringDataPtr(m.ExternalId),
            })
            if err != nil {
                return nil, err
            }
            all = append(all, r)
        }
        if resp.JSON200.ContinuationToken == nil {
            break
        }
        token = resp.JSON200.ContinuationToken
    }
    return all, nil
}
```

`roleName`/`statusName` translate the generated `openapi.OrganizationUserType`/`openapi.OrganizationUserStatusType` integer enums to the stable lowercase strings the `.lr` schema documents (`owner`/`admin`/`user`/`custom`, `invited`/`accepted`/`confirmed`/`staged`/`revoked`) so query authors never depend on Bitwarden's internal numbering.

### Policy List (`GetPublicPoliciesWithResponse`, one call, twenty-some rows)

```go
func (b *mqlBitwarden) policies() ([]any, error) {
    conn := b.MqlRuntime.Connection.(*connection.BitwardenConnection)

    resp, err := conn.Client().GetPublicPoliciesWithResponse(context.Background())
    if err != nil {
        return nil, err
    }
    if resp.JSON200 == nil {
        return nil, fmt.Errorf("bitwarden: unexpected response listing policies: %s", resp.Status())
    }

    var all []any
    for _, p := range resp.JSON200.Data {
        data, err := convert.JsonToDict(p.Data)
        if err != nil {
            return nil, err
        }
        r, err := CreateResource(b.MqlRuntime, "bitwarden.policy", map[string]*llx.RawData{
            "__id":       llx.StringData(p.Id.String()),
            "id":         llx.StringData(p.Id.String()),
            "policyType": llx.StringData(policyTypeName(p.Type)),
            "enabled":    llx.BoolData(p.Enabled),
            "data":       llx.DictData(data),
        })
        if err != nil {
            return nil, err
        }
        all = append(all, r)
    }
    return all, nil
}
```

### Typed Cross-References (member <-> group <-> collection, via Internal struct)

The Public API returns a member's or group's collection/group associations as ID lists embedded in the same response (generated methods `GetPublicMembersIdGroupIdsWithResponse`, `GetPublicGroupsIdMemberIdsWithResponse`), not as a separate join endpoint. Cache the raw ID lists on creation and resolve them lazily so a query that never touches `groups` or `collections` never issues the extra call:

```go
type mqlBitwardenMemberInternal struct {
    cacheGroupIds      []string
    cacheCollectionIds []string
}

func (m *mqlBitwardenMember) groups() ([]any, error) {
    if len(m.cacheGroupIds) == 0 {
        m.Groups.State = plugin.StateIsSet
        return nil, nil
    }
    var all []any
    for _, id := range m.cacheGroupIds {
        r, err := NewResource(m.MqlRuntime, "bitwarden.group", map[string]*llx.RawData{"id": llx.StringData(id)})
        if err != nil {
            log.Warn().Err(err).Str("id", id).Msg("bitwarden: failed to resolve group")
            continue
        }
        all = append(all, r)
    }
    return all, nil
}
```

`bitwarden.group`'s `init` accepts `id` and resolves it against an org-wide group listing cached once per connection (Pattern C: cross-references filtered in memory, avoiding an N+1 `GetPublicGroupsIdWithResponse` call per member).

---

## Security Policies (MVP)

Ship as `mondoo-bitwarden-security.mql.yaml` (in the cnspec `content/` repository, not this one):

**Authentication & Access:**
- Two-step login (2FA) required policy must be enabled (`bitwarden.policies.where(policyType == "twoFactorAuthentication").any(enabled)`)
- SSO authentication must be required for the organization when SSO is available (`requireSso` policy enabled)
- Single-organization policy must be enabled, preventing members from also belonging to unmanaged organizations
- Master password strength policy must be enforced with a minimum complexity score

**Vault Data Governance:**
- Personal ownership must be disabled (`organizationDataOwnership` policy enabled), so vault items are created in the organization, not a member's personal vault
- Vault export via the personal vault must be disabled where the organization does not require it

**Member Hygiene:**
- All confirmed members must have two-factor authentication enabled (`bitwarden.members.where(status == "confirmed").all(twoFactorEnabled)`)
- No members may remain in `invited` or `accepted` status past a defined staleness window (stale onboarding is a common cnspec finding pattern; the check itself needs an `asset` timestamp comparison outside this provider's scope, so the MVP flags any `invited`/`accepted` member and lets the policy author add a time bound later)
- The number of members with the `owner` or `admin` role must stay under an organization-defined ceiling

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags (`--client-id`, `--client-secret`, `--api-url`, `--identity-url`)
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/bitwarden` in `go.work` list
4. **`Makefile`** — `bitwarden` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/bitwarden/resources/bitwarden.lr \
  --dist providers/bitwarden/resources

# Build and install
make providers/build/bitwarden && make providers/install/bitwarden

# Test
export BITWARDEN_CLIENT_ID="organization.00000000-0000-0000-0000-000000000000"
export BITWARDEN_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mql shell bitwarden
> bitwarden.organization
> bitwarden.policies { policyType enabled data }
> bitwarden.members { email role status twoFactorEnabled resetPasswordEnrolled }
> bitwarden.groups { name members { email } }
> bitwarden.collections { name groups { name } members { email } }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/bitwarden --provider-id bitwarden --provider-name "Bitwarden"` then `cd providers/bitwarden && go mod tidy`
1.5. Vendor `api/specs/public/swagger.json` from `bitwarden/docs` into `openapi/public-api.swagger.json` and wire `go generate` to run `oapi-codegen -generate types,client -package openapi` over it, producing `openapi/client.gen.go`
2. Connection + token exchange (validates auth: the organization's own details aren't reachable through a dedicated endpoint, so validate by calling `GetPublicPoliciesWithResponse` and treating a 401 as an auth failure)
3. Root + Organization (validates auth end to end)
4. Policies (smallest, highest security value, no cross-references)
5. Members (role/status enum translation, largest field set)
6. Groups + Collections (cross-references to members via `*-ids` endpoints)
7. Security policies
8. Discovery (single organization asset per connection; no fan-out to child assets)
9. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Bitwarden Public API reference](https://bitwarden.com/help/api/)
- [Bitwarden Public API overview (Contributing docs)](https://contributing.bitwarden.com/getting-started/server/public-api/)
- [Bitwarden organization API keys](https://bitwarden.com/help/public-api/)
- [`bitwarden/docs` Public API OpenAPI v3 spec](https://github.com/bitwarden/docs/blob/master/api/specs/public/swagger.json) (the spec generated into `openapi/client.gen.go`)
- [`bitwarden/sdk-go`](https://github.com/bitwarden/sdk-go) (checked and ruled out: covers Secrets Manager, not the Public API's organization governance endpoints)
- [`OneSignal/terraform-provider-bitwarden`](https://github.com/OneSignal/terraform-provider-bitwarden) (Terraform provider alignment reference: same Public API surface, same client-credentials auth)
- [`bitwarden/server` `PolicyType` enum (source of truth for policy types)](https://github.com/bitwarden/server/blob/main/src/Core/AdminConsole/Enums/PolicyType.cs)
- [`oapi-codegen`](https://github.com/oapi-codegen/oapi-codegen) (OpenAPI v3 to Go client/types generator used to produce `openapi/client.gen.go`)
- [`golang.org/x/oauth2/clientcredentials`](https://pkg.go.dev/golang.org/x/oauth2/clientcredentials)
- Reference providers: `providers/shodan/`, `providers/ipinfo/` (single API-key/token auth mode; unlike Bitwarden, neither has a vendor OpenAPI spec to generate a client from)
