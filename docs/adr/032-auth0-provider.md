# ADR-032: Auth0 Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Auth0 is a widely deployed identity-as-a-service platform (now part of Okta) that customer tenants use to authenticate end users and machine clients, federate external identity providers, and issue OAuth/OIDC tokens. Its Management API v2 is a well-documented REST API with a maintained Go SDK (`auth0/go-auth0`), and authentication is a single, well-understood machine-to-machine (M2M) client-credentials flow rather than the sprawling IAM surface of a hyperscaler. That combination, a REST API, one auth pattern, and a security-relevant but bounded resource set, makes it a good next SaaS provider after `okta` and `tailscale`: most of the value comes from auditing tenant-wide authentication hardening (MFA, breached-password detection, brute-force protection, token lifetimes, refresh-token rotation) rather than from modeling every object the API exposes.

This ADR scopes the provider to the resources that carry security signal: tenant settings, applications (`client`), identity connections, users, roles, actions, log streams, and the tenant's attack-protection configuration. It intentionally excludes lower-value objects (branding, custom domains cosmetics, prompts/rules-v1 legacy fields, blacklists) from the MVP; those can follow in later iterations once the core provider ships.

**Terraform provider alignment.** `github.com/auth0/go-auth0` is the official vendor Go SDK and covers every endpoint this ADR needs, so client selection stays on rung 1 of the SDK priority ladder; no OpenAPI generation or hand-written HTTP client is warranted. Auth0 also publishes an official Terraform provider (`auth0/terraform-provider-auth0`), and this schema's resource and field names (`auth0.tenant`, `auth0.client`, `auth0.connection`, `auth0.role`, `auth0.action`) are chosen to line up with that provider's `auth0_tenant`, `auth0_client`, `auth0_connection`, `auth0_role`, and `auth0_action` resource schemas wherever the concepts overlap. Keeping the two in sync means a field an engineer recognizes from a Terraform config (grant types, refresh-token rotation, password policy) resolves to the same name and shape in MQL, and any future resource-server modeling should follow the Terraform provider's `auth0_resource_server` schema for the same reason.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `auth0` |
| **Provider ID** | `go.mondoo.com/mql/providers/auth0` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `auth0` |
| **Go SDK** | `github.com/auth0/go-auth0` (`management` package) |
| **API Type** | REST (Auth0 Management API v2) |
| **Auth** | Machine-to-Machine client credentials: tenant domain + client ID + client secret, exchanged for a Management API access token (`AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` env vars, or `--domain`/`--client-id`/`--client-secret` flags) |

---

## Directory Structure

```
providers/auth0/
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
    ├── auth0.lr
    ├── auth0.lr.go              # generated
    ├── auth0.lr.versions        # generated
    ├── discovery.go
    ├── auth0.go                 # root resource + tenant
    ├── client.go                # applications
    ├── connection_resource.go   # identity connections
    ├── user.go
    ├── role.go
    ├── action.go
    ├── logstream.go
    └── attackprotection.go
```

`connection_resource.go` (not `connection.go`) avoids a name collision with `connection/connection.go`, following the same convention `okta` uses for `okta_organization.go` versus the `connection` package.

---

## Resource Schema (`auth0.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/auth0"
option go_package = "go.mondoo.com/mql/providers/auth0/resources"

// Auth0 tenant
//
// Namespace for the identity resources reachable through an Auth0 tenant's
// Management API: applications, identity connections, users, roles, actions,
// and log streams. Query auth0.tenant for tenant-wide session and flag
// settings, and auth0.attackProtection for the brute-force, suspicious-IP,
// and breached-password defenses that apply across the whole tenant.
auth0 {
  // Tenant-wide settings: session lifetimes, default audience, and flags
  tenant() auth0.tenant
  // Applications (OAuth/OIDC clients) registered in the tenant
  clients() []auth0.client
  // Identity connections (database, social, and enterprise) available to applications
  connections() []auth0.connection
  // Users held in the tenant's database connections
  users() []auth0.user
  // Administrative and application roles defined in the tenant
  roles() []auth0.role
  // Actions that run custom logic during authentication and other flows
  actions() []auth0.action
  // Log streams that export tenant events to external destinations
  logStreams() []auth0.logStream
  // Tenant-wide brute-force, suspicious-IP, and breached-password protections
  attackProtection() auth0.attackProtection
}

// Auth0 tenant settings
//
// Tenant-wide configuration that applies across every application and
// connection in the Auth0 tenant. `sessionLifetime` and `idleSessionLifetime`
// bound how long an authenticated session and an idle session may last before
// re-authentication is required, `allowedLogoutUrls` is the allowlist
// end-user logout redirects are validated against, and `flags` carries the
// full set of tenant feature flags returned by the API (also surfaced
// individually as boolean fields for the security-relevant ones).
auth0.tenant @defaults("friendlyName") {
  // Tenant display name
  friendlyName string
  // Support contact email shown to end users
  supportEmail string
  // Support URL shown to end users
  supportUrl string
  // URL of the tenant logo
  pictureUrl string
  // Logout redirect URLs allowed for this tenant
  //
  // End-user logout redirects (`returnTo` on the logout endpoint) that are
  // not scoped to a specific application must match an entry in this list.
  allowedLogoutUrls []string
  // Authenticated session lifetime in hours
  sessionLifetime float
  // Idle session lifetime in hours before re-authentication is required
  idleSessionLifetime float
  // Default audience for API authorization requests that omit one
  defaultAudience string
  // Default directory (database connection) used for username/password logins
  defaultDirectory string
  // Locales enabled for Universal Login
  enabledLocales []string
  // Tenant feature flags
  //
  // Raw flag payload as returned by the API, keyed by flag name (for example
  // enableApisSection, changePwdFlowV1, disableClickjackProtectionHeaders).
  flags dict
}

// Auth0 application
//
// OAuth 2.0/OIDC client (a "Application" in the Auth0 dashboard) registered
// in the tenant, identified by its `id` (the Auth0 `client_id`). Covers the
// settings that govern how the application authenticates and what it is
// permitted to do: `grantTypes` lists the OAuth grants it may use,
// `tokenEndpointAuthMethod` and the refresh-token fields describe its
// credential and token-rotation posture, and `callbacks`/`allowedOrigins`/
// `webOrigins` bound where it may redirect users and make cross-origin
// calls from. A public client with `implicit` in `grantTypes`, a wildcard
// callback URL, or refresh tokens that never rotate are common findings.
auth0.client @defaults("name appType") {
  // Client ID (Auth0's identifier for the application)
  id string
  // Application name
  name string
  // Application description
  description string
  // Application type
  //
  // One of native, spa (single-page app), regular_web, or non_interactive
  // (machine-to-machine).
  appType string
  // Whether this application is a Mondoo/Auth0 "first party" application
  isFirstParty bool
  // Whether the application uses the OIDC-conformant pipeline
  oidcConformant bool
  // Allowed callback (redirect) URLs after authentication
  callbacks []string
  // Allowed URLs to redirect to after logout
  allowedLogoutUrls []string
  // Allowed origins for cross-origin (CORS) authentication requests
  allowedOrigins []string
  // Allowed origins for web-message (silent authentication) responses
  webOrigins []string
  // OAuth 2.0 grant types the application is permitted to use
  //
  // Common values: authorization_code, implicit, refresh_token,
  // client_credentials, password, and the device and passwordless variants.
  // implicit is legacy; client_credentials should be reserved for
  // non_interactive applications.
  grantTypes []string
  // How the application authenticates to the token endpoint
  //
  // One of none (public client, e.g. SPA or native), client_secret_post,
  // or client_secret_basic.
  tokenEndpointAuthMethod string
  // Whether refresh tokens rotate on use
  //
  // One of rotating (a new refresh token is issued and the previous one
  // invalidated on each use) or non-rotating (the same refresh token is
  // reused until it expires). Rotating is the hardened setting.
  refreshTokenRotationType string
  // Refresh token expiration behavior
  //
  // One of expiring (tokens have an absolute and inactivity lifetime) or
  // non-expiring (tokens never expire on their own).
  refreshTokenExpirationType string
  // Grace period in seconds a rotated-out refresh token remains usable
  refreshTokenLeeway int
  // Absolute refresh token lifetime in seconds, when expiring
  refreshTokenLifetime int
  // Inactivity lifetime in seconds before an unused refresh token expires
  refreshTokenIdleLifetime int
  // Whether single sign-on is disabled for this application
  ssoDisabled bool
  // Whether cross-origin authentication is enabled for this application
  crossOriginAuth bool
  // URI Auth0 redirects to in order to initiate a login for this application
  initiateLoginUri string
  // Signing algorithm and lifetime for ID tokens: keys alg (RS256 or HS256, HS256 shares a symmetric secret) and lifetimeInSeconds
  jwtConfiguration dict
  // Free-form metadata attached to the application
  clientMetadata map[string]string
  // Identity connections this application is enabled on
  enabledConnections() []auth0.connection
}

// Auth0 identity connection
//
// Identity source available to applications in the tenant: a database
// connection (username/password, stored and verified by Auth0), a social
// connection (Google, GitHub, and so on), or an enterprise connection
// (SAML, OIDC, Active Directory/LDAP, Azure AD). The `strategy` field
// selects the connection kind. For database connections, `passwordPolicy`
// and the `passwordHistory*`/`passwordDictionaryEnabled` fields describe
// the credential strength Auth0 enforces at signup and password reset, and
// `mfaActive` reports whether multi-factor authentication is required for
// logins through this connection. `enabledClients` resolves the
// applications permitted to authenticate against it.
auth0.connection @defaults("name strategy") {
  // Connection ID
  id string
  // Connection name
  name string
  // Connection strategy
  //
  // Identifies the connection kind, for example auth0 (database), google-oauth2,
  // github, samlp, oidc, waad (Azure AD), or ad (Active Directory/LDAP).
  strategy string
  // Whether this is the tenant's default (domain) connection
  isDomainConnection bool
  // Whether new-user signup is disabled on this connection
  disableSignup bool
  // Whether login on this connection requires a username in addition to email
  requiresUsername bool
  // Password strength policy for a database connection
  //
  // One of none, low, fair, good, or excellent. Empty for non-database
  // (social or enterprise) connections.
  passwordPolicy string
  // Whether Auth0 rejects passwords found in a breach-credential dictionary
  passwordDictionaryEnabled bool
  // Whether Auth0 rejects passwords that reuse a user's recent password history
  passwordHistoryEnabled bool
  // Number of previous passwords checked when password history is enabled
  passwordHistorySize int
  // Whether Auth0 rejects passwords containing the user's personal information
  passwordNoPersonalInfo bool
  // Whether multi-factor authentication is active for logins through this connection
  mfaActive bool
  // Whether MFA enrollment settings are returned during authentication
  mfaReturnEnrollSettings bool
  // Legacy per-connection brute-force protection flag
  //
  // Deprecated in favor of the tenant-wide brute-force protection exposed
  // through auth0.attackProtection, which supersedes this per-connection
  // setting for database connections.
  bruteForceProtection @maturity("deprecated") bool
  // Raw options payload for this connection, for strategy-specific settings (SAML certs, AD/LDAP binds, social app keys) not promoted to a typed field
  options dict
  // Applications enabled on this connection
  enabledClients() []auth0.client
}

// Auth0 user
//
// Individual account held in one of the tenant's database connections and
// selected by its `id` (the Auth0 `user_id`, for example
// `auth0|507f1f77bcf86cd799439011`). The lifecycle fields (`blocked`,
// `lastLogin`, `loginsCount`) surface dormant or locked-out accounts,
// `multifactor` lists which MFA factor types the user has enrolled, and
// `identities` shows every linked social or enterprise account merged into
// this profile. `roles` resolves the administrative and application roles
// granted to the user.
auth0.user @defaults("email") {
  // User ID
  id string
  // Primary email address
  email string
  // Whether the primary email address has been verified
  emailVerified bool
  // Full name
  name string
  // Username, for connections that require one
  username string
  // Phone number, for passwordless/SMS connections
  phoneNumber string
  // Whether the phone number has been verified
  phoneVerified bool
  // Whether the account is blocked
  blocked bool
  // Timestamp when the account was created
  createdAt time
  // Timestamp when the account was last updated
  updatedAt time
  // Timestamp of the user's last login
  lastLogin time
  // IP address of the user's last login
  lastIp string
  // Total number of successful logins
  loginsCount int
  // MFA factor types enrolled (guardian, sms, email); empty means no MFA factor enrolled
  multifactor []string
  // Linked identities merged into this profile, each a dict with keys connection, provider, userId, isSocial, and profileData
  identities []dict
  // Application-controlled metadata not editable by the user
  appMetadata dict
  // User-editable profile metadata
  userMetadata dict
  // Roles assigned to the user
  roles() []auth0.role
}

// Auth0 role
//
// Named collection of permissions that can be assigned to users or, through
// an application's client-credentials grant, to machine clients. Select a
// role by its `name`. The `permissions` field lists the resource-server
// scopes the role grants, and `users` lists the accounts currently holding
// it, letting you audit membership in high-privilege roles directly.
auth0.role @defaults("name") {
  // Role ID
  id string
  // Role name
  name string
  // Role description
  description string
  // Permissions granted by the role
  //
  // One entry per permission, each a dict with keys permissionName,
  // resourceServerIdentifier, resourceServerName, and description.
  permissions() []dict
  // Users currently assigned this role
  users() []auth0.user
}

// Auth0 action
//
// Piece of custom Node.js logic that Auth0 runs during an authentication or
// management flow, such as login, machine-to-machine token issuance, or
// user registration. Select an action by its `name`. `supportedTriggers`
// identifies which flow(s) the action can bind to, `status` and `deployed`
// report whether the current version is live, and `code` is the action's
// source, useful for spotting hardcoded secrets or unreviewed logic
// running inline in the authentication path. `secrets` lists the names of
// configured secrets without exposing their values.
auth0.action @defaults("name status") {
  // Action ID
  id string
  // Action name
  name string
  // Runtime the action executes in, for example node18 or node22
  runtime string
  // Trigger(s) the action is bound to
  //
  // Each entry is a dict with keys id (post-login, credentials-exchange,
  // pre-user-registration, and so on) and version.
  supportedTriggers []dict
  // Deployment status of the action's current version: pending, building, packaged, built, retrying, or failed
  status string
  // Whether the current version of the action is deployed to its trigger(s)
  deployed bool
  // Action source code
  code string
  // npm package dependencies declared by the action, each a dict with keys name, version, and registryUrl
  dependencies []dict
  // Names of secrets configured for the action (values are never returned by the API)
  secrets []dict
  // Timestamp when the action was created
  createdAt time
  // Timestamp when the action was last updated
  updatedAt time
}

// Auth0 log stream
//
// Connection that exports tenant log events to an external destination such
// as AWS EventBridge, Datadog, Splunk, or a generic HTTP endpoint. Select a
// stream by its `name`. `type` identifies the destination kind, `sink`
// carries the destination-specific configuration (endpoint URLs, region,
// API keys are redacted), and `status` reports whether delivery is active,
// paused, or has been suspended by Auth0 after repeated failures. An
// absent or non-active stream means tenant authentication events are not
// being shipped to a SIEM or audit pipeline.
auth0.logStream @defaults("name type status") {
  // Log stream ID
  id string
  // Log stream name
  name string
  // Destination type
  //
  // For example http, eventbridge, eventgrid, datadog, splunk, sumo,
  // mixpanel, or segment.
  type string
  // Delivery status
  //
  // One of active, paused, or suspended (Auth0 disabled the stream after
  // repeated delivery failures).
  status string
  // Destination-specific configuration
  //
  // Shape depends on type: http (httpEndpoint, httpContentFormat), datadog
  // (datadogRegion, key redacted), splunk (splunkDomain, splunkPort), or
  // eventbridge (awsAccountId, awsRegion).
  sink dict
  // Event categories streamed (for example login, failed_login); empty means all categories
  filters []dict
}

// Auth0 attack protection
//
// Tenant-wide defenses against credential attacks: brute-force login
// attempts, suspicious traffic from a small number of IPs hitting many
// accounts, and logins with passwords known to be exposed in third-party
// breaches. Each defense is flattened onto this resource with a
// disambiguating prefix (`bruteForce*`, `suspiciousIpThrottling*`,
// `breachedPasswordDetection*`) since all three are singleton
// configuration blocks scoped to the tenant, not independently addressable
// records. A tenant with `breachedPasswordDetectionEnabled` false, or
// `bruteForceEnabled` false, accepts logins Auth0 would otherwise have
// blocked or flagged.
auth0.attackProtection @defaults("bruteForceEnabled breachedPasswordDetectionEnabled") {
  // Whether brute-force protection is enabled
  bruteForceEnabled bool
  // Brute-force lockout mode: count_per_identifier_and_ip (username+IP pair, the default) or count_per_identifier (username alone)
  bruteForceMode string
  // Number of failed attempts before a lockout is triggered
  bruteForceMaxAttempts int
  // IP addresses exempted from brute-force lockout
  bruteForceAllowlist []string
  // Whether suspicious-IP throttling is enabled
  suspiciousIpThrottlingEnabled bool
  // IP addresses exempted from suspicious-IP throttling
  suspiciousIpThrottlingAllowlist []string
  // Maximum sign-in attempts allowed per interval before throttling on the pre-login stage
  suspiciousIpThrottlingPreLoginMaxAttempts int
  // Maximum sign-up attempts allowed per interval before throttling on the pre-registration stage
  suspiciousIpThrottlingPreRegistrationMaxAttempts int
  // Whether breached-password detection is enabled
  breachedPasswordDetectionEnabled bool
  // Breached-password detection method: standard (checks at login/signup) or enhanced (also checks continuously against new breaches)
  breachedPasswordDetectionMethod string
  // Actions ("shields") on detection: block, user_notification, and/or admin_notification
  breachedPasswordDetectionShields []string
  // How often admin notification digest emails are sent: immediately, daily, weekly, or monthly
  breachedPasswordDetectionAdminNotificationFrequency []string
}
```

Because `auth0` is a brand-new, unreleased provider, every entry this schema generates in `auth0.lr.versions` is part of the `13.0.0` initial release, not `13.0.1` (see CLAUDE.md §6, "Exception: brand-new, unreleased provider"). Run the `version` tool to confirm rather than hand-editing.

---

## Authentication

Machine-to-machine client credentials, matching the pattern `okta` uses for its OAuth client-credentials flow:

```go
package connection

import (
	"context"
	"os"

	"github.com/auth0/go-auth0/management"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type Auth0Connection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *management.Management
}

func NewAuth0Connection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*Auth0Connection, error) {
	conn := &Auth0Connection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	domain := conf.Options["domain"]
	if domain == "" {
		domain = os.Getenv("AUTH0_DOMAIN")
	}
	if domain == "" {
		return nil, errors.New("a valid Auth0 tenant domain is required (set AUTH0_DOMAIN or use --domain)")
	}

	clientID := os.Getenv("AUTH0_CLIENT_ID")
	clientSecret := os.Getenv("AUTH0_CLIENT_SECRET")
	for _, cred := range conf.Credentials {
		switch cred.Type {
		case vault.CredentialType_password:
			// --client-secret (or a credential injected via vault)
			clientSecret = string(cred.Secret)
		}
	}
	if id, ok := conf.Options["client-id"]; ok && id != "" {
		clientID = id
	}
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("a valid Auth0 client ID and client secret are required " +
			"(set AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET, or use --client-id/--client-secret)")
	}

	mgmt, err := management.New(domain,
		management.WithClientCredentials(context.Background(), clientID, clientSecret),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate to Auth0 Management API")
	}
	conn.client = mgmt

	return conn, nil
}

func (c *Auth0Connection) Client() *management.Management {
	return c.client
}
```

The Management API token minted from these credentials is scoped by whatever `scope`s the M2M application was granted in the Auth0 dashboard (`read:clients`, `read:connections`, `read:users`, `read:roles`, `read:actions`, `read:log_streams`, `read:attack_protection`, `read:tenant_settings`). Document the required scopes in `providers/auth0/README.md`, the same way `okta`'s README documents its required API token scopes.

---

## Implementation Patterns

### Paginated List (all list APIs)

The Auth0 Management API uses offset pagination (`page`/`per_page`, capped at 1000 total records via `page * per_page`), matching `okta`'s cursor style closely enough that the same "loop until the last page" shape applies:

```go
func (a *mqlAuth0) clients() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Auth0Connection)
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Client.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, c := range list.Clients {
			r, err := CreateResource(a.MqlRuntime, "auth0.client", map[string]*llx.RawData{
				"id":                       llx.StringDataPtr(c.ClientID),
				"name":                     llx.StringDataPtr(c.Name),
				"appType":                  llx.StringDataPtr(c.AppType),
				"grantTypes":               llx.ArrayData(convert.SliceStrPtrToInterface(c.GrantTypes), types.String),
				"tokenEndpointAuthMethod":  llx.StringDataPtr(c.TokenEndpointAuthMethod),
				// ... remaining fields
			})
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}
```

### Typed Resource References (via Internal struct)

Connections store enabled applications as a list of client IDs (`enabled_clients` in the API); expose them as typed `auth0.client` references instead of raw strings, following the Step 1.5 typed-reference gate:

```go
type mqlAuth0ConnectionInternal struct {
	cacheEnabledClientIds []string
}

func (c *mqlAuth0Connection) enabledClients() ([]any, error) {
	if len(c.cacheEnabledClientIds) == 0 {
		return []any{}, nil
	}

	var result []any
	for _, clientID := range c.cacheEnabledClientIds {
		r, err := NewResource(c.MqlRuntime, "auth0.client",
			map[string]*llx.RawData{"id": llx.StringData(clientID)})
		if err != nil {
			// initAuth0Client logs and continues on a stale/deleted client ID
			// rather than failing the whole connection; verify against a real
			// tenant that a deleted client doesn't silently empty this list.
			continue
		}
		result = append(result, r)
	}
	return result, nil
}
```

`initAuth0Client` must accept `id` and fetch `GET /api/v2/clients/{id}` on demand; per CLAUDE.md, if the client is not found it must return a not-found error, not fall through to a blank resource with unset fields.

### Singleton Resources (tenant, attackProtection)

`auth0.tenant` and `auth0.attackProtection` are per-tenant singletons with no natural list or ID: Pattern A with a synthetic constant `__id` (the tenant domain), computed once in the root `auth0` resource's `tenant()`/`attackProtection()` accessors, mirroring `okta.organization`/`okta.threatsConfiguration`. One API call each (`Tenant.Read`, `AttackProtection.BruteForceProtection`/`SuspiciousIPThrottling`/`BreachedPasswordDetection`) mapped directly with `CreateResource`.

---

## Security Policies (MVP)

Ship as `mondoo-auth0-security.mql.yaml`:

**Multi-Factor Authentication:**
- Database connections must have MFA active: `auth0.connections.where(strategy == 'auth0').all(mfaActive == true)`
- Users holding an administrative role must have at least one MFA factor enrolled

**Credential Hardening:**
- Breached-password detection must be enabled tenant-wide (`enhanced` method preferred over `standard`): `auth0.attackProtection.breachedPasswordDetectionEnabled == true`
- Database connections must enforce a `good` or `excellent` password policy, with `passwordHistoryEnabled` and `passwordDictionaryEnabled` on

**Brute-Force and Abuse Protection:**
- Brute-force protection and suspicious-IP throttling must both be enabled tenant-wide: `auth0.attackProtection.bruteForceEnabled == true && auth0.attackProtection.suspiciousIpThrottlingEnabled == true`
- Brute-force and suspicious-IP allowlists should be empty or explicitly justified

**Application (Client) Hardening:**
- No application may use the `implicit` grant type or a bare wildcard callback URL: `auth0.clients.all(!grantTypes.contains('implicit') && callbacks.all(_ != '*'))`
- Confidential applications (`appType` other than `spa`/`native`) must not use `tokenEndpointAuthMethod == 'none'`
- Applications using `refresh_token` grants must have `refreshTokenRotationType == 'rotating'` and `refreshTokenExpirationType == 'expiring'` with a bounded `refreshTokenLifetime`

**Administrative Access:**
- Membership in high-privilege roles (for example a tenant `Admin` role) should stay within an expected count: `auth0.roles.where(name == 'Admin').all(users.length <= 5)`
- Machine-to-machine applications should not hold interactive administrative roles

**Observability and Session Hygiene:**
- At least one log stream must be `active`, and none should sit in `suspended` (repeated delivery failures Auth0 gave up retrying): `auth0.logStreams.where(status == 'active').length > 0`
- Tenant session and idle-session lifetimes should be bounded: `auth0.tenant.sessionLifetime <= 720 && auth0.tenant.idleSessionLifetime <= 72` (30 days / 3 days)

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags (`--domain`, `--client-id`, `--client-secret`)
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/auth0` in `go.work` list
4. **`Makefile`** — `auth0` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/auth0/resources/auth0.lr \
  --dist providers/auth0/resources

# Build and install
make providers/build/auth0 && make providers/install/auth0

# Test
export AUTH0_DOMAIN="your-tenant.us.auth0.com"
export AUTH0_CLIENT_ID="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export AUTH0_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
mql shell auth0
> auth0.tenant { friendlyName sessionLifetime idleSessionLifetime }
> auth0.attackProtection { bruteForceEnabled breachedPasswordDetectionEnabled }
> auth0.clients { name appType grantTypes refreshTokenRotationType }
> auth0.connections { name strategy mfaActive passwordPolicy enabledClients { name } }
> auth0.roles { name users { email } }
> auth0.logStreams { name type status }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/auth0 --provider-id auth0 --provider-name "Auth0"` then `cd providers/auth0 && go mod tidy`
2. Connection + auth (validates M2M client credentials against `Tenant.Read`)
3. Root + Tenant (first resource that exercises the connection end to end)
4. Attack Protection (three flattened blocks, highest security value per line of code)
5. Clients (applications: grant types, callback URLs, refresh-token rotation)
6. Connections (identity connections: password policy, MFA, `enabledClients` typed ref)
7. Roles + Users (`roles()`/`users()` cross-references between the two)
8. Actions (source code and secrets metadata)
9. Log Streams
10. Security policies (`mondoo-auth0-security.mql.yaml`)
11. Discovery (asset per tenant; consider per-application child assets in a later iteration)
12. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Auth0 Management API v2](https://auth0.com/docs/api/management/v2)
- [go-auth0 Go SDK](https://github.com/auth0/go-auth0) / [usage examples](https://github.com/auth0/go-auth0/blob/main/EXAMPLES.md)
- [Auth0 Terraform Provider](https://github.com/auth0/terraform-provider-auth0) (schema alignment reference)
- [Attack Protection: Breached Password Detection](https://auth0.com/docs/api/management/v2/attack-protection/get-breached-password-detection), [Brute-Force Protection](https://auth0.com/docs/api/management/v2/attack-protection/get-brute-force-protection), [Suspicious IP Throttling](https://auth0.com/docs/api/management/v2/attack-protection/get-suspicious-ip-throttling)
- [Application (Client) Grant Types](https://auth0.com/docs/get-started/applications/application-grant-types) · [Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
- Reference providers: `providers/okta/`, `providers/tailscale/`
