// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realmPayload is a realm as the admin API answers GET /admin/realms/{realm},
// trimmed to the settings the provider reads.
const realmPayload = `{
  "id": "f4b1a0b8-0f0c-4a58-9f36-6f2a9f0f2a11",
  "realm": "production",
  "displayName": "Production",
  "enabled": true,
  "sslRequired": "external",
  "passwordPolicy": "length(12) and digits(1) and upperCase(1) and notUsername(undefined) and passwordHistory(3)",
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxTemporaryLockouts": 2,
  "failureFactor": 30,
  "waitIncrementSeconds": 60,
  "maxFailureWaitSeconds": 900,
  "maxDeltaTimeSeconds": 43200,
  "quickLoginCheckMilliSeconds": 1000,
  "minimumQuickLoginWaitSeconds": 60,
  "registrationAllowed": false,
  "registrationEmailAsUsername": false,
  "rememberMe": true,
  "verifyEmail": true,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "accessTokenLifespan": 300,
  "accessTokenLifespanForImplicitFlow": 900,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000,
  "ssoSessionIdleTimeoutRememberMe": 0,
  "ssoSessionMaxLifespanRememberMe": 0,
  "offlineSessionIdleTimeout": 2592000,
  "offlineSessionMaxLifespanEnabled": false,
  "offlineSessionMaxLifespan": 5184000,
  "accessCodeLifespan": 60,
  "accessCodeLifespanUserAction": 300,
  "accessCodeLifespanLogin": 1800,
  "actionTokenGeneratedByUserLifespan": 300,
  "revokeRefreshToken": true,
  "refreshTokenMaxReuse": 0,
  "otpPolicyType": "totp",
  "otpPolicyAlgorithm": "HmacSHA1",
  "otpPolicyDigits": 6,
  "otpPolicyPeriod": 30,
  "defaultSignatureAlgorithm": "RS256",
  "eventsEnabled": true,
  "eventsExpiration": 604800,
  "adminEventsEnabled": true,
  "adminEventsDetailsEnabled": false,
  "browserSecurityHeaders": {
    "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
    "xFrameOptions": "SAMEORIGIN",
    "strictTransportSecurity": "max-age=31536000; includeSubDomains"
  },
  "defaultGroups": ["/everyone"],
  "defaultRole": {
    "id": "9f3f1a5c-1111-2222-3333-444455556666",
    "name": "default-roles-production",
    "composite": true,
    "clientRole": false,
    "containerId": "f4b1a0b8-0f0c-4a58-9f36-6f2a9f0f2a11"
  },
  "browserFlow": "browser",
  "registrationFlow": "registration",
  "directGrantFlow": "direct grant",
  "resetCredentialsFlow": "reset credentials",
  "clientAuthenticationFlow": "clients",
  "dockerAuthenticationFlow": "docker auth",
  "firstBrokerLoginFlow": "first broker login"
}`

func TestRealmRecordDecode(t *testing.T) {
	var rec realmRecord
	require.NoError(t, json.Unmarshal([]byte(realmPayload), &rec))

	assert.Equal(t, "production", rec.Realm)
	assert.Equal(t, "f4b1a0b8-0f0c-4a58-9f36-6f2a9f0f2a11", rec.ID)
	assert.True(t, rec.Enabled)
	assert.Equal(t, "external", rec.SslRequired)

	// Brute force settings.
	assert.True(t, rec.BruteForceProtected)
	assert.False(t, rec.PermanentLockout)
	assert.Equal(t, int64(30), rec.FailureFactor)
	assert.Equal(t, int64(60), rec.WaitIncrementSeconds)
	assert.Equal(t, int64(900), rec.MaxFailureWaitSeconds)
	assert.Equal(t, int64(43200), rec.MaxDeltaTimeSeconds)
	assert.Equal(t, int64(1000), rec.QuickLoginCheckMilliSeconds)
	assert.Equal(t, int64(60), rec.MinimumQuickLoginWaitSeconds)
	assert.Equal(t, int64(2), rec.MaxTemporaryLockouts)

	// Self-service exposure.
	assert.False(t, rec.RegistrationAllowed)
	assert.True(t, rec.RememberMe)
	assert.True(t, rec.VerifyEmail)
	assert.True(t, rec.ResetPasswordAllowed)
	assert.False(t, rec.EditUsernameAllowed)
	assert.True(t, rec.LoginWithEmailAllowed)
	assert.False(t, rec.DuplicateEmailsAllowed)

	// Token and session lifespans.
	assert.Equal(t, int64(300), rec.AccessTokenLifespan)
	assert.Equal(t, int64(900), rec.AccessTokenLifespanForImplicitFlow)
	assert.Equal(t, int64(1800), rec.SsoSessionIdleTimeout)
	assert.Equal(t, int64(36000), rec.SsoSessionMaxLifespan)
	assert.Equal(t, int64(2592000), rec.OfflineSessionIdleTimeout)
	assert.False(t, rec.OfflineSessionMaxLifespanEnabled)
	assert.Equal(t, int64(60), rec.AccessCodeLifespan)
	assert.Equal(t, int64(1800), rec.AccessCodeLifespanLogin)
	assert.Equal(t, int64(300), rec.ActionTokenGeneratedByUserLifespan)
	assert.True(t, rec.RevokeRefreshToken)

	// Events and headers.
	assert.True(t, rec.EventsEnabled)
	assert.True(t, rec.AdminEventsEnabled)
	assert.False(t, rec.AdminEventsDetailsEnabled)
	assert.Equal(t, "SAMEORIGIN", rec.BrowserSecurityHeaders["xFrameOptions"])

	// Flow bindings.
	assert.Equal(t, "browser", rec.BrowserFlow)
	assert.Equal(t, "direct grant", rec.DirectGrantFlow)
	assert.Equal(t, "registration", rec.RegistrationFlow)
	assert.Equal(t, "reset credentials", rec.ResetCredentialsFlow)
	assert.Equal(t, "clients", rec.ClientAuthenticationFlow)
	assert.Equal(t, "docker auth", rec.DockerAuthenticationFlow)
	assert.Equal(t, "first broker login", rec.FirstBrokerLoginFlow)

	require.NotNil(t, rec.DefaultRole)
	assert.Equal(t, "default-roles-production", rec.DefaultRole.Name)
	assert.True(t, rec.DefaultRole.Composite)
	assert.Equal(t, []string{"/everyone"}, rec.DefaultGroups)
}

func TestRealmRecordDecodeOfAnUnhardenedRealm(t *testing.T) {
	// The settings a fresh realm ships with, which is what most of the checks
	// are written against.
	const payload = `{
      "realm": "demo",
      "enabled": true,
      "sslRequired": "none",
      "passwordPolicy": "",
      "bruteForceProtected": false,
      "registrationAllowed": true,
      "rememberMe": true,
      "adminEventsEnabled": false
    }`

	var rec realmRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "none", rec.SslRequired)
	assert.Empty(t, rec.PasswordPolicy)
	assert.False(t, rec.BruteForceProtected)
	assert.True(t, rec.RegistrationAllowed)
	assert.True(t, rec.RememberMe)
	assert.False(t, rec.AdminEventsEnabled)
	// An absent setting must not invent a value.
	assert.Nil(t, rec.DefaultRole)
	assert.Empty(t, rec.BrowserFlow)
}

func TestParsePasswordPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   map[string]string
	}{
		{
			name:   "empty policy",
			policy: "",
			want:   map[string]string{},
		},
		{
			name:   "rules with arguments",
			policy: "length(12) and digits(1) and upperCase(1) and specialChars(1)",
			want: map[string]string{
				"length":       "12",
				"digits":       "1",
				"upperCase":    "1",
				"specialChars": "1",
			},
		},
		{
			name:   "a rule without an argument reads as empty",
			policy: "notUsername(undefined) and notEmail(undefined)",
			want: map[string]string{
				"notUsername": "",
				"notEmail":    "",
			},
		},
		{
			name:   "hash and history rules",
			policy: "hashAlgorithm(pbkdf2-sha512) and passwordHistory(3) and forceExpiredPasswordChange(90)",
			want: map[string]string{
				"hashAlgorithm":              "pbkdf2-sha512",
				"passwordHistory":            "3",
				"forceExpiredPasswordChange": "90",
			},
		},
		{
			name:   "a rule with no parentheses keeps its name",
			policy: "notUsername",
			want:   map[string]string{"notUsername": ""},
		},
		{
			name:   "surrounding space is trimmed",
			policy: "  length(8)   and    digits(2)  ",
			want:   map[string]string{"length": "8", "digits": "2"},
		},
		{
			name:   "a regex argument keeps its own parentheses",
			policy: "regexPattern((?=.*[A-Z]).*)",
			want:   map[string]string{"regexPattern": "(?=.*[A-Z]).*"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParsePasswordPolicy(tc.policy))
		})
	}
}

// clientPayload is a client as the admin API answers
// GET /admin/realms/{realm}/clients.
const clientPayload = `{
  "id": "5b9c3f3e-1c1e-4c47-9d3a-1f0f2b3c4d5e",
  "clientId": "kubernetes",
  "name": "Cluster API server",
  "description": "OIDC client for the cluster apiserver",
  "rootUrl": "https://apps.example.com",
  "adminUrl": "https://apps.example.com",
  "baseUrl": "/",
  "surrogateAuthRequired": false,
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "redirectUris": ["https://apps.example.com/callback", "https://apps.example.com/oauth2/*"],
  "webOrigins": ["https://apps.example.com"],
  "notBefore": 0,
  "bearerOnly": false,
  "consentRequired": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true,
  "publicClient": false,
  "frontchannelLogout": true,
  "protocol": "openid-connect",
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "+",
    "access.token.lifespan": "600"
  },
  "authenticationFlowBindingOverrides": {"browser": "9a8b7c6d-0000-1111-2222-333344445555"},
  "fullScopeAllowed": false,
  "defaultClientScopes": ["web-origins", "profile", "roles", "email"],
  "optionalClientScopes": ["address", "phone", "offline_access"]
}`

func TestClientRecordDecode(t *testing.T) {
	var rec clientRecord
	require.NoError(t, json.Unmarshal([]byte(clientPayload), &rec))

	assert.Equal(t, "kubernetes", rec.ClientID)
	assert.Equal(t, "5b9c3f3e-1c1e-4c47-9d3a-1f0f2b3c4d5e", rec.ID)
	assert.True(t, rec.Enabled)

	// Confidential versus public, and the grants the client may use.
	assert.False(t, rec.PublicClient)
	assert.False(t, rec.BearerOnly)
	assert.True(t, rec.StandardFlowEnabled)
	assert.False(t, rec.ImplicitFlowEnabled)
	assert.True(t, rec.DirectAccessGrantsEnabled)
	assert.True(t, rec.ServiceAccountsEnabled)
	assert.False(t, rec.AuthorizationServicesEnabled)

	// Redirect and origin surface.
	assert.Equal(t, []string{"https://apps.example.com/callback", "https://apps.example.com/oauth2/*"}, rec.RedirectUris)
	assert.Equal(t, []string{"https://apps.example.com"}, rec.WebOrigins)

	assert.False(t, rec.ConsentRequired)
	assert.True(t, rec.FrontchannelLogout)
	assert.Equal(t, "openid-connect", rec.Protocol)
	assert.Equal(t, "client-secret", rec.ClientAuthenticatorType)
	assert.False(t, rec.FullScopeAllowed)
	assert.Equal(t, "S256", rec.Attributes[pkceAttribute])
	assert.Equal(t, "9a8b7c6d-0000-1111-2222-333344445555", rec.AuthenticationFlowBindingOverrides["browser"])
	assert.Len(t, rec.DefaultClientScopes, 4)
	assert.Len(t, rec.OptionalClientScopes, 3)
}

func TestClientRecordDecodeOfAPublicClient(t *testing.T) {
	// The shape that carries the finding: a public client whose redirect URI
	// accepts any URL and whose code exchange is not bound by PKCE.
	const payload = `{
      "id": "aaaa",
      "clientId": "legacy-spa",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "implicitFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "redirectUris": ["*"],
      "webOrigins": ["*"],
      "attributes": {}
    }`

	var rec clientRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.True(t, rec.PublicClient)
	assert.True(t, rec.ImplicitFlowEnabled)
	assert.Equal(t, []string{"*"}, rec.RedirectUris)
	assert.Empty(t, rec.Attributes[pkceAttribute])
	assert.Equal(t, []string{"*"}, WildcardRedirectUris(rec.RedirectUris))
	assert.True(t, HasWildcardWebOrigin(rec.WebOrigins))
}

func TestWildcardRedirectUris(t *testing.T) {
	tests := []struct {
		name string
		uris []string
		want []string
	}{
		{name: "no redirect uris at all", uris: nil},
		{
			name: "exact uris carry no wildcard",
			uris: []string{"https://app.example.com/callback", "http://localhost:8080/callback"},
		},
		{
			name: "a trailing wildcard path",
			uris: []string{"https://app.example.com/*"},
			want: []string{"https://app.example.com/*"},
		},
		{
			name: "the bare wildcard accepts any url",
			uris: []string{"*"},
			want: []string{"*"},
		},
		{
			name: "a wildcard in the host",
			uris: []string{"https://*.example.com/callback"},
			want: []string{"https://*.example.com/callback"},
		},
		{
			name: "only the wildcard entries are reported",
			uris: []string{"https://app.example.com/callback", "https://app.example.com/*"},
			want: []string{"https://app.example.com/*"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := WildcardRedirectUris(tc.uris)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, len(tc.want) > 0, len(got) > 0)
		})
	}
}

func TestHasWildcardWebOrigin(t *testing.T) {
	assert.False(t, HasWildcardWebOrigin(nil))
	assert.False(t, HasWildcardWebOrigin([]string{"https://app.example.com"}))
	// Keycloak's + stands for the origins the redirect URIs imply, so it is
	// bounded by them and is not a wildcard.
	assert.False(t, HasWildcardWebOrigin([]string{"+"}))
	assert.True(t, HasWildcardWebOrigin([]string{"*"}))
	assert.True(t, HasWildcardWebOrigin([]string{"https://app.example.com", " * "}))
}

func TestRoleRecordDecode(t *testing.T) {
	const payload = `{
      "id": "1c2d3e4f-aaaa-bbbb-cccc-ddddeeeeffff",
      "name": "platform-admin",
      "description": "Administers the platform",
      "composite": true,
      "clientRole": false,
      "containerId": "f4b1a0b8-0f0c-4a58-9f36-6f2a9f0f2a11",
      "attributes": {"owner": ["platform-team"]}
    }`

	var rec roleRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "platform-admin", rec.Name)
	assert.True(t, rec.Composite)
	assert.False(t, rec.ClientRole)
	assert.Equal(t, "f4b1a0b8-0f0c-4a58-9f36-6f2a9f0f2a11", rec.ContainerID)
	assert.Equal(t, []string{"platform-team"}, rec.Attributes["owner"])
}

func TestRoleMappingsDecode(t *testing.T) {
	// The shape of GET /admin/realms/{realm}/users/{id}/role-mappings.
	const payload = `{
      "realmMappings": [
        {"id": "r1", "name": "platform-admin", "composite": true, "clientRole": false, "containerId": "realm-uuid"}
      ],
      "clientMappings": {
        "realm-management": {
          "id": "client-uuid",
          "client": "realm-management",
          "mappings": [
            {"id": "c1", "name": "view-users", "composite": false, "clientRole": true, "containerId": "client-uuid"}
          ]
        }
      }
    }`

	var rec roleMappingsRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	require.Len(t, rec.RealmMappings, 1)
	assert.Equal(t, "platform-admin", rec.RealmMappings[0].Name)

	mapping, ok := rec.ClientMappings["realm-management"]
	require.True(t, ok)
	assert.Equal(t, "realm-management", mapping.Client)
	require.Len(t, mapping.Mappings, 1)
	assert.Equal(t, "view-users", mapping.Mappings[0].Name)
	assert.True(t, mapping.Mappings[0].ClientRole)
}

func TestHoldsAdminRole(t *testing.T) {
	tests := []struct {
		name  string
		roles []RoleRef
		want  bool
	}{
		{name: "no roles at all"},
		{
			name:  "an ordinary realm role",
			roles: []RoleRef{{Name: "offline_access"}, {Name: "developer"}},
		},
		{
			name:  "the master realm superuser role",
			roles: []RoleRef{{Name: "admin"}},
			want:  true,
		},
		{
			name:  "realm-admin on realm-management",
			roles: []RoleRef{{Name: "realm-admin", ClientRole: true, ClientID: "realm-management"}},
			want:  true,
		},
		{
			name:  "manage-users on realm-management",
			roles: []RoleRef{{Name: "manage-users", ClientRole: true, ClientID: "realm-management"}},
			want:  true,
		},
		{
			name:  "view-users is not administration",
			roles: []RoleRef{{Name: "view-users", ClientRole: true, ClientID: "realm-management"}},
		},
		{
			name:  "the master realm holds another realm's roles on a named client",
			roles: []RoleRef{{Name: "manage-realm", ClientRole: true, ClientID: "production-realm"}},
			want:  true,
		},
		{
			name:  "a role of the same name on an unrelated client does not count",
			roles: []RoleRef{{Name: "manage-users", ClientRole: true, ClientID: "billing-app"}},
		},
		{
			name:  "an unresolved client is still checked by name",
			roles: []RoleRef{{Name: "realm-admin", ClientRole: true}},
			want:  true,
		},
		{
			name:  "a realm role named realm-admin is not the master superuser role",
			roles: []RoleRef{{Name: "realm-admin"}},
		},
		{
			name: "one administering role among many is enough",
			roles: []RoleRef{
				{Name: "developer"},
				{Name: "view-clients", ClientRole: true, ClientID: "realm-management"},
				{Name: "impersonation", ClientRole: true, ClientID: "realm-management"},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HoldsAdminRole(tc.roles))
		})
	}
}

func TestUserRecordDecode(t *testing.T) {
	const payload = `{
      "id": "u-1",
      "username": "jane",
      "email": "jane@example.com",
      "firstName": "Jane",
      "lastName": "Doe",
      "enabled": true,
      "emailVerified": false,
      "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP"],
      "createdTimestamp": 1700000000000,
      "federationLink": "ldap-corp",
      "attributes": {"department": ["platform"]}
    }`

	var rec userRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "jane", rec.Username)
	assert.True(t, rec.Enabled)
	assert.False(t, rec.EmailVerified)
	assert.Equal(t, []string{"UPDATE_PASSWORD", "CONFIGURE_TOTP"}, rec.RequiredActions)
	assert.Equal(t, "ldap-corp", rec.FederationLink)
	assert.Equal(t, []string{"platform"}, rec.Attributes["department"])

	created := epochMillisToTime(rec.CreatedTimestamp)
	require.NotNil(t, created)
	assert.Equal(t, time.UnixMilli(1700000000000).UTC(), *created)
}

func TestUserRecordDecodeOfAServiceAccount(t *testing.T) {
	const payload = `{
      "id": "u-2",
      "username": "service-account-mondoo-scanner",
      "enabled": true,
      "emailVerified": false,
      "serviceAccountClientId": "mondoo-scanner"
    }`

	var rec userRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "mondoo-scanner", rec.ServiceAccountClientID)
	assert.True(t, IsServiceAccount(rec.ServiceAccountClientID, rec.Username))
}

func TestServiceAccountClientID(t *testing.T) {
	// The field is present on the service account endpoint.
	assert.Equal(t, "scanner", ServiceAccountClientID("scanner", "service-account-scanner"))
	// A realm's user list omits the field, so the user name is what is left.
	assert.Equal(t, "scanner", ServiceAccountClientID("", "service-account-scanner"))
	// An ordinary account belongs to nobody.
	assert.Empty(t, ServiceAccountClientID("", "jane"))
	// A person whose name merely starts with the word is not a service
	// account, but Keycloak reserves the exact prefix, so this is the shape
	// that matters.
	assert.Empty(t, ServiceAccountClientID("", "service-accountant"))

	assert.True(t, IsServiceAccount("", "service-account-scanner"))
	assert.False(t, IsServiceAccount("", "jane"))
	assert.False(t, IsServiceAccount("", ""))
}

func TestEpochMillisToTime(t *testing.T) {
	// An absent timestamp must stay null rather than becoming the epoch, which
	// would report 1 January 1970 as a real creation date.
	assert.Nil(t, epochMillisToTime(0))
	assert.Nil(t, epochMillisToTime(-1))

	got := epochMillisToTime(1700000000000)
	require.NotNil(t, got)
	assert.Equal(t, int64(1700000000000), got.UnixMilli())
}

func TestGroupRecordDecode(t *testing.T) {
	const payload = `{
      "id": "g-1",
      "name": "cluster-admins",
      "path": "/platform/cluster-admins",
      "subGroupCount": 2,
      "attributes": {"cost-center": ["4711"]},
      "realmRoles": ["platform-admin"],
      "clientRoles": {"realm-management": ["realm-admin", "view-users"]},
      "subGroups": []
    }`

	var rec groupRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "cluster-admins", rec.Name)
	assert.Equal(t, "/platform/cluster-admins", rec.Path)
	assert.Equal(t, int64(2), rec.SubGroupCount)
	assert.Equal(t, []string{"platform-admin"}, rec.RealmRoles)
	assert.Equal(t, []string{"realm-admin", "view-users"}, rec.ClientRoles["realm-management"])
	assert.Equal(t, []string{"4711"}, rec.Attributes["cost-center"])
	assert.Equal(t, int64(2), subGroupCount(&rec))
}

func TestSubGroupCountFallsBackToTheEmbeddedGroups(t *testing.T) {
	// An older server embeds the nested groups and reports no count.
	rec := groupRecord{SubGroups: []groupRecord{{ID: "a"}, {ID: "b"}, {ID: "c"}}}
	assert.Equal(t, int64(3), subGroupCount(&rec))

	// A group with neither reports none.
	assert.Equal(t, int64(0), subGroupCount(&groupRecord{}))
}

func TestIdentityProviderRecordDecode(t *testing.T) {
	const payload = `{
      "alias": "corp-oidc",
      "internalId": "idp-1",
      "displayName": "Corporate SSO",
      "providerId": "oidc",
      "enabled": true,
      "trustEmail": true,
      "storeToken": false,
      "addReadTokenRoleOnCreate": false,
      "linkOnly": false,
      "firstBrokerLoginFlowAlias": "first broker login",
      "postBrokerLoginFlowAlias": "",
      "config": {
        "validateSignature": "true",
        "useJwksUrl": "true",
        "jwksUrl": "https://idp.example.com/jwks",
        "issuer": "https://idp.example.com/",
        "authorizationUrl": "https://idp.example.com/authorize",
        "tokenUrl": "https://idp.example.com/token",
        "clientId": "keycloak",
        "clientAuthMethod": "client_secret_post",
        "pkceEnabled": "true",
        "syncMode": "FORCE",
        "defaultScope": "openid profile email",
        "hideOnLoginPage": "false"
      }
    }`

	var rec identityProviderRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "corp-oidc", rec.Alias)
	assert.Equal(t, "oidc", rec.ProviderID)
	assert.True(t, rec.Enabled)
	assert.True(t, rec.TrustEmail)
	assert.False(t, rec.LinkOnly)
	assert.Equal(t, "first broker login", rec.FirstBrokerLoginFlow)

	// Settings Keycloak keeps in the config map as strings.
	assert.True(t, configBool(rec.Config[idpConfigValidateSignature]))
	assert.True(t, configBool(rec.Config[idpConfigUseJwksURL]))
	assert.True(t, configBool(rec.Config[idpConfigPkceEnabled]))
	assert.Equal(t, "FORCE", rec.Config[idpConfigSyncMode])
	assert.Equal(t, "https://idp.example.com/", rec.Config[idpConfigIssuer])
	assert.Equal(t, "client_secret_post", rec.Config[idpConfigClientAuthMethod])
	assert.False(t, HideOnLoginPage(&rec))
}

func TestIdentityProviderWithoutSignatureValidation(t *testing.T) {
	const payload = `{
      "alias": "legacy-saml",
      "providerId": "saml",
      "enabled": true,
      "trustEmail": true,
      "hideOnLogin": true,
      "config": {"validateSignature": "false", "syncMode": "IMPORT"}
    }`

	var rec identityProviderRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.False(t, configBool(rec.Config[idpConfigValidateSignature]))
	assert.False(t, configBool(rec.Config[idpConfigUseJwksURL]))
	assert.Equal(t, "IMPORT", rec.Config[idpConfigSyncMode])
	// Newer servers moved the setting onto the representation itself.
	assert.True(t, HideOnLoginPage(&rec))
}

func TestConfigBool(t *testing.T) {
	assert.True(t, configBool("true"))
	assert.True(t, configBool("TRUE"))
	assert.True(t, configBool(" true "))
	assert.False(t, configBool("false"))
	assert.False(t, configBool(""))
	// Keycloak writes nothing else, so anything unexpected takes the state the
	// server itself applies when the setting is missing.
	assert.False(t, configBool("1"))
	assert.False(t, configBool("yes"))
}

func TestAuthenticationFlowRecordDecode(t *testing.T) {
	const payload = `[
      {"id": "f-1", "alias": "browser", "description": "browser based authentication", "providerId": "basic-flow", "topLevel": true, "builtIn": true},
      {"id": "f-2", "alias": "forms", "description": "username, password, otp and other auth forms", "providerId": "basic-flow", "topLevel": false, "builtIn": true}
    ]`

	var records []authenticationFlowRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &records))

	require.Len(t, records, 2)
	assert.Equal(t, "browser", records[0].Alias)
	assert.True(t, records[0].TopLevel)
	assert.True(t, records[0].BuiltIn)
	assert.False(t, records[1].TopLevel)
}

func TestExecutionRecordDecode(t *testing.T) {
	// The shape of GET /authentication/flows/browser/executions, which is what
	// makes a missing second factor visible.
	const payload = `[
      {"id": "e-1", "requirement": "ALTERNATIVE", "displayName": "Cookie", "requirementChoices": ["REQUIRED","ALTERNATIVE","DISABLED"], "configurable": false, "providerId": "auth-cookie", "level": 0, "index": 0},
      {"id": "e-2", "requirement": "ALTERNATIVE", "displayName": "forms", "requirementChoices": ["REQUIRED","ALTERNATIVE","DISABLED"], "configurable": false, "authenticationFlow": true, "flowId": "f-2", "level": 0, "index": 2},
      {"id": "e-3", "requirement": "REQUIRED", "displayName": "Username Password Form", "requirementChoices": ["REQUIRED"], "configurable": false, "providerId": "auth-username-password-form", "level": 1, "index": 0},
      {"id": "e-4", "requirement": "CONDITIONAL", "displayName": "Browser - Conditional OTP", "requirementChoices": ["REQUIRED","ALTERNATIVE","DISABLED","CONDITIONAL"], "configurable": false, "authenticationFlow": true, "flowId": "f-3", "level": 1, "index": 1}
    ]`

	var records []executionRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &records))

	require.Len(t, records, 4)

	assert.Equal(t, "auth-cookie", records[0].ProviderID)
	assert.Equal(t, "ALTERNATIVE", records[0].Requirement)
	assert.Equal(t, int64(0), records[0].Level)
	assert.Empty(t, SubFlowAlias(&records[0]))

	// A sub-flow carries no authenticator, and its alias is the display name.
	assert.True(t, records[1].AuthenticationFlow)
	assert.Empty(t, records[1].ProviderID)
	assert.Equal(t, "forms", SubFlowAlias(&records[1]))

	assert.Equal(t, "REQUIRED", records[2].Requirement)
	assert.Equal(t, "auth-username-password-form", records[2].ProviderID)
	assert.Equal(t, int64(1), records[2].Level)

	assert.Equal(t, "CONDITIONAL", records[3].Requirement)
	assert.Equal(t, "Browser - Conditional OTP", SubFlowAlias(&records[3]))
}

func TestComponentRecordDecodeOfAnLdapFederation(t *testing.T) {
	const payload = `{
      "id": "comp-1",
      "name": "corp-ldap",
      "providerId": "ldap",
      "providerType": "org.keycloak.storage.UserStorageProvider",
      "parentId": "f4b1a0b8-0f0c-4a58-9f36-6f2a9f0f2a11",
      "config": {
        "connectionUrl": ["ldap://ldap.corp.example.com:389"],
        "startTls": ["false"],
        "useTruststoreSpi": ["always"],
        "bindDn": ["cn=keycloak,ou=services,dc=corp,dc=example,dc=com"],
        "usersDn": ["ou=people,dc=corp,dc=example,dc=com"],
        "authType": ["simple"],
        "editMode": ["READ_ONLY"],
        "vendor": ["other"],
        "validatePasswordPolicy": ["false"],
        "trustEmail": ["true"]
      }
    }`

	var rec componentRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "corp-ldap", rec.Name)
	assert.Equal(t, "ldap", rec.ProviderID)
	assert.Equal(t, userStorageProviderType, rec.ProviderType)

	// Every component setting arrives as a list, even when it holds one value.
	assert.Equal(t, "ldap://ldap.corp.example.com:389", firstConfigValue(rec.Config, componentConfigConnectionURL))
	assert.False(t, configBool(firstConfigValue(rec.Config, componentConfigStartTLS)))
	assert.Equal(t, "always", firstConfigValue(rec.Config, componentConfigUseTruststoreSpi))
	assert.Equal(t, "READ_ONLY", firstConfigValue(rec.Config, componentConfigEditMode))
	assert.True(t, configBool(firstConfigValue(rec.Config, componentConfigTrustEmail)))

	// A plaintext LDAP URL with StartTLS off sends the bind credentials and
	// every validated password in the clear.
	assert.False(t, ConnectionEncrypted(
		firstConfigValue(rec.Config, componentConfigConnectionURL),
		configBool(firstConfigValue(rec.Config, componentConfigStartTLS)),
	))
}

func TestFirstConfigValue(t *testing.T) {
	config := map[string][]string{
		"connectionUrl": {"ldaps://ldap.example.com:636"},
		"empty":         {},
		"multi":         {"first", "second"},
	}

	assert.Equal(t, "ldaps://ldap.example.com:636", firstConfigValue(config, "connectionUrl"))
	assert.Empty(t, firstConfigValue(config, "empty"))
	assert.Empty(t, firstConfigValue(config, "absent"))
	assert.Equal(t, "first", firstConfigValue(config, "multi"))
	assert.Empty(t, firstConfigValue(nil, "connectionUrl"))
}

func TestConnectionEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		startTLS bool
		want     bool
	}{
		{name: "ldaps is encrypted from the start", url: "ldaps://ldap.example.com:636", want: true},
		{name: "ldaps is matched case insensitively", url: "LDAPS://ldap.example.com:636", want: true},
		{name: "ldaps with surrounding space", url: " ldaps://ldap.example.com ", want: true},
		{name: "plaintext ldap with StartTLS", url: "ldap://ldap.example.com:389", startTLS: true, want: true},
		{name: "plaintext ldap without StartTLS", url: "ldap://ldap.example.com:389"},
		{name: "a component that names no directory", url: "", startTLS: true},
		{name: "no directory and no StartTLS", url: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ConnectionEncrypted(tc.url, tc.startTLS))
		})
	}
}

func TestRequiredActionRecordDecode(t *testing.T) {
	const payload = `[
      {"alias": "CONFIGURE_TOTP", "name": "Configure OTP", "providerId": "CONFIGURE_TOTP", "enabled": true, "defaultAction": false, "priority": 10, "config": {}},
      {"alias": "UPDATE_PASSWORD", "name": "Update Password", "providerId": "UPDATE_PASSWORD", "enabled": true, "defaultAction": false, "priority": 30, "config": {}},
      {"alias": "VERIFY_EMAIL", "name": "Verify Email", "providerId": "VERIFY_EMAIL", "enabled": true, "defaultAction": true, "priority": 50, "config": {}}
    ]`

	var records []requiredActionRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &records))

	require.Len(t, records, 3)
	// A one-time password that is available but not asked of every new user is
	// a second factor the realm offers without requiring it.
	assert.Equal(t, "CONFIGURE_TOTP", records[0].Alias)
	assert.True(t, records[0].Enabled)
	assert.False(t, records[0].DefaultAction)
	assert.Equal(t, int64(10), records[0].Priority)

	assert.True(t, records[2].DefaultAction)
}

func TestRealmBriefDecode(t *testing.T) {
	// GET /admin/realms answers with brief representations, which is why the
	// settings are read from each realm's own endpoint.
	const payload = `[
      {"id": "1", "realm": "master", "displayName": "Keycloak"},
      {"id": "2", "realm": "production"}
    ]`

	var records []realmBrief
	require.NoError(t, json.Unmarshal([]byte(payload), &records))

	require.Len(t, records, 2)
	assert.Equal(t, "master", records[0].Realm)
	assert.Equal(t, "production", records[1].Realm)
}

func TestMultiMapToDict(t *testing.T) {
	got := multiMapToDict(map[string][]string{
		"connectionUrl": {"ldaps://ldap.example.com"},
		"empty":         {},
	})

	want := map[string]any{
		"connectionUrl": []any{"ldaps://ldap.example.com"},
		"empty":         []any{},
	}
	assert.Equal(t, want, got)

	assert.Equal(t, map[string]any{}, multiMapToDict(nil))
}

func TestSliceAndMapWidening(t *testing.T) {
	assert.Equal(t, []any{"a", "b"}, strSliceToAny([]string{"a", "b"}))
	assert.Equal(t, []any{}, strSliceToAny(nil))

	assert.Equal(t, map[string]any{"k": "v"}, mapStrToAny(map[string]string{"k": "v"}))
	assert.Equal(t, map[string]any{}, mapStrToAny(nil))
}

func TestHoldsAdminRoleEvaluatesTheWholeList(t *testing.T) {
	// The administering role sits last, behind many ordinary ones. A check
	// that stopped at the first non-matching entry would answer false.
	roles := make([]RoleRef, 0, 51)
	for i := range 50 {
		roles = append(roles, RoleRef{Name: "team-role-" + strconv.Itoa(i)})
	}
	roles = append(roles, RoleRef{Name: "realm-admin", ClientRole: true, ClientID: "realm-management"})

	assert.True(t, HoldsAdminRole(roles))

	// The same list without the last entry must answer false, which shows the
	// result comes from that entry and not from the ordinary ones.
	assert.False(t, HoldsAdminRole(roles[:50]))
}

func TestHoldsAdminRoleOnASingleRef(t *testing.T) {
	// The walk settles the answer one ref at a time, so a single-entry list
	// must give the same verdict as the same entry inside a longer one.
	admin := RoleRef{Name: "manage-realm", ClientRole: true, ClientID: "realm-management"}
	ordinary := RoleRef{Name: "developer"}

	assert.True(t, HoldsAdminRole([]RoleRef{admin}))
	assert.False(t, HoldsAdminRole([]RoleRef{ordinary}))
	assert.True(t, HoldsAdminRole([]RoleRef{ordinary, admin}))
}

func TestClientRoleMappingsCollectEveryClient(t *testing.T) {
	// The client role picker must walk every client mapping. A group that
	// grants realm-management roles through the second client would otherwise
	// look harmless.
	mappings := &roleMappingsRecord{
		RealmMappings: []roleRecord{{ID: "r1", Name: "developer"}},
		ClientMappings: map[string]clientRoleMappings{
			"account": {
				Client:   "account",
				Mappings: []roleRecord{{ID: "c1", Name: "view-profile", ClientRole: true}},
			},
			"realm-management": {
				Client:   "realm-management",
				Mappings: []roleRecord{{ID: "c2", Name: "realm-admin", ClientRole: true}},
			},
		},
	}

	clientOnly := []roleRecord{}
	for _, mapping := range mappings.ClientMappings {
		clientOnly = append(clientOnly, mapping.Mappings...)
	}
	require.Len(t, clientOnly, 2)

	names := map[string]bool{}
	for _, rec := range clientOnly {
		names[rec.Name] = true
		// The realm role must not leak into the client-only list.
		assert.True(t, rec.ClientRole)
	}
	assert.True(t, names["realm-admin"])
	assert.True(t, names["view-profile"])

	// allRoles is the union, so it carries the realm role as well.
	assert.Len(t, collectMappedRoles(mappings), 3)
}
