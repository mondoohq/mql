// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeSecurityIntegrationInternal struct {
	descLock    sync.Mutex
	descLoaded  bool
	descProps   map[string]string
	descLoadErr error
}

func (r *mqlSnowflakeAccount) securityIntegrations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	integrations, err := client.SecurityIntegrations.Show(ctx, &sdk.ShowSecurityIntegrationRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range integrations {
		mqlSecurityIntegration, err := newMqlSnowflakeSecurityIntegration(r.MqlRuntime, integrations[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlSecurityIntegration)
	}

	return list, nil
}

func newMqlSnowflakeSecurityIntegration(runtime *plugin.Runtime, integration sdk.SecurityIntegration) (*mqlSnowflakeSecurityIntegration, error) {
	r, err := CreateResource(runtime, "snowflake.securityIntegration", map[string]*llx.RawData{
		"__id":      llx.StringData(sdk.NewAccountObjectIdentifier(integration.Name).FullyQualifiedName()),
		"name":      llx.StringData(integration.Name),
		"type":      llx.StringData(integration.IntegrationType),
		"comment":   llx.StringData(integration.Comment),
		"enabled":   llx.BoolData(integration.Enabled),
		"createdAt": llx.TimeData(integration.CreatedOn),
		"category":  llx.StringData(integration.Category),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeSecurityIntegration)
	return mqlResource, nil
}

// describeProperties fetches DESCRIBE SECURITY INTEGRATION once and caches the
// flattened name->value map. SAML2_X509_CERT, SAML2_ISSUER, OAUTH_CLIENT_ID,
// etc. all live in this single result set.
func (r *mqlSnowflakeSecurityIntegration) describeProperties() (map[string]string, error) {
	if r.descLoaded {
		return r.descProps, r.descLoadErr
	}
	r.descLock.Lock()
	defer r.descLock.Unlock()
	if r.descLoaded {
		return r.descProps, r.descLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	props, err := client.SecurityIntegrations.Describe(ctx, sdk.NewAccountObjectIdentifier(r.Name.Data))
	if err != nil {
		r.descLoaded = true
		r.descLoadErr = err
		return nil, err
	}

	out := make(map[string]string, len(props))
	for _, p := range props {
		out[p.Name] = p.Value
	}
	r.descProps = out
	r.descLoaded = true
	return out, nil
}

func (r *mqlSnowflakeSecurityIntegration) properties() (map[string]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		out[k] = v
	}
	return out, nil
}

func (r *mqlSnowflakeSecurityIntegration) saml2X509Cert() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["SAML2_X509_CERT"], nil
}

func (r *mqlSnowflakeSecurityIntegration) saml2Issuer() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["SAML2_ISSUER"], nil
}

func (r *mqlSnowflakeSecurityIntegration) saml2Provider() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["SAML2_PROVIDER"], nil
}

func (r *mqlSnowflakeSecurityIntegration) saml2SsoUrl() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["SAML2_SSO_URL"], nil
}

func (r *mqlSnowflakeSecurityIntegration) saml2SignRequest() (bool, error) {
	props, err := r.describeProperties()
	if err != nil {
		return false, err
	}
	return parseSnowflakeBool(props["SAML2_SIGN_REQUEST"]), nil
}

func (r *mqlSnowflakeSecurityIntegration) saml2ForceAuthn() (bool, error) {
	props, err := r.describeProperties()
	if err != nil {
		return false, err
	}
	return parseSnowflakeBool(props["SAML2_FORCE_AUTHN"]), nil
}

// parseSnowflakeBool handles the common rendering of bool properties from
// DESCRIBE results. Snowflake returns "true"/"false" (lowercase) for most
// booleans but parseBool tolerates uppercase variants.
func parseSnowflakeBool(value string) bool {
	if value == "" {
		return false
	}
	b, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return b
}

// initSnowflakeSecurityIntegration resolves a security integration by name so
// typed references (such as snowflake.authenticationPolicy.securityIntegrationRefs)
// can hydrate a full integration from just its name.
func initSnowflakeSecurityIntegration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("snowflake.securityIntegration requires a non-empty name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	integrations, err := client.SecurityIntegrations.Show(ctx, sdk.NewShowSecurityIntegrationRequest().WithLike(sdk.Like{Pattern: new(name)}))
	if err != nil {
		return nil, nil, err
	}
	for i := range integrations {
		if integrations[i].Name == name {
			res, err := newMqlSnowflakeSecurityIntegration(runtime, integrations[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.securityIntegration %q not found", name)
}

// Reading one property out of DESCRIBE SECURITY INTEGRATION.
//
// The result set is one row per property of the integration's own type, so a
// SAML integration reports no OAUTH_ properties at all and a SCIM integration
// reports neither. An absent property is therefore unknown, not off, and the
// difference is load bearing: reporting a missing OAUTH_ENFORCE_PKCE as false
// would say a proof key is not enforced on an integration that has no
// authorization code flow to enforce it on, and an assertion written against
// that would fail on every SAML integration in the account.
//
// An empty value is a different thing and is reported as it stands, because
// Snowflake does return an empty string for a list property that is set to
// nothing.

// stringProperty returns a property value, marking the field null when the
// integration does not report the property.
func stringProperty(props map[string]string, key string, field *plugin.TValue[string]) (string, error) {
	value, ok := props[key]
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return strings.TrimSpace(value), nil
}

// boolProperty returns a boolean property, marking the field null when the
// property is absent or does not read as a boolean.
func boolProperty(props map[string]string, key string, field *plugin.TValue[bool]) (bool, error) {
	value, ok := props[key]
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return parsed, nil
}

// intProperty returns an integer property, marking the field null when the
// property is absent or does not read as an integer.
func intProperty(props map[string]string, key string, field *plugin.TValue[int64]) (int64, error) {
	value, ok := props[key]
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return parsed, nil
}

// listProperty returns a list property, marking the field null when the
// integration does not report the property.
func listProperty(props map[string]string, key string, field *plugin.TValue[[]any]) ([]any, error) {
	value, ok := props[key]
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return parseSecurityIntegrationList(value), nil
}

// parseSecurityIntegrationList splits a list-valued DESCRIBE SECURITY
// INTEGRATION property into its members.
//
// Snowflake renders these in more than one shape. A roles list arrives bare
// (`ACCOUNTADMIN,SECURITYADMIN`), while a claim or audience list arrives
// bracketed with quoted members (`['upn', 'sub']`), so brackets and either
// quote style are stripped. An empty value yields an empty list rather than a
// list holding one empty member.
func parseSecurityIntegrationList(value string) []any {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	out := []any{}
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `'"`)
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthAnyRoleMode() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "EXTERNAL_OAUTH_ANY_ROLE_MODE", &r.ExternalOauthAnyRoleMode)
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthIssuer() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "EXTERNAL_OAUTH_ISSUER", &r.ExternalOauthIssuer)
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthSnowflakeUserMappingAttribute() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE", &r.ExternalOauthSnowflakeUserMappingAttribute)
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthTokenUserMappingClaims() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return listProperty(props, "EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM", &r.ExternalOauthTokenUserMappingClaims)
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthAudienceList() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return listProperty(props, "EXTERNAL_OAUTH_AUDIENCE_LIST", &r.ExternalOauthAudienceList)
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthAllowedRolesList() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return listProperty(props, "EXTERNAL_OAUTH_ALLOWED_ROLES_LIST", &r.ExternalOauthAllowedRolesList)
}

func (r *mqlSnowflakeSecurityIntegration) externalOauthBlockedRolesList() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return listProperty(props, "EXTERNAL_OAUTH_BLOCKED_ROLES_LIST", &r.ExternalOauthBlockedRolesList)
}

func (r *mqlSnowflakeSecurityIntegration) oauthClientType() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "OAUTH_CLIENT_TYPE", &r.OauthClientType)
}

func (r *mqlSnowflakeSecurityIntegration) oauthRedirectUri() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "OAUTH_REDIRECT_URI", &r.OauthRedirectUri)
}

func (r *mqlSnowflakeSecurityIntegration) oauthIssueRefreshTokens() (bool, error) {
	props, err := r.describeProperties()
	if err != nil {
		return false, err
	}
	return boolProperty(props, "OAUTH_ISSUE_REFRESH_TOKENS", &r.OauthIssueRefreshTokens)
}

func (r *mqlSnowflakeSecurityIntegration) oauthRefreshTokenValidity() (int64, error) {
	props, err := r.describeProperties()
	if err != nil {
		return 0, err
	}
	return intProperty(props, "OAUTH_REFRESH_TOKEN_VALIDITY", &r.OauthRefreshTokenValidity)
}

func (r *mqlSnowflakeSecurityIntegration) oauthEnforcePkce() (bool, error) {
	props, err := r.describeProperties()
	if err != nil {
		return false, err
	}
	return boolProperty(props, "OAUTH_ENFORCE_PKCE", &r.OauthEnforcePkce)
}

func (r *mqlSnowflakeSecurityIntegration) oauthUseSecondaryRoles() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "OAUTH_USE_SECONDARY_ROLES", &r.OauthUseSecondaryRoles)
}

func (r *mqlSnowflakeSecurityIntegration) blockedRolesList() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return listProperty(props, "BLOCKED_ROLES_LIST", &r.BlockedRolesList)
}

func (r *mqlSnowflakeSecurityIntegration) scimClient() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return stringProperty(props, "SCIM_CLIENT", &r.ScimClient)
}

func (r *mqlSnowflakeSecurityIntegration) syncPassword() (bool, error) {
	props, err := r.describeProperties()
	if err != nil {
		return false, err
	}
	return boolProperty(props, "SYNC_PASSWORD", &r.SyncPassword)
}

func (r *mqlSnowflakeSecurityIntegration) runAsRole() (*mqlSnowflakeRole, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	name, ok := props["RUN_AS_ROLE"]
	if !ok {
		r.RunAsRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOwnerRole(r.MqlRuntime, strings.TrimSpace(name), &r.RunAsRole)
}

func (r *mqlSnowflakeSecurityIntegration) networkPolicy() (*mqlSnowflakeNetworkPolicy, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(props["NETWORK_POLICY"])
	if name == "" {
		r.NetworkPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	policy, err := networkPolicyByName(r.MqlRuntime, name)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		r.NetworkPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return policy, nil
}
