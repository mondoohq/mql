// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

type mqlCloudflareOneInternal struct {
	ZoneID    string
	AccountID string
}

// The Cloudflare Access (Zero Trust) list endpoints are modeled as polymorphic
// unions in cloudflare-go (apps and identity providers vary by type). To keep
// the existing MQL schema stable we read these endpoints via the client's
// generic Get and decode them into the flat shapes below.
type (
	accessApp struct {
		ID                      string            `json:"id"`
		AUD                     string            `json:"aud"`
		Name                    string            `json:"name"`
		Domain                  string            `json:"domain"`
		AllowedIdps             []string          `json:"allowed_idps"`
		AppLauncherVisible      *bool             `json:"app_launcher_visible"`
		AutoRedirectToIdentity  *bool             `json:"auto_redirect_to_identity"`
		OptionsPreflightBypass  *bool             `json:"options_preflight_bypass"`
		CustomDenyMessage       string            `json:"custom_deny_message"`
		CustomDenyURL           string            `json:"custom_deny_url"`
		ServiceAuth401Redirect  *bool             `json:"service_auth_401_redirect"`
		EnableBindingCookie     *bool             `json:"enable_binding_cookie"`
		HTTPOnlyCookieAttribute *bool             `json:"http_only_cookie_attribute"`
		SameSiteCookieAttribute string            `json:"same_site_cookie_attribute"`
		LogoURL                 string            `json:"logo_url"`
		SessionDuration         string            `json:"session_duration"`
		SkipInterstitial        *bool             `json:"skip_interstitial"`
		Type                    string            `json:"type"`
		CreatedAt               *time.Time        `json:"created_at"`
		UpdatedAt               *time.Time        `json:"updated_at"`
		CorsHeaders             *accessCorsHeader `json:"cors_headers"`
		Policies                []accessPolicy    `json:"policies"`

		AllowAuthenticateViaWarp    *bool                  `json:"allow_authenticate_via_warp"`
		AllowIframe                 *bool                  `json:"allow_iframe"`
		ReadServiceTokensFromHeader *string                `json:"read_service_tokens_from_header"`
		PathCookieAttribute         *bool                  `json:"path_cookie_attribute"`
		MfaConfig                   *accessMfaConfig       `json:"mfa_config"`
		Destinations                []accessAppDestination `json:"destinations"`
	}

	// accessMfaConfig is the MFA configuration carried by an organization, an
	// application or a policy. A nil pointer means the record has none.
	accessMfaConfig struct {
		AllowedAuthenticators []string `json:"allowed_authenticators"`
		MfaDisabled           *bool    `json:"mfa_disabled"`
		SessionDuration       *string  `json:"session_duration"`
	}

	// accessAppDestination is one destination an Access application protects.
	// Which fields are set depends on the destination type.
	accessAppDestination struct {
		Type       *string `json:"type"`
		URI        *string `json:"uri"`
		Hostname   *string `json:"hostname"`
		CIDR       *string `json:"cidr"`
		PortRange  *string `json:"port_range"`
		L4Protocol *string `json:"l4_protocol"`
		VnetID     *string `json:"vnet_id"`
	}

	accessCorsHeader struct {
		AllowAllHeaders  bool     `json:"allow_all_headers"`
		AllowAllMethods  bool     `json:"allow_all_methods"`
		AllowAllOrigins  bool     `json:"allow_all_origins"`
		AllowCredentials bool     `json:"allow_credentials"`
		AllowedHeaders   []string `json:"allowed_headers"`
		AllowedMethods   []string `json:"allowed_methods"`
		AllowedOrigins   []string `json:"allowed_origins"`
		MaxAge           int64    `json:"max_age"`
	}

	accessPolicy struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		Decision   string     `json:"decision"`
		Precedence int64      `json:"precedence"`
		CreatedAt  *time.Time `json:"created_at"`
		UpdatedAt  *time.Time `json:"updated_at"`
		Include    []any      `json:"include"`
		Require    []any      `json:"require"`
		Exclude    []any      `json:"exclude"`

		ApprovalRequired             *bool            `json:"approval_required"`
		IsolationRequired            *bool            `json:"isolation_required"`
		PurposeJustificationRequired *bool            `json:"purpose_justification_required"`
		SessionDuration              *string          `json:"session_duration"`
		MfaConfig                    *accessMfaConfig `json:"mfa_config"`
		// AppCount is only reported for reusable account-level policies; a
		// policy embedded in an application record omits it.
		AppCount *int64 `json:"app_count"`
	}

	accessGroup struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		CreatedAt *time.Time `json:"created_at"`
		UpdatedAt *time.Time `json:"updated_at"`
		Include   []any      `json:"include"`
		Require   []any      `json:"require"`
		Exclude   []any      `json:"exclude"`
	}

	accessServiceToken struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		ClientID   string     `json:"client_id"`
		Duration   string     `json:"duration"`
		ExpiresAt  *time.Time `json:"expires_at"`
		LastSeenAt *time.Time `json:"last_seen_at"`
		CreatedAt  *time.Time `json:"created_at"`
		UpdatedAt  *time.Time `json:"updated_at"`
		Enabled    *bool      `json:"enabled"`
		// The leak fields are omitted unless a secret scanning partner
		// reported the token's client secret.
		LeakReportedAt *time.Time `json:"leak_reported_at"`
		LeakReporter   *string    `json:"leak_reporter"`
		LeakReportURL  *string    `json:"leak_report_url"`
	}

	accessOrganization struct {
		Name                           string  `json:"name"`
		AuthDomain                     string  `json:"auth_domain"`
		IsUIReadOnly                   *bool   `json:"is_ui_read_only"`
		UserSeatExpirationInactiveTime string  `json:"user_seat_expiration_inactive_time"`
		AutoRedirectToIdentity         *bool   `json:"auto_redirect_to_identity"`
		SessionDuration                *string `json:"session_duration"`
		WarpAuthSessionDuration        *string `json:"warp_auth_session_duration"`
		AllowAuthenticateViaWarp       *bool   `json:"allow_authenticate_via_warp"`
		WarpAuthNonBrowser401          *bool   `json:"warp_auth_non_browser_401"`
		StrictServiceTokenAuth         *bool   `json:"strict_service_token_auth"`
		DisableEndUserAppCreation      *bool   `json:"disable_end_user_app_creation"`
		DenyUnmatchedRequests          *bool   `json:"deny_unmatched_requests"`
		// DenyUnmatchedRequestsExemptedZoneNames is nil when the organization
		// does not report the list.
		DenyUnmatchedRequestsExemptedZoneNames []string         `json:"deny_unmatched_requests_exempted_zone_names"`
		MfaRequiredForAllApps                  *bool            `json:"mfa_required_for_all_apps"`
		MfaConfig                              *accessMfaConfig `json:"mfa_config"`
		CreatedAt                              *time.Time       `json:"created_at"`
		UpdatedAt                              *time.Time       `json:"updated_at"`
		// ServiceTokenInactivity is nil when the organization does not report
		// the setting, so its fields read as null rather than as disabled.
		ServiceTokenInactivity *accessServiceTokenInactivity `json:"service_token_inactivity"`
	}

	accessServiceTokenInactivity struct {
		Enabled                 *bool   `json:"enabled"`
		Action                  *string `json:"action"`
		InactivityThresholdDays *int64  `json:"inactivity_threshold_days"`
	}

	// accessIdp decodes only the identity provider settings the schema
	// exposes. The OAuth client secret and the SCIM secret are deliberately
	// not decoded.
	accessIdp struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Config struct {
			SsoTargetURL       string   `json:"sso_target_url"`
			IssuerURL          string   `json:"issuer_url"`
			SignRequest        bool     `json:"sign_request"`
			IdpPublicCert      string   `json:"idp_public_cert"`
			EmailAttributeName string   `json:"email_attribute_name"`
			Attributes         []string `json:"attributes"`
			// These are type dependent: nil when the provider type does
			// not report them.
			PkceEnabled              *bool `json:"pkce_enabled"`
			ConditionalAccessEnabled *bool `json:"conditional_access_enabled"`
		} `json:"config"`
		ScimConfig struct {
			Enabled                bool    `json:"enabled"`
			UserDeprovision        *bool   `json:"user_deprovision"`
			SeatDeprovision        *bool   `json:"seat_deprovision"`
			IdentityUpdateBehavior *string `json:"identity_update_behavior"`
		} `json:"scim_config"`
	}
)

// isSAMLIdpType returns true for IdP types that authenticate via SAML 2.0
// (either the generic SAML connector or vendor-specific SAML connectors).
// OIDC and social IdPs (e.g., google, github, yandex) are excluded.
//
// Note: Cloudflare's `okta` connector is OIDC. Okta deployments that use
// SAML come through as the generic `saml` type, which is already covered.
func isSAMLIdpType(t string) bool {
	switch t {
	case "saml", "adfs", "centrify", "onelogin", "ping", "pingone":
		return true
	}
	return false
}

func newOne(runtime *plugin.Runtime, accountID, zoneID string) (*mqlCloudflareOne, error) {
	// Cloudflare One is account-scoped; the __id keys on the account. A
	// zone-scoped access is retained for backward compatibility and keys on
	// the zone so its zone-pathed apps/identityProviders stay distinct.
	key := "account@" + accountID
	if zoneID != "" {
		key = "zone@" + zoneID
	}
	res, err := CreateResource(runtime, "cloudflare.one", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.one@" + key),
	})
	if err != nil {
		return nil, err
	}

	one := res.(*mqlCloudflareOne)
	one.AccountID = accountID
	one.ZoneID = zoneID

	return one, nil
}

// accessScope returns the API path prefix for Access endpoints that exist at
// both account and zone scope (apps, identity providers). A zone-scoped One
// keeps querying the zone; an account-scoped One queries the account.
func (c *mqlCloudflareOne) accessScope() string {
	if c.ZoneID != "" {
		return "zones/" + c.ZoneID
	}
	return "accounts/" + c.AccountID
}

func (c *mqlCloudflareAccount) one() (*mqlCloudflareOne, error) {
	return newOne(c.MqlRuntime, c.Id.Data, "")
}

type mqlCloudflareOneAppInternal struct {
	// appPolicies caches the access policies embedded in the application
	// record so the policies() accessor needs no extra API call.
	appPolicies []accessPolicy
}

func (c *mqlCloudflareOneApp) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// accessRules normalizes an Access include/require/exclude rule list (a list of
// generic condition objects) into a dict-safe slice.
func accessRules(in []any) []any {
	if in == nil {
		return []any{}
	}
	return in
}

// stringPtrOrNil returns null for an absent, null or empty string, and the
// string otherwise.
func stringPtrOrNil(s *string) *llx.RawData {
	if s == nil || *s == "" {
		return llx.NilData
	}
	return llx.StringData(*s)
}

// mfaDisabled reports whether MFA is turned off, or null when the record has no
// MFA configuration or the configuration does not carry the flag.
func (m *accessMfaConfig) mfaDisabled() *llx.RawData {
	if m == nil {
		return llx.NilData
	}
	return llx.BoolDataPtr(m.MfaDisabled)
}

// allowedAuthenticators lists the permitted MFA methods, or null when the
// record has no MFA configuration or the configuration does not list them.
func (m *accessMfaConfig) allowedAuthenticators() *llx.RawData {
	if m == nil {
		return llx.NilData
	}
	return stringSliceOrNil(m.AllowedAuthenticators)
}

// sessionDuration returns the MFA session duration, or null when the record
// has no MFA configuration or sets none.
func (m *accessMfaConfig) sessionDuration() *llx.RawData {
	if m == nil {
		return llx.NilData
	}
	return stringPtrOrNil(m.SessionDuration)
}

// accessAppDestinationDicts converts an application's destinations into dicts,
// keeping only the keys the API returned for each destination. A nil slice
// (destinations not reported) reads as null.
func accessAppDestinationDicts(in []accessAppDestination) *llx.RawData {
	if in == nil {
		return llx.NilData
	}
	out := make([]any, 0, len(in))
	for i := range in {
		d := in[i]
		m := map[string]any{}
		for key, v := range map[string]*string{
			"type":       d.Type,
			"uri":        d.URI,
			"hostname":   d.Hostname,
			"cidr":       d.CIDR,
			"portRange":  d.PortRange,
			"l4Protocol": d.L4Protocol,
			"vnetId":     d.VnetID,
		} {
			if v != nil {
				m[key] = *v
			}
		}
		out = append(out, m)
	}
	return llx.ArrayData(out, types.Dict)
}

// newAccessPolicyResource builds an access policy resource, including its
// include/require/exclude condition rules. Shared by the account accessPolicies()
// listing and the per-application policies() accessor. fallbackKey supplies a
// unique cache key for inline app-attached policies, which historically arrive
// with an empty id — without it, every such policy would collide on the empty
// __id and alias to the first one. A policy with a real id keys on that id, so
// the same reusable policy dedups across the two access paths regardless of
// which path built it. An inline policy (empty id) keys on fallbackKey and is
// intentionally per-app: it has no id to dedup on and only ever exists inline,
// so it never needs to match an account-level entry.
func newAccessPolicyResource(runtime *plugin.Runtime, fallbackKey string, p accessPolicy) (plugin.Resource, error) {
	idKey := p.ID
	if idKey == "" {
		idKey = fallbackKey
	}
	return NewResource(runtime, "cloudflare.one.accessPolicy", map[string]*llx.RawData{
		"__id":       llx.StringData("cloudflare.one.accessPolicy@" + idKey),
		"id":         llx.StringData(p.ID),
		"name":       llx.StringData(p.Name),
		"decision":   llx.StringData(p.Decision),
		"precedence": llx.IntData(p.Precedence),
		"createdAt":  llx.TimeDataPtr(p.CreatedAt),
		"updatedAt":  llx.TimeDataPtr(p.UpdatedAt),
		"include":    llx.ArrayData(accessRules(p.Include), types.Dict),
		"require":    llx.ArrayData(accessRules(p.Require), types.Dict),
		"exclude":    llx.ArrayData(accessRules(p.Exclude), types.Dict),

		"approvalRequired":             llx.BoolDataPtr(p.ApprovalRequired),
		"isolationRequired":            llx.BoolDataPtr(p.IsolationRequired),
		"purposeJustificationRequired": llx.BoolDataPtr(p.PurposeJustificationRequired),
		"sessionDuration":              stringPtrOrNil(p.SessionDuration),
		"mfaDisabled":                  p.MfaConfig.mfaDisabled(),
		"mfaAllowedAuthenticators":     p.MfaConfig.allowedAuthenticators(),
		"appCount":                     llx.IntDataPtr(p.AppCount),
	})
}

func (c *mqlCloudflareOneApp) policies() ([]any, error) {
	result := make([]any, 0, len(c.appPolicies))
	for i := range c.appPolicies {
		p := c.appPolicies[i]
		// Content-derived fallback for inline policies without an id: name +
		// decision + precedence is stable across list reordering (precedence is
		// unique per app), unlike the loop index, which would shift the __id if
		// the API returned the policies in a different order on a later scan.
		fallback := fmt.Sprintf("%s/policy/%s/%s/%d", c.Id.Data, p.Name, p.Decision, p.Precedence)
		res, err := newAccessPolicyResource(c.MqlRuntime, fallback, p)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (c *mqlCloudflareOne) apps() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[accessApp](conn, fmt.Sprintf("%s/access/apps", c.accessScope()))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		resourceData := map[string]*llx.RawData{
			"id":     llx.StringData(rec.ID),
			"aud":    llx.StringData(rec.AUD),
			"name":   llx.StringData(rec.Name),
			"domain": llx.StringData(rec.Domain),

			"allowedIdentityProviders": llx.ArrayData(convert.SliceAnyToInterface(rec.AllowedIdps), types.String),

			"appLauncherVisible":     llx.BoolDataPtr(rec.AppLauncherVisible),
			"autoRedirectToIdentity": llx.BoolDataPtr(rec.AutoRedirectToIdentity),
			"optionsPreflightBypass": llx.BoolDataPtr(rec.OptionsPreflightBypass),

			"customDenyMessage":      llx.StringData(rec.CustomDenyMessage),
			"customDenyUrl":          llx.StringData(rec.CustomDenyURL),
			"serviceAuth401Redirect": llx.BoolDataPtr(rec.ServiceAuth401Redirect),

			"enableBindingCookie":     llx.BoolDataPtr(rec.EnableBindingCookie),
			"httpOnlyCookieAttribute": llx.BoolDataPtr(rec.HTTPOnlyCookieAttribute),
			"sameSiteCookieAttribute": llx.StringData(rec.SameSiteCookieAttribute),

			"logoUrl":          llx.StringData(rec.LogoURL),
			"sessionDuration":  llx.StringData(rec.SessionDuration),
			"skipInterstitial": llx.BoolDataPtr(rec.SkipInterstitial),

			"type": llx.StringData(rec.Type),

			"createdAt": llx.TimeDataPtr(rec.CreatedAt),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt),

			"corsHeaders": llx.NilData,

			"allowAuthenticateViaWarp":    llx.BoolDataPtr(rec.AllowAuthenticateViaWarp),
			"allowIframe":                 llx.BoolDataPtr(rec.AllowIframe),
			"readServiceTokensFromHeader": stringPtrOrNil(rec.ReadServiceTokensFromHeader),
			"pathCookieAttribute":         llx.BoolDataPtr(rec.PathCookieAttribute),
			"mfaDisabled":                 rec.MfaConfig.mfaDisabled(),
			"mfaAllowedAuthenticators":    rec.MfaConfig.allowedAuthenticators(),
			"destinations":                accessAppDestinationDicts(rec.Destinations),
		}

		if rec.CorsHeaders != nil {
			headers := rec.CorsHeaders
			corsHeaders, err := NewResource(c.MqlRuntime, "cloudflare.corsHeaders", map[string]*llx.RawData{
				"allowAllHeaders":  llx.BoolData(headers.AllowAllHeaders),
				"allowAllMethods":  llx.BoolData(headers.AllowAllMethods),
				"allowAllOrigins":  llx.BoolData(headers.AllowAllOrigins),
				"allowCredentials": llx.BoolData(headers.AllowCredentials),
				"allowedHeaders":   llx.ArrayData(convert.SliceAnyToInterface(headers.AllowedHeaders), types.String),
				"allowedMethods":   llx.ArrayData(convert.SliceAnyToInterface(headers.AllowedMethods), types.String),
				"allowedOrigins":   llx.ArrayData(convert.SliceAnyToInterface(headers.AllowedOrigins), types.String),
				"maxAge":           llx.IntData(headers.MaxAge),
			})
			if err != nil {
				return nil, err
			}
			resourceData["corsHeaders"] = llx.ResourceData(corsHeaders, corsHeaders.MqlName())
		}

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.app", resourceData)
		if err != nil {
			return nil, err
		}
		res.(*mqlCloudflareOneApp).appPolicies = rec.Policies

		result = append(result, res)
	}

	return result, nil
}

func (c *mqlCloudflareOneAccessPolicy) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) accessPolicies() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[accessPolicy](conn, fmt.Sprintf("accounts/%s/access/policies", c.AccountID))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		res, err := newAccessPolicyResource(c.MqlRuntime, records[i].ID, records[i])
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}

func (c *mqlCloudflareOneAccessGroup) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) accessGroups() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[accessGroup](conn, fmt.Sprintf("accounts/%s/access/groups", c.AccountID))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.accessGroup", map[string]*llx.RawData{
			"id":        llx.StringData(rec.ID),
			"name":      llx.StringData(rec.Name),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt),
			"include":   llx.ArrayData(accessRules(rec.Include), types.Dict),
			"require":   llx.ArrayData(accessRules(rec.Require), types.Dict),
			"exclude":   llx.ArrayData(accessRules(rec.Exclude), types.Dict),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}

func (c *mqlCloudflareOneServiceToken) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) serviceTokens() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[accessServiceToken](conn, fmt.Sprintf("accounts/%s/access/service_tokens", c.AccountID))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.serviceToken", map[string]*llx.RawData{
			"id":         llx.StringData(rec.ID),
			"name":       llx.StringData(rec.Name),
			"clientId":   llx.StringData(rec.ClientID),
			"duration":   llx.StringData(rec.Duration),
			"expiresAt":  llx.TimeDataPtr(rec.ExpiresAt),
			"lastSeenAt": llx.TimeDataPtr(rec.LastSeenAt),
			"createdAt":  llx.TimeDataPtr(rec.CreatedAt),
			"updatedAt":  llx.TimeDataPtr(rec.UpdatedAt),

			"enabled":        llx.BoolDataPtr(rec.Enabled),
			"leakReportedAt": llx.TimeDataPtr(rec.LeakReportedAt),
			"leakReporter":   stringPtrOrNil(rec.LeakReporter),
			"leakReportUrl":  stringPtrOrNil(rec.LeakReportURL),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}

// serviceTokenInactivity returns the organization's service-token inactivity
// settings, or an all-nil value when the organization does not report them.
func (o accessOrganization) serviceTokenInactivity() accessServiceTokenInactivity {
	if o.ServiceTokenInactivity == nil {
		return accessServiceTokenInactivity{}
	}
	return *o.ServiceTokenInactivity
}

func (c *mqlCloudflareOne) organization() (*mqlCloudflareOneOrganization, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result accessOrganization `json:"result"`
	}
	uri := fmt.Sprintf("accounts/%s/access/organizations", c.AccountID)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.Organization.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	org := env.Result
	inactivity := org.serviceTokenInactivity()

	res, err := NewResource(c.MqlRuntime, "cloudflare.one.organization", map[string]*llx.RawData{
		"__id":                                llx.StringData("cloudflare.one.organization@" + c.AccountID),
		"name":                                llx.StringData(org.Name),
		"authDomain":                          llx.StringData(org.AuthDomain),
		"isUiReadOnly":                        llx.BoolDataPtr(org.IsUIReadOnly),
		"userSeatExpirationInactiveTime":      llx.StringData(org.UserSeatExpirationInactiveTime),
		"autoRedirectToIdentity":              llx.BoolDataPtr(org.AutoRedirectToIdentity),
		"sessionDuration":                     llx.StringDataPtr(org.SessionDuration),
		"warpAuthSessionDuration":             llx.StringDataPtr(org.WarpAuthSessionDuration),
		"allowAuthenticateViaWarp":            llx.BoolDataPtr(org.AllowAuthenticateViaWarp),
		"warpAuthNonBrowser401":               llx.BoolDataPtr(org.WarpAuthNonBrowser401),
		"createdAt":                           llx.TimeDataPtr(org.CreatedAt),
		"updatedAt":                           llx.TimeDataPtr(org.UpdatedAt),
		"serviceTokenInactivityEnabled":       llx.BoolDataPtr(inactivity.Enabled),
		"serviceTokenInactivityAction":        llx.StringDataPtr(inactivity.Action),
		"serviceTokenInactivityThresholdDays": llx.IntDataPtr(inactivity.InactivityThresholdDays),
		"strictServiceTokenAuth":              llx.BoolDataPtr(org.StrictServiceTokenAuth),
		"disableEndUserAppCreation":           llx.BoolDataPtr(org.DisableEndUserAppCreation),
		"denyUnmatchedRequests":               llx.BoolDataPtr(org.DenyUnmatchedRequests),
		"mfaRequiredForAllApps":               llx.BoolDataPtr(org.MfaRequiredForAllApps),
		"mfaAllowedAuthenticators":            org.MfaConfig.allowedAuthenticators(),
		"mfaSessionDuration":                  org.MfaConfig.sessionDuration(),
	})
	if err != nil {
		return nil, err
	}

	o := res.(*mqlCloudflareOneOrganization)
	o.accountID = c.AccountID
	o.cacheExemptedZoneNames = org.DenyUnmatchedRequestsExemptedZoneNames
	return o, nil
}

// denyUnmatchedRequestsExemptedZones resolves the exempted zone names against
// the organization's own account's listed zones. Another account's zone of the
// same name is not this organization's exemption, and names with no listed zone
// in the account are left out.
func (o *mqlCloudflareOneOrganization) denyUnmatchedRequestsExemptedZones() ([]any, error) {
	if o.cacheExemptedZoneNames == nil {
		o.DenyUnmatchedRequestsExemptedZones.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if len(o.cacheExemptedZoneNames) == 0 {
		return []any{}, nil
	}
	list, err := listedZones(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return zonesNamed(o.cacheExemptedZoneNames, list, o.accountID), nil
}

func (c *mqlCloudflareOneIdp) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) identityProviders() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[accessIdp](conn, fmt.Sprintf("%s/access/identity_providers", c.accessScope()))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.idp", map[string]*llx.RawData{
			"id":                 llx.StringData(rec.ID),
			"name":               llx.StringData(rec.Name),
			"type":               llx.StringData(rec.Type),
			"saml":               llx.BoolData(isSAMLIdpType(rec.Type)),
			"ssoTargetUrl":       llx.StringData(rec.Config.SsoTargetURL),
			"issuerUrl":          llx.StringData(rec.Config.IssuerURL),
			"signRequest":        llx.BoolData(rec.Config.SignRequest),
			"idpPublicCert":      llx.StringData(rec.Config.IdpPublicCert),
			"emailAttributeName": llx.StringData(rec.Config.EmailAttributeName),
			"attributes":         llx.ArrayData(convert.SliceAnyToInterface(rec.Config.Attributes), types.String),
			"scimEnabled":        llx.BoolData(rec.ScimConfig.Enabled),

			"scimUserDeprovision":        llx.BoolDataPtr(rec.ScimConfig.UserDeprovision),
			"scimSeatDeprovision":        llx.BoolDataPtr(rec.ScimConfig.SeatDeprovision),
			"scimIdentityUpdateBehavior": stringPtrOrNil(rec.ScimConfig.IdentityUpdateBehavior),
			"pkceEnabled":                llx.BoolDataPtr(rec.Config.PkceEnabled),
			"conditionalAccessEnabled":   llx.BoolDataPtr(rec.Config.ConditionalAccessEnabled),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}
