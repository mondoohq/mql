// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/types"
)

// mqlKeycloakRealmInternal caches the default role of the realm, which arrives
// with the realm itself rather than through a lookup of its own.
type mqlKeycloakRealmInternal struct {
	cacheDefaultRole *roleRecord

	// The realm's default and optional scope lists are read once and shared by
	// every scope resource, so the two endpoints are called once per realm
	// rather than once per scope.
	defaultScopesLock    sync.Mutex
	defaultScopesFetched bool
	cacheDefaultScopes   *realmDefaultScopes
}

type realmRecord struct {
	ID                                 string            `json:"id"`
	Realm                              string            `json:"realm"`
	DisplayName                        string            `json:"displayName"`
	Enabled                            bool              `json:"enabled"`
	SslRequired                        string            `json:"sslRequired"`
	PasswordPolicy                     string            `json:"passwordPolicy"`
	BruteForceProtected                bool              `json:"bruteForceProtected"`
	PermanentLockout                   bool              `json:"permanentLockout"`
	FailureFactor                      int64             `json:"failureFactor"`
	WaitIncrementSeconds               int64             `json:"waitIncrementSeconds"`
	MaxFailureWaitSeconds              int64             `json:"maxFailureWaitSeconds"`
	MaxDeltaTimeSeconds                int64             `json:"maxDeltaTimeSeconds"`
	QuickLoginCheckMilliSeconds        int64             `json:"quickLoginCheckMilliSeconds"`
	MinimumQuickLoginWaitSeconds       int64             `json:"minimumQuickLoginWaitSeconds"`
	MaxTemporaryLockouts               int64             `json:"maxTemporaryLockouts"`
	RegistrationAllowed                bool              `json:"registrationAllowed"`
	RegistrationEmailAsUsername        bool              `json:"registrationEmailAsUsername"`
	RememberMe                         bool              `json:"rememberMe"`
	VerifyEmail                        bool              `json:"verifyEmail"`
	ResetPasswordAllowed               bool              `json:"resetPasswordAllowed"`
	EditUsernameAllowed                bool              `json:"editUsernameAllowed"`
	LoginWithEmailAllowed              bool              `json:"loginWithEmailAllowed"`
	DuplicateEmailsAllowed             bool              `json:"duplicateEmailsAllowed"`
	AccessTokenLifespan                int64             `json:"accessTokenLifespan"`
	AccessTokenLifespanForImplicitFlow int64             `json:"accessTokenLifespanForImplicitFlow"`
	SsoSessionIdleTimeout              int64             `json:"ssoSessionIdleTimeout"`
	SsoSessionMaxLifespan              int64             `json:"ssoSessionMaxLifespan"`
	SsoSessionIdleTimeoutRememberMe    int64             `json:"ssoSessionIdleTimeoutRememberMe"`
	SsoSessionMaxLifespanRememberMe    int64             `json:"ssoSessionMaxLifespanRememberMe"`
	OfflineSessionIdleTimeout          int64             `json:"offlineSessionIdleTimeout"`
	OfflineSessionMaxLifespanEnabled   bool              `json:"offlineSessionMaxLifespanEnabled"`
	OfflineSessionMaxLifespan          int64             `json:"offlineSessionMaxLifespan"`
	AccessCodeLifespan                 int64             `json:"accessCodeLifespan"`
	AccessCodeLifespanLogin            int64             `json:"accessCodeLifespanLogin"`
	AccessCodeLifespanUserAction       int64             `json:"accessCodeLifespanUserAction"`
	ActionTokenGeneratedByUserLifespan int64             `json:"actionTokenGeneratedByUserLifespan"`
	RevokeRefreshToken                 bool              `json:"revokeRefreshToken"`
	RefreshTokenMaxReuse               int64             `json:"refreshTokenMaxReuse"`
	OtpPolicyType                      string            `json:"otpPolicyType"`
	OtpPolicyAlgorithm                 string            `json:"otpPolicyAlgorithm"`
	OtpPolicyDigits                    int64             `json:"otpPolicyDigits"`
	OtpPolicyPeriod                    int64             `json:"otpPolicyPeriod"`
	DefaultSignatureAlgorithm          string            `json:"defaultSignatureAlgorithm"`
	EventsEnabled                      bool              `json:"eventsEnabled"`
	EventsExpiration                   int64             `json:"eventsExpiration"`
	AdminEventsEnabled                 bool              `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled          bool              `json:"adminEventsDetailsEnabled"`
	BrowserSecurityHeaders             map[string]string `json:"browserSecurityHeaders"`
	DefaultGroups                      []string          `json:"defaultGroups"`
	DefaultRole                        *roleRecord       `json:"defaultRole"`
	BrowserFlow                        string            `json:"browserFlow"`
	DirectGrantFlow                    string            `json:"directGrantFlow"`
	RegistrationFlow                   string            `json:"registrationFlow"`
	ResetCredentialsFlow               string            `json:"resetCredentialsFlow"`
	ClientAuthenticationFlow           string            `json:"clientAuthenticationFlow"`
	DockerAuthenticationFlow           string            `json:"dockerAuthenticationFlow"`
	FirstBrokerLoginFlow               string            `json:"firstBrokerLoginFlow"`
}

func newKeycloakRealm(runtime *plugin.Runtime, rec *realmRecord) (*mqlKeycloakRealm, error) {
	res, err := CreateResource(runtime, "keycloak.realm", map[string]*llx.RawData{
		"__id":                               llx.StringData(rec.Realm),
		"id":                                 llx.StringData(rec.ID),
		"name":                               llx.StringData(rec.Realm),
		"displayName":                        llx.StringData(rec.DisplayName),
		"enabled":                            llx.BoolData(rec.Enabled),
		"sslRequired":                        llx.StringData(rec.SslRequired),
		"passwordPolicy":                     llx.StringData(rec.PasswordPolicy),
		"passwordPolicyRules":                llx.MapData(mapStrToAny(ParsePasswordPolicy(rec.PasswordPolicy)), types.String),
		"bruteForceProtected":                llx.BoolData(rec.BruteForceProtected),
		"permanentLockout":                   llx.BoolData(rec.PermanentLockout),
		"failureFactor":                      llx.IntData(rec.FailureFactor),
		"waitIncrementSeconds":               llx.IntData(rec.WaitIncrementSeconds),
		"maxFailureWaitSeconds":              llx.IntData(rec.MaxFailureWaitSeconds),
		"maxDeltaTimeSeconds":                llx.IntData(rec.MaxDeltaTimeSeconds),
		"quickLoginCheckMilliSeconds":        llx.IntData(rec.QuickLoginCheckMilliSeconds),
		"minimumQuickLoginWaitSeconds":       llx.IntData(rec.MinimumQuickLoginWaitSeconds),
		"maxTemporaryLockouts":               llx.IntData(rec.MaxTemporaryLockouts),
		"registrationAllowed":                llx.BoolData(rec.RegistrationAllowed),
		"registrationEmailAsUsername":        llx.BoolData(rec.RegistrationEmailAsUsername),
		"rememberMe":                         llx.BoolData(rec.RememberMe),
		"verifyEmail":                        llx.BoolData(rec.VerifyEmail),
		"resetPasswordAllowed":               llx.BoolData(rec.ResetPasswordAllowed),
		"editUsernameAllowed":                llx.BoolData(rec.EditUsernameAllowed),
		"loginWithEmailAllowed":              llx.BoolData(rec.LoginWithEmailAllowed),
		"duplicateEmailsAllowed":             llx.BoolData(rec.DuplicateEmailsAllowed),
		"accessTokenLifespan":                llx.IntData(rec.AccessTokenLifespan),
		"accessTokenLifespanForImplicitFlow": llx.IntData(rec.AccessTokenLifespanForImplicitFlow),
		"ssoSessionIdleTimeout":              llx.IntData(rec.SsoSessionIdleTimeout),
		"ssoSessionMaxLifespan":              llx.IntData(rec.SsoSessionMaxLifespan),
		"ssoSessionIdleTimeoutRememberMe":    llx.IntData(rec.SsoSessionIdleTimeoutRememberMe),
		"ssoSessionMaxLifespanRememberMe":    llx.IntData(rec.SsoSessionMaxLifespanRememberMe),
		"offlineSessionIdleTimeout":          llx.IntData(rec.OfflineSessionIdleTimeout),
		"offlineSessionMaxLifespanEnabled":   llx.BoolData(rec.OfflineSessionMaxLifespanEnabled),
		"offlineSessionMaxLifespan":          llx.IntData(rec.OfflineSessionMaxLifespan),
		"accessCodeLifespan":                 llx.IntData(rec.AccessCodeLifespan),
		"accessCodeLifespanLogin":            llx.IntData(rec.AccessCodeLifespanLogin),
		"accessCodeLifespanUserAction":       llx.IntData(rec.AccessCodeLifespanUserAction),
		"actionTokenGeneratedByUserLifespan": llx.IntData(rec.ActionTokenGeneratedByUserLifespan),
		"revokeRefreshToken":                 llx.BoolData(rec.RevokeRefreshToken),
		"refreshTokenMaxReuse":               llx.IntData(rec.RefreshTokenMaxReuse),
		"otpPolicyType":                      llx.StringData(rec.OtpPolicyType),
		"otpPolicyAlgorithm":                 llx.StringData(rec.OtpPolicyAlgorithm),
		"otpPolicyDigits":                    llx.IntData(rec.OtpPolicyDigits),
		"otpPolicyPeriod":                    llx.IntData(rec.OtpPolicyPeriod),
		"defaultSignatureAlgorithm":          llx.StringData(rec.DefaultSignatureAlgorithm),
		"eventsEnabled":                      llx.BoolData(rec.EventsEnabled),
		"eventsExpiration":                   llx.IntData(rec.EventsExpiration),
		"adminEventsEnabled":                 llx.BoolData(rec.AdminEventsEnabled),
		"adminEventsDetailsEnabled":          llx.BoolData(rec.AdminEventsDetailsEnabled),
		"browserSecurityHeaders":             llx.MapData(mapStrToAny(rec.BrowserSecurityHeaders), types.String),
		"defaultGroups":                      llx.ArrayData(strSliceToAny(rec.DefaultGroups), types.String),
		"browserFlow":                        llx.StringData(rec.BrowserFlow),
		"directGrantFlow":                    llx.StringData(rec.DirectGrantFlow),
		"registrationFlow":                   llx.StringData(rec.RegistrationFlow),
		"resetCredentialsFlow":               llx.StringData(rec.ResetCredentialsFlow),
		"clientAuthenticationFlow":           llx.StringData(rec.ClientAuthenticationFlow),
		"dockerAuthenticationFlow":           llx.StringData(rec.DockerAuthenticationFlow),
		"firstBrokerLoginFlow":               llx.StringData(rec.FirstBrokerLoginFlow),
	})
	if err != nil {
		return nil, err
	}

	realm := res.(*mqlKeycloakRealm)
	realm.cacheDefaultRole = rec.DefaultRole
	return realm, nil
}

func (r *mqlKeycloakRealm) id() (string, error) {
	return r.Name.Data, r.Name.Error
}

// ParsePasswordPolicy splits a Keycloak password policy string into its named
// rules. Keycloak stores the policy as `length(12) and digits(1)`, and writes
// the argument of a rule that takes none as `undefined`, which is reported as
// an empty value so a policy can be asserted on by rule name alone.
func ParsePasswordPolicy(policy string) map[string]string {
	rules := map[string]string{}

	for part := range strings.SplitSeq(policy, " and ") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		name := part
		value := ""
		if open := strings.Index(part, "("); open >= 0 && strings.HasSuffix(part, ")") {
			name = strings.TrimSpace(part[:open])
			value = strings.TrimSpace(part[open+1 : len(part)-1])
			if value == "undefined" {
				value = ""
			}
		}
		if name == "" {
			continue
		}
		rules[name] = value
	}

	return rules
}

// realmName returns the realm a child lookup is scoped to.
func (r *mqlKeycloakRealm) realmName() string {
	return r.Name.Data
}

func (r *mqlKeycloakRealm) defaultRole() (*mqlKeycloakRole, error) {
	if r.cacheDefaultRole == nil || r.cacheDefaultRole.ID == "" {
		setNullResource(&r.DefaultRole)
		return nil, nil
	}
	return newKeycloakRole(r.MqlRuntime, r, r.cacheDefaultRole)
}

// --- realm children -------------------------------------------------------

func (r *mqlKeycloakRealm) clients() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	records, err := connection.GetPaged[clientRecord](ctx, c, connection.AdminPath(r.realmName(), "clients"), nil)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		client, err := newKeycloakClient(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, client)
	}
	return res, nil
}

func (r *mqlKeycloakRealm) roles() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	records, err := connection.GetPaged[roleRecord](ctx, c, connection.AdminPath(r.realmName(), "roles"), connection.FullRepresentation())
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		role, err := newKeycloakRole(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, role)
	}
	return res, nil
}

func (r *mqlKeycloakRealm) groups() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	records, err := connection.GetPaged[groupRecord](ctx, c, connection.AdminPath(r.realmName(), "groups"), connection.FullRepresentation())
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		group, err := newKeycloakGroup(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, group)
	}
	return res, nil
}

func (r *mqlKeycloakRealm) users() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	records, err := connection.GetPaged[userRecord](ctx, c, connection.AdminPath(r.realmName(), "users"), connection.FullRepresentation())
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		user, err := newKeycloakUser(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, user)
	}
	return res, nil
}

func (r *mqlKeycloakRealm) identityProviders() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	// The list endpoints below are walked with GetPaged rather than read in
	// one request. A server that caps the response would otherwise truncate it
	// silently, and a truncated flow list makes the realm's flow bindings
	// resolve to null for flows that are present. An endpoint that ignores the
	// paging parameters answers the second request with the same body, which
	// GetPaged detects and stops on, so the walk costs one extra request there.
	path := connection.AdminPath(r.realmName(), "identity-provider", "instances")
	records, err := connection.GetPaged[identityProviderRecord](ctx, c, path, nil)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		idp, err := newKeycloakIdentityProvider(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, idp)
	}
	return res, nil
}

func (r *mqlKeycloakRealm) authenticationFlows() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	path := connection.AdminPath(r.realmName(), "authentication", "flows")
	records, err := connection.GetPaged[authenticationFlowRecord](ctx, c, path, nil)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		flow, err := newKeycloakAuthenticationFlow(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, flow)
	}
	return res, nil
}

func (r *mqlKeycloakRealm) components() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	records, err := connection.GetPaged[componentRecord](ctx, c, connection.AdminPath(r.realmName(), "components"), nil)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		component, err := newKeycloakComponent(r.MqlRuntime, r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, component)
	}
	return res, nil
}

type requiredActionRecord struct {
	Alias         string            `json:"alias"`
	Name          string            `json:"name"`
	ProviderID    string            `json:"providerId"`
	Enabled       bool              `json:"enabled"`
	DefaultAction bool              `json:"defaultAction"`
	Priority      int64             `json:"priority"`
	Config        map[string]string `json:"config"`
}

func (r *mqlKeycloakRealm) requiredActions() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	path := connection.AdminPath(r.realmName(), "authentication", "required-actions")
	records, err := connection.GetPaged[requiredActionRecord](ctx, c, path, nil)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		created, err := CreateResource(r.MqlRuntime, "keycloak.realm.requiredAction", map[string]*llx.RawData{
			"__id":          llx.StringData(r.realmName() + "/" + rec.Alias),
			"alias":         llx.StringData(rec.Alias),
			"name":          llx.StringData(rec.Name),
			"providerId":    llx.StringData(rec.ProviderID),
			"enabled":       llx.BoolData(rec.Enabled),
			"defaultAction": llx.BoolData(rec.DefaultAction),
			"priority":      llx.IntData(rec.Priority),
			"config":        llx.MapData(mapStrToAny(rec.Config), types.String),
		})
		if err != nil {
			return nil, err
		}
		action := created.(*mqlKeycloakRealmRequiredAction)
		action.parentRealm = r
		res = append(res, action)
	}
	return res, nil
}

type mqlKeycloakRealmRequiredActionInternal struct {
	parentRealm *mqlKeycloakRealm
}

func (a *mqlKeycloakRealmRequiredAction) realm() (*mqlKeycloakRealm, error) {
	if a.parentRealm == nil {
		setNullResource(&a.Realm)
		return nil, nil
	}
	return a.parentRealm, nil
}

// --- flow bindings --------------------------------------------------------

func (r *mqlKeycloakRealm) browserFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	return r.flowByAlias(&r.BrowserFlowRef, r.BrowserFlow.Data)
}

func (r *mqlKeycloakRealm) directGrantFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	return r.flowByAlias(&r.DirectGrantFlowRef, r.DirectGrantFlow.Data)
}

func (r *mqlKeycloakRealm) registrationFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	return r.flowByAlias(&r.RegistrationFlowRef, r.RegistrationFlow.Data)
}

func (r *mqlKeycloakRealm) resetCredentialsFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	return r.flowByAlias(&r.ResetCredentialsFlowRef, r.ResetCredentialsFlow.Data)
}

func (r *mqlKeycloakRealm) clientAuthenticationFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	return r.flowByAlias(&r.ClientAuthenticationFlowRef, r.ClientAuthenticationFlow.Data)
}

func (r *mqlKeycloakRealm) dockerAuthenticationFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	return r.flowByAlias(&r.DockerAuthenticationFlowRef, r.DockerAuthenticationFlow.Data)
}

// flowByAlias resolves a binding through the realm's cached flow list, so the
// six bindings together cost one call rather than one call each.
func (r *mqlKeycloakRealm) flowByAlias(field *plugin.TValue[*mqlKeycloakAuthenticationFlow], alias string) (*mqlKeycloakAuthenticationFlow, error) {
	if alias == "" {
		setNullResource(field)
		return nil, nil
	}

	flows := r.GetAuthenticationFlows()
	if flows.Error != nil {
		return nil, flows.Error
	}

	for _, it := range flows.Data {
		flow, ok := it.(*mqlKeycloakAuthenticationFlow)
		if ok && flow.Alias.Data == alias {
			return flow, nil
		}
	}

	// A binding can name a flow the list does not carry, for example when the
	// realm was exported from a server whose flow was later removed. Report
	// that as null rather than as a failure of the whole realm.
	setNullResource(field)
	return nil, nil
}

// clientScopes lists the scopes defined in the realm, marking which ones the
// realm attaches to every new client.
func (r *mqlKeycloakRealm) clientScopes() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	var records []clientScopeRecord
	if err := c.Get(ctx, connection.AdminPath(r.realmName(), "client-scopes"), nil, &records); err != nil {
		return nil, err
	}

	realmScopes, err := r.defaultScopeSets()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		scope, err := newKeycloakClientScope(r.MqlRuntime, r, &records[i], realmScopes)
		if err != nil {
			return nil, err
		}
		res = append(res, scope)
	}
	return res, nil
}

// defaultScopeSets reads the realm's default and optional scope lists once and
// keeps them, since every scope resource and both name fields need them.
func (r *mqlKeycloakRealm) defaultScopeSets() (*realmDefaultScopes, error) {
	if r.defaultScopesFetched {
		return r.cacheDefaultScopes, nil
	}

	r.defaultScopesLock.Lock()
	defer r.defaultScopesLock.Unlock()
	if r.defaultScopesFetched {
		return r.cacheDefaultScopes, nil
	}

	sets, err := fetchRealmDefaultScopes(context.Background(), keycloakConn(r.MqlRuntime), r.realmName())
	if err != nil {
		return nil, err
	}

	r.cacheDefaultScopes = sets
	r.defaultScopesFetched = true
	return sets, nil
}

func (r *mqlKeycloakRealm) defaultDefaultClientScopes() ([]any, error) {
	sets, err := r.defaultScopeSets()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(sets.names), nil
}

func (r *mqlKeycloakRealm) defaultOptionalClientScopes() ([]any, error) {
	sets, err := r.defaultScopeSets()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(sets.optNames), nil
}
