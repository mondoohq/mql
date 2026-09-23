// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"
)

// This file models the instance tier: the application settings that govern
// every group and project below them, the CI/CD variables and hooks wired in
// at that scope, the OAuth applications registered against the instance, and
// the version and edition it runs.
//
// Everything here except gitlab.metadata needs an administrator token on a
// self-managed instance. gitlab.com answers 403 for a normal account, and
// older self-managed releases simply do not have some of these settings.
// Neither case is a scan failure, and neither may be reported as "switched
// off": a collection the token could not read is null, a collection that is
// genuinely empty is an empty list, and a setting the instance never sent is
// a null field.
//
// No secret material is modeled. Variable values, webhook tokens, and OAuth
// client secrets are all omitted, and only their presence is reported where
// GitLab reports it.

//
// Instance application settings
//

// instanceSettingsPolicy holds the application settings this provider reports
// as posture, decoded with pointers so a setting the instance never sent stays
// null instead of reading as off. GitLab added most of these in the last few
// major releases, so an older self-managed instance omits them outright.
type instanceSettingsPolicy struct {
	// credential lifecycle
	RequirePersonalAccessTokenExpiry      *bool  `json:"require_personal_access_token_expiry"`
	MaxPersonalAccessTokenLifetime        *int64 `json:"max_personal_access_token_lifetime"`
	ServiceAccessTokensExpirationEnforced *bool  `json:"service_access_tokens_expiration_enforced"`
	AllowRunnerRegistrationToken          *bool  `json:"allow_runner_registration_token"`
	RunnerTokenExpirationInterval         *int64 `json:"runner_token_expiration_interval"`
	GroupRunnerTokenExpirationInterval    *int64 `json:"group_runner_token_expiration_interval"`
	ProjectRunnerTokenExpirationInterval  *int64 `json:"project_runner_token_expiration_interval"`

	// SSH key algorithm and size restrictions
	RSAKeyRestriction       *int64 `json:"rsa_key_restriction"`
	DSAKeyRestriction       *int64 `json:"dsa_key_restriction"`
	ECDSAKeyRestriction     *int64 `json:"ecdsa_key_restriction"`
	ECDSASKKeyRestriction   *int64 `json:"ecdsa_sk_key_restriction"`
	Ed25519KeyRestriction   *int64 `json:"ed25519_key_restriction"`
	Ed25519SKKeyRestriction *int64 `json:"ed25519_sk_key_restriction"`

	// sign-in hardening and IP controls
	MaxLoginAttempts                                       *int64 `json:"max_login_attempts"`
	FailedLoginAttemptsUnlockPeriodInMinutes               *int64 `json:"failed_login_attempts_unlock_period_in_minutes"`
	UniqueIPsLimitEnabled                                  *bool  `json:"unique_ips_limit_enabled"`
	UniqueIPsLimitPerUser                                  *int64 `json:"unique_ips_limit_per_user"`
	UniqueIPsLimitTimeWindow                               *int64 `json:"unique_ips_limit_time_window"`
	DisablePasswordAuthenticationForUsersWithSSOIdentities *bool  `json:"disable_password_authentication_for_users_with_sso_identities"`
	LoginRecaptchaProtectionEnabled                        *bool  `json:"login_recaptcha_protection_enabled"`
	AdminMode                                              *bool  `json:"admin_mode"`
	SessionExpireFromInit                                  *bool  `json:"session_expire_from_init"`
	DeactivateDormantUsers                                 *bool  `json:"deactivate_dormant_users"`
	DeactivateDormantUsersPeriod                           *int64 `json:"deactivate_dormant_users_period"`

	// CI job token scope and package registry exposure
	EnforceCIInboundJobTokenScopeEnabled   *bool `json:"enforce_ci_inbound_job_token_scope_enabled"`
	PackageRegistryAllowAnyoneToPullOption *bool `json:"package_registry_allow_anyone_to_pull_option"`
}

// getInstanceSettings fetches GET /application/settings once and returns both
// views of the same body: the SDK's typed struct for the fields that have been
// reported since well before the versions we support, and the pointer-typed
// overlay for the ones where absent and false are different answers.
func getInstanceSettings(c *gitlab.Client) (*gitlab.Settings, *instanceSettingsPolicy, error) {
	var raw json.RawMessage
	if _, err := getRawJSON(c, "application/settings", nil, &raw); err != nil {
		return nil, nil, err
	}

	settings := &gitlab.Settings{}
	if err := json.Unmarshal(raw, settings); err != nil {
		return nil, nil, err
	}

	policy := &instanceSettingsPolicy{}
	if err := json.Unmarshal(raw, policy); err != nil {
		return nil, nil, err
	}

	return settings, policy, nil
}

// setInstanceSettingsPolicyArgs writes the pointer-typed settings onto the
// resource args. Every value goes through an llx *DataPtr helper, so a setting
// the instance did not report lands as a null field rather than a fabricated
// false or 0.
func setInstanceSettingsPolicyArgs(args map[string]*llx.RawData, p *instanceSettingsPolicy) {
	args["requirePersonalAccessTokenExpiry"] = llx.BoolDataPtr(p.RequirePersonalAccessTokenExpiry)
	args["maxPersonalAccessTokenLifetime"] = llx.IntDataPtr(p.MaxPersonalAccessTokenLifetime)
	args["serviceAccessTokensExpirationEnforced"] = llx.BoolDataPtr(p.ServiceAccessTokensExpirationEnforced)
	args["allowRunnerRegistrationToken"] = llx.BoolDataPtr(p.AllowRunnerRegistrationToken)
	args["runnerTokenExpirationInterval"] = llx.IntDataPtr(p.RunnerTokenExpirationInterval)
	args["groupRunnerTokenExpirationInterval"] = llx.IntDataPtr(p.GroupRunnerTokenExpirationInterval)
	args["projectRunnerTokenExpirationInterval"] = llx.IntDataPtr(p.ProjectRunnerTokenExpirationInterval)

	args["rsaKeyRestriction"] = llx.IntDataPtr(p.RSAKeyRestriction)
	args["dsaKeyRestriction"] = llx.IntDataPtr(p.DSAKeyRestriction)
	args["ecdsaKeyRestriction"] = llx.IntDataPtr(p.ECDSAKeyRestriction)
	args["ecdsaSkKeyRestriction"] = llx.IntDataPtr(p.ECDSASKKeyRestriction)
	args["ed25519KeyRestriction"] = llx.IntDataPtr(p.Ed25519KeyRestriction)
	args["ed25519SkKeyRestriction"] = llx.IntDataPtr(p.Ed25519SKKeyRestriction)

	args["maxLoginAttempts"] = llx.IntDataPtr(p.MaxLoginAttempts)
	args["failedLoginAttemptsUnlockPeriodInMinutes"] = llx.IntDataPtr(p.FailedLoginAttemptsUnlockPeriodInMinutes)
	args["uniqueIpsLimitEnabled"] = llx.BoolDataPtr(p.UniqueIPsLimitEnabled)
	args["uniqueIpsLimitPerUser"] = llx.IntDataPtr(p.UniqueIPsLimitPerUser)
	args["uniqueIpsLimitTimeWindow"] = llx.IntDataPtr(p.UniqueIPsLimitTimeWindow)
	args["disablePasswordAuthenticationForUsersWithSsoIdentities"] = llx.BoolDataPtr(p.DisablePasswordAuthenticationForUsersWithSSOIdentities)
	args["loginRecaptchaProtectionEnabled"] = llx.BoolDataPtr(p.LoginRecaptchaProtectionEnabled)
	args["adminMode"] = llx.BoolDataPtr(p.AdminMode)
	args["sessionExpireFromInit"] = llx.BoolDataPtr(p.SessionExpireFromInit)
	args["deactivateDormantUsers"] = llx.BoolDataPtr(p.DeactivateDormantUsers)
	args["deactivateDormantUsersPeriod"] = llx.IntDataPtr(p.DeactivateDormantUsersPeriod)

	args["enforceCiInboundJobTokenScopeEnabled"] = llx.BoolDataPtr(p.EnforceCIInboundJobTokenScopeEnabled)
	args["packageRegistryAllowAnyoneToPullOption"] = llx.BoolDataPtr(p.PackageRegistryAllowAnyoneToPullOption)
}

//
// Instance-scope CI/CD variables
//

func (v *mqlGitlabSettingsVariable) id() (string, error) {
	return "gitlab.settings.variable/" + v.Key.Data, nil
}

// variables lists the CI/CD variables defined at instance scope. Values are
// never read: masked, protected, and variableType are the auditable surface.
func (s *mqlGitlabSettings) variables() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.GitLabConnection)

	perPage := int64(50)
	page := int64(1)
	var all []*gitlab.InstanceVariable

	for {
		vars, resp, err := conn.Client().InstanceVariables.ListVariables(&gitlab.ListInstanceVariablesOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage},
		})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Err(err).Msg("gitlab> cannot read instance CI/CD variables, reporting null")
				s.Variables.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}

		all = append(all, vars...)

		page = nextPage(resp, page)
		if page == 0 {
			break
		}
	}

	mqlVars := []any{}
	for _, v := range all {
		if v == nil {
			continue
		}
		mqlVar, err := CreateResource(s.MqlRuntime, "gitlab.settings.variable", map[string]*llx.RawData{
			"key":          llx.StringData(v.Key),
			"variableType": llx.StringData(string(v.VariableType)),
			"protected":    llx.BoolData(v.Protected),
			"masked":       llx.BoolData(v.Masked),
			"raw":          llx.BoolData(v.Raw),
			"description":  llx.StringData(v.Description),
		})
		if err != nil {
			return nil, err
		}
		mqlVars = append(mqlVars, mqlVar)
	}

	return mqlVars, nil
}

//
// System hooks
//

func (h *mqlGitlabSettingsSystemHook) id() (string, error) {
	return "gitlab.settings.systemHook/" + strconv.FormatInt(h.Id.Data, 10), nil
}

// systemHooks lists the instance-wide hooks. These fire for events in every
// project and group on the instance, so they sit a tier above the project and
// group webhooks the provider already models.
func (s *mqlGitlabSettings) systemHooks() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.GitLabConnection)

	raw, resp, err := listRawPages(conn.Client(), "hooks", 50)
	if err != nil {
		if isTierOrPermissionGated(resp) {
			log.Debug().Err(err).Msg("gitlab> cannot read system hooks, reporting null")
			s.SystemHooks.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	all, presence, err := decodeHooks[gitlab.Hook](raw)
	if err != nil {
		return nil, err
	}

	mqlHooks := []any{}
	for i, hook := range all {
		urlVariables := map[string]any{}
		for _, v := range hook.URLVariables {
			urlVariables[v.Key] = v.Value
		}

		mqlHook, err := CreateResource(s.MqlRuntime, "gitlab.settings.systemHook", map[string]*llx.RawData{
			"id":                     llx.IntData(hook.ID),
			"url":                    llx.StringData(hook.URL),
			"name":                   llx.StringData(hook.Name),
			"description":            llx.StringData(hook.Description),
			"sslVerification":        llx.BoolData(hook.EnableSSLVerification),
			"pushEvents":             llx.BoolData(hook.PushEvents),
			"tagPushEvents":          llx.BoolData(hook.TagPushEvents),
			"mergeRequestsEvents":    llx.BoolData(hook.MergeRequestsEvents),
			"repositoryUpdateEvents": llx.BoolDataPtr(presence[i].RepositoryUpdateEvents),
			"tokenPresent":           llx.BoolDataPtr(presence[i].TokenPresent),
			"urlVariables":           llx.MapData(urlVariables, types.String),
			"createdAt":              llx.TimeDataPtr(hook.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		mqlHooks = append(mqlHooks, mqlHook)
	}

	return mqlHooks, nil
}

//
// OAuth applications
//

func (a *mqlGitlabSettingsApplication) id() (string, error) {
	return "gitlab.settings.application/" + strconv.FormatInt(a.Id.Data, 10), nil
}

// splitRedirectURIs turns the newline-separated callback configuration GitLab
// reports into one entry per redirect URI, dropping blank lines and stray
// whitespace. An application with no callback configured yields an empty list.
func splitRedirectURIs(callbackURL string) []any {
	out := []any{}
	for _, line := range strings.FieldsFunc(callbackURL, func(r rune) bool { return r == '\n' || r == '\r' }) {
		uri := strings.TrimSpace(line)
		if uri == "" {
			continue
		}
		out = append(out, uri)
	}
	return out
}

// applications lists the OAuth applications registered on the instance. The
// client secret is deliberately not modeled: it is a live credential, and the
// posture question is whether the application is confidential and where it may
// send an authorization code.
func (s *mqlGitlabSettings) applications() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.GitLabConnection)

	perPage := int64(50)
	page := int64(1)
	var all []*gitlab.Application

	for {
		apps, resp, err := conn.Client().Applications.ListApplications(&gitlab.ListApplicationsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage},
		})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Err(err).Msg("gitlab> cannot read OAuth applications, reporting null")
				s.Applications.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}

		all = append(all, apps...)

		page = nextPage(resp, page)
		if page == 0 {
			break
		}
	}

	mqlApps := []any{}
	for _, app := range all {
		if app == nil {
			continue
		}

		// GitLab has not always returned scopes when listing applications, and
		// an empty scope set is not a thing an OAuth application can have. Null
		// says the instance did not tell us; a list says these are the scopes.
		scopes := llx.NilData
		if app.Scopes != nil {
			entries := make([]any, 0, len(app.Scopes))
			for _, scope := range app.Scopes {
				entries = append(entries, scope)
			}
			scopes = llx.ArrayData(entries, types.String)
		}

		mqlApp, err := CreateResource(s.MqlRuntime, "gitlab.settings.application", map[string]*llx.RawData{
			"id":           llx.IntData(app.ID),
			"clientId":     llx.StringData(app.ApplicationID),
			"name":         llx.StringData(app.ApplicationName),
			"confidential": llx.BoolData(app.Confidential),
			"redirectUris": llx.ArrayData(splitRedirectURIs(app.CallbackURL), types.String),
			"scopes":       scopes,
		})
		if err != nil {
			return nil, err
		}
		mqlApps = append(mqlApps, mqlApp)
	}

	return mqlApps, nil
}

//
// Instance version and edition
//

// initGitlabMetadata reads the version and edition of the instance under scan.
// Unlike gitlab.settings this needs no administrator rights, which is the point
// of keeping it a separate resource: a scan that cannot read the application
// settings can still tell whether an empty Ultimate-only collection means the
// instance is clean or unlicensed.
func initGitlabMetadata(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Singleton with no lookup key, so the only reason to skip the fetch is a
	// caller that already handed us the full field set. The threshold allows
	// for the implicit __id arg, matching the other inits in this provider.
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GitLabConnection)
	metadata, _, err := conn.Client().Metadata.GetMetadata()
	if err != nil {
		return nil, nil, err
	}

	args["version"] = llx.StringData(metadata.Version)
	args["revision"] = llx.StringData(metadata.Revision)
	args["enterprise"] = llx.BoolData(metadata.Enterprise)

	return args, nil, nil
}

func (m *mqlGitlabMetadata) id() (string, error) {
	return "gitlab.metadata", nil
}
