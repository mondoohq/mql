// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"
)

// initGitlabSettings fetches instance-level application settings.
// Requires an admin-scoped token; returns a permission error otherwise.
func initGitlabSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// gitlab.settings is a singleton with no lookup key, so the only reason to
	// skip the fetch is that a caller already handed us the full field set.
	// The threshold has to allow for the implicit __id arg — every other init
	// in this provider uses > 2 for the same reason. At > 0 a single incidental
	// arg skipped the fetch entirely and left all 33 fields unset.
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GitLabConnection)
	settings, policy, err := getInstanceSettings(conn.Client())
	if err != nil {
		return nil, nil, err
	}

	args["id"] = llx.IntData(settings.ID)
	args["updatedAt"] = llx.TimeDataPtr(settings.UpdatedAt)
	args["requireTwoFactorAuthentication"] = llx.BoolData(settings.RequireTwoFactorAuthentication)
	args["twoFactorGracePeriod"] = llx.IntData(settings.TwoFactorGracePeriod)
	args["requireAdminTwoFactorAuthentication"] = llx.BoolData(settings.RequireAdminTwoFactorAuthentication)
	args["gitTwoFactorSessionExpiry"] = llx.IntData(settings.GitTwoFactorSessionExpiry)
	args["passwordAuthenticationEnabledForWeb"] = llx.BoolData(settings.PasswordAuthenticationEnabledForWeb)
	args["passwordAuthenticationEnabledForGit"] = llx.BoolData(settings.PasswordAuthenticationEnabledForGit)
	args["signupEnabled"] = llx.BoolData(settings.SignupEnabled)
	args["defaultProjectVisibility"] = llx.StringData(string(settings.DefaultProjectVisibility))
	args["defaultGroupVisibility"] = llx.StringData(string(settings.DefaultGroupVisibility))
	args["minimumPasswordLength"] = llx.IntData(settings.MinimumPasswordLength)
	args["passwordNumberRequired"] = llx.BoolData(settings.PasswordNumberRequired)
	args["passwordSymbolRequired"] = llx.BoolData(settings.PasswordSymbolRequired)
	args["passwordUppercaseRequired"] = llx.BoolData(settings.PasswordUppercaseRequired)
	args["passwordLowercaseRequired"] = llx.BoolData(settings.PasswordLowercaseRequired)
	args["enforcePatExpiration"] = llx.BoolData(settings.EnforcePATExpiration)
	args["enforceSshKeyExpiration"] = llx.BoolData(settings.EnforceSSHKeyExpiration)
	args["requireAdminApprovalAfterUserSignup"] = llx.BoolData(settings.RequireAdminApprovalAfterUserSignup)
	args["domainAllowlist"] = llx.ArrayData(convert.SliceAnyToInterface(settings.DomainAllowlist), types.String)
	args["domainDenylistEnabled"] = llx.BoolData(settings.DomainDenylistEnabled)
	args["domainDenylist"] = llx.ArrayData(convert.SliceAnyToInterface(settings.DomainDenylist), types.String)
	args["disabledOauthSignInSources"] = llx.ArrayData(convert.SliceAnyToInterface(settings.DisabledOauthSignInSources), types.String)
	args["notifyOnUnknownSignIn"] = llx.BoolData(settings.NotifyOnUnknownSignIn)
	args["externalAuthorizationServiceEnabled"] = llx.BoolData(settings.ExternalAuthorizationServiceEnabled)
	args["allowLocalRequestsFromWebHooksAndServices"] = llx.BoolData(settings.AllowLocalRequestsFromWebHooksAndServices)
	args["allowLocalRequestsFromSystemHooks"] = llx.BoolData(settings.AllowLocalRequestsFromSystemHooks)
	args["protectedCiVariables"] = llx.BoolData(settings.ProtectedCIVariables)
	args["importSources"] = llx.ArrayData(convert.SliceAnyToInterface(settings.ImportSources), types.String)
	args["sessionExpireDelay"] = llx.IntData(settings.SessionExpireDelay)
	args["terminalMaxSessionTime"] = llx.IntData(settings.TerminalMaxSessionTime)
	args["duoFeaturesEnabled"] = llx.BoolData(settings.DuoFeaturesEnabled)
	args["lockDuoFeaturesEnabled"] = llx.BoolData(settings.LockDuoFeaturesEnabled)

	// The credential-lifecycle, sign-in hardening and CI job-token settings are
	// read from the same response through a pointer-typed view, so a release
	// that predates one of them reports null rather than claiming it is off.
	setInstanceSettingsPolicyArgs(args, policy)

	return args, nil, nil
}

func (s *mqlGitlabSettings) id() (string, error) {
	return "gitlab.settings", nil
}
