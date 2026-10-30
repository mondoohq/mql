// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

type mqlMicrosoftAuthenticationMethodsPolicyInternal struct {
	cachePolicy models.AuthenticationMethodsPolicyable
}

// initMicrosoftAuthenticationMethodsPolicy populates the policy when it is
// queried directly (microsoft.authenticationMethodsPolicy) rather than through
// microsoft.policies.authenticationMethodsPolicy. Without this, a direct query
// returns a bare resource whose cachePolicy is nil, so every per-method
// accessor (fido2, microsoftAuthenticator, ...) resolves to null. We delegate
// to the policies accessor, which fetches the policy and caches it.
func initMicrosoftAuthenticationMethodsPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	policiesResource, err := CreateResource(runtime, ResourceMicrosoftPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	policy, err := policiesResource.(*mqlMicrosoftPolicies).authenticationMethodsPolicy()
	if err != nil {
		return nil, nil, err
	}

	return nil, policy, nil
}

// authMethodTargets renders the include/exclude target lists of an
// authentication method (or the registration campaign) as dictionaries. Every
// target type shares the id and targetType accessors.
func authMethodTargets[T interface {
	GetId() *string
	GetTargetType() *models.AuthenticationMethodTargetType
}](targets []T) []any {
	res := []any{}
	for _, t := range targets {
		d := map[string]any{}
		if t.GetId() != nil {
			d["id"] = *t.GetId()
		}
		if tt := t.GetTargetType(); tt != nil {
			d["targetType"] = tt.String()
		}
		res = append(res, d)
	}
	return res
}

// findAuthMethodConfig returns the first method configuration of type C from the
// cached policy, or false if the policy did not include it.
func findAuthMethodConfig[C models.AuthenticationMethodConfigurationable](a *mqlMicrosoftAuthenticationMethodsPolicy) (C, bool) {
	var zero C
	if a.cachePolicy == nil {
		return zero, false
	}
	for _, cfg := range a.cachePolicy.GetAuthenticationMethodConfigurations() {
		if c, ok := cfg.(C); ok {
			return c, true
		}
	}
	return zero, false
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) fido2() (*mqlMicrosoftAuthenticationMethodsPolicyFido2, error) {
	cfg, ok := findAuthMethodConfig[models.Fido2AuthenticationMethodConfigurationable](a)
	if !ok {
		a.Fido2.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	var keyRestrictionsEnforced *bool
	var enforcementType *string
	aaGuids := []any{}
	if kr := cfg.GetKeyRestrictions(); kr != nil {
		keyRestrictionsEnforced = kr.GetIsEnforced()
		enforcementType = enumPtrString(kr.GetEnforcementType())
		for _, g := range kr.GetAaGuids() {
			aaGuids = append(aaGuids, g)
		}
	}

	res, err := CreateResource(a.MqlRuntime, "microsoft.authenticationMethodsPolicy.fido2",
		map[string]*llx.RawData{
			"__id":                             llx.StringData(a.Id.Data + "/fido2"),
			"state":                            llx.StringDataPtr(enumPtrString(cfg.GetState())),
			"includeTargets":                   llx.ArrayData(authMethodTargets(cfg.GetIncludeTargets()), types.Dict),
			"excludeTargets":                   llx.ArrayData(authMethodTargets(cfg.GetExcludeTargets()), types.Dict),
			"isAttestationEnforced":            llx.BoolDataPtr(cfg.GetIsAttestationEnforced()),
			"isSelfServiceRegistrationAllowed": llx.BoolDataPtr(cfg.GetIsSelfServiceRegistrationAllowed()),
			"keyRestrictionsEnforced":          llx.BoolDataPtr(keyRestrictionsEnforced),
			"keyRestrictionsEnforcementType":   llx.StringDataPtr(enforcementType),
			"keyRestrictionsAaGuids":           llx.ArrayData(aaGuids, types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyFido2), nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) microsoftAuthenticator() (*mqlMicrosoftAuthenticationMethodsPolicyMicrosoftAuthenticator, error) {
	cfg, ok := findAuthMethodConfig[models.MicrosoftAuthenticatorAuthenticationMethodConfigurationable](a)
	if !ok {
		a.MicrosoftAuthenticator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	var displayApp, displayLocation *string
	if fs := cfg.GetFeatureSettings(); fs != nil {
		if c := fs.GetDisplayAppInformationRequiredState(); c != nil {
			displayApp = enumPtrString(c.GetState())
		}
		if c := fs.GetDisplayLocationInformationRequiredState(); c != nil {
			displayLocation = enumPtrString(c.GetState())
		}
	}

	res, err := CreateResource(a.MqlRuntime, "microsoft.authenticationMethodsPolicy.microsoftAuthenticator",
		map[string]*llx.RawData{
			"__id":                               llx.StringData(a.Id.Data + "/microsoftAuthenticator"),
			"state":                              llx.StringDataPtr(enumPtrString(cfg.GetState())),
			"includeTargets":                     llx.ArrayData(authMethodTargets(cfg.GetIncludeTargets()), types.Dict),
			"excludeTargets":                     llx.ArrayData(authMethodTargets(cfg.GetExcludeTargets()), types.Dict),
			"isSoftwareOathEnabled":              llx.BoolDataPtr(cfg.GetIsSoftwareOathEnabled()),
			"displayAppInformationRequiredState": llx.StringDataPtr(displayApp),
			"displayLocationInformationRequiredState": llx.StringDataPtr(displayLocation),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyMicrosoftAuthenticator), nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) temporaryAccessPass() (*mqlMicrosoftAuthenticationMethodsPolicyTemporaryAccessPass, error) {
	cfg, ok := findAuthMethodConfig[models.TemporaryAccessPassAuthenticationMethodConfigurationable](a)
	if !ok {
		a.TemporaryAccessPass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(a.MqlRuntime, "microsoft.authenticationMethodsPolicy.temporaryAccessPass",
		map[string]*llx.RawData{
			"__id":                     llx.StringData(a.Id.Data + "/temporaryAccessPass"),
			"state":                    llx.StringDataPtr(enumPtrString(cfg.GetState())),
			"includeTargets":           llx.ArrayData(authMethodTargets(cfg.GetIncludeTargets()), types.Dict),
			"excludeTargets":           llx.ArrayData(authMethodTargets(cfg.GetExcludeTargets()), types.Dict),
			"defaultLifetimeInMinutes": llx.IntDataPtr(cfg.GetDefaultLifetimeInMinutes()),
			"defaultLength":            llx.IntDataPtr(cfg.GetDefaultLength()),
			"minimumLifetimeInMinutes": llx.IntDataPtr(cfg.GetMinimumLifetimeInMinutes()),
			"maximumLifetimeInMinutes": llx.IntDataPtr(cfg.GetMaximumLifetimeInMinutes()),
			"isUsableOnce":             llx.BoolDataPtr(cfg.GetIsUsableOnce()),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyTemporaryAccessPass), nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) email() (*mqlMicrosoftAuthenticationMethodsPolicyEmail, error) {
	cfg, ok := findAuthMethodConfig[models.EmailAuthenticationMethodConfigurationable](a)
	if !ok {
		a.Email.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(a.MqlRuntime, "microsoft.authenticationMethodsPolicy.email",
		map[string]*llx.RawData{
			"__id":                         llx.StringData(a.Id.Data + "/email"),
			"state":                        llx.StringDataPtr(enumPtrString(cfg.GetState())),
			"includeTargets":               llx.ArrayData(authMethodTargets(cfg.GetIncludeTargets()), types.Dict),
			"excludeTargets":               llx.ArrayData(authMethodTargets(cfg.GetExcludeTargets()), types.Dict),
			"allowExternalIdToUseEmailOtp": llx.StringDataPtr(enumPtrString(cfg.GetAllowExternalIdToUseEmailOtp())),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyEmail), nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) voice() (*mqlMicrosoftAuthenticationMethodsPolicyVoice, error) {
	cfg, ok := findAuthMethodConfig[models.VoiceAuthenticationMethodConfigurationable](a)
	if !ok {
		a.Voice.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(a.MqlRuntime, "microsoft.authenticationMethodsPolicy.voice",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(a.Id.Data + "/voice"),
			"state":                llx.StringDataPtr(enumPtrString(cfg.GetState())),
			"includeTargets":       llx.ArrayData(authMethodTargets(cfg.GetIncludeTargets()), types.Dict),
			"excludeTargets":       llx.ArrayData(authMethodTargets(cfg.GetExcludeTargets()), types.Dict),
			"isOfficePhoneAllowed": llx.BoolDataPtr(cfg.GetIsOfficePhoneAllowed()),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyVoice), nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) registrationCampaign() (*mqlMicrosoftAuthenticationMethodsPolicyRegistrationCampaign, error) {
	if a.cachePolicy == nil {
		a.RegistrationCampaign.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	enforcement := a.cachePolicy.GetRegistrationEnforcement()
	if enforcement == nil {
		a.RegistrationCampaign.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	campaign := enforcement.GetAuthenticationMethodsRegistrationCampaign()
	if campaign == nil {
		a.RegistrationCampaign.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(a.MqlRuntime, "microsoft.authenticationMethodsPolicy.registrationCampaign",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(a.Id.Data + "/registrationCampaign"),
			"state":                llx.StringDataPtr(enumPtrString(campaign.GetState())),
			"snoozeDurationInDays": llx.IntDataPtr(campaign.GetSnoozeDurationInDays()),
			"includeTargets":       llx.ArrayData(authMethodTargets(campaign.GetIncludeTargets()), types.Dict),
			"excludeTargets":       llx.ArrayData(authMethodTargets(campaign.GetExcludeTargets()), types.Dict),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyRegistrationCampaign), nil
}

// --- Microsoft Authenticator feature settings ---
//
// companionAppAllowedState and numberMatchingRequiredState exist only on the
// beta authenticationMethodsPolicy; the v1.0 featureSettings object carries
// just the two display-state fields the parent resource already reports. The
// beta policy is therefore fetched on demand, and only once per resource,
// rather than making every scan pay for a second policy read.

type mqlMicrosoftAuthenticationMethodsPolicyMicrosoftAuthenticatorInternal struct {
	betaLock sync.Mutex
	fetched  bool
	betaCfg  betamodels.MicrosoftAuthenticatorAuthenticationMethodConfigurationable
	fetchErr error
}

func (a *mqlMicrosoftAuthenticationMethodsPolicyMicrosoftAuthenticator) betaConfig() (betamodels.MicrosoftAuthenticatorAuthenticationMethodConfigurationable, error) {
	a.betaLock.Lock()
	defer a.betaLock.Unlock()
	if a.fetched {
		return a.betaCfg, a.fetchErr
	}
	a.fetched = true

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		a.fetchErr = err
		return nil, err
	}

	policy, err := betaClient.Policies().AuthenticationMethodsPolicy().Get(context.Background(), nil)
	if err != nil {
		a.fetchErr = transformError(err)
		return nil, a.fetchErr
	}
	if policy == nil {
		return nil, nil
	}

	for _, cfg := range policy.GetAuthenticationMethodConfigurations() {
		if c, ok := cfg.(betamodels.MicrosoftAuthenticatorAuthenticationMethodConfigurationable); ok {
			a.betaCfg = c
			break
		}
	}
	return a.betaCfg, nil
}

// authMethodFeatureConfiguration renders one feature toggle of an
// authentication method.
func authMethodFeatureConfiguration(runtime *plugin.Runtime, id string, cfg betamodels.AuthenticationMethodFeatureConfigurationable) (*mqlMicrosoftAuthenticationMethodsPolicyFeatureConfiguration, error) {
	if cfg == nil {
		return nil, nil
	}

	featureTarget := func(t betamodels.FeatureTargetable) any {
		if t == nil {
			return nil
		}
		d := map[string]any{}
		if id := t.GetId(); id != nil {
			d["id"] = *id
		}
		if tt := t.GetTargetType(); tt != nil {
			d["targetType"] = tt.String()
		}
		return d
	}

	res, err := CreateResource(runtime, ResourceMicrosoftAuthenticationMethodsPolicyFeatureConfiguration,
		map[string]*llx.RawData{
			"__id":          llx.StringData(id),
			"state":         llx.StringDataPtr(enumPtrString(cfg.GetState())),
			"includeTarget": llx.DictData(featureTarget(cfg.GetIncludeTarget())),
			"excludeTarget": llx.DictData(featureTarget(cfg.GetExcludeTarget())),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftAuthenticationMethodsPolicyFeatureConfiguration), nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicyMicrosoftAuthenticator) featureSettings() (*mqlMicrosoftAuthenticationMethodsPolicyAuthenticatorFeatureSettings, error) {
	nullResult := func() (*mqlMicrosoftAuthenticationMethodsPolicyAuthenticatorFeatureSettings, error) {
		a.FeatureSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cfg, err := a.betaConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nullResult()
	}
	fs := cfg.GetFeatureSettings()
	if fs == nil {
		return nullResult()
	}

	base := a.__id + "/featureSettings"
	args := map[string]*llx.RawData{"__id": llx.StringData(base)}
	missing := map[string]bool{}
	for name, c := range map[string]betamodels.AuthenticationMethodFeatureConfigurationable{
		"companionAppAllowedState":                fs.GetCompanionAppAllowedState(),
		"displayAppInformationRequiredState":      fs.GetDisplayAppInformationRequiredState(),
		"displayLocationInformationRequiredState": fs.GetDisplayLocationInformationRequiredState(),
		"numberMatchingRequiredState":             fs.GetNumberMatchingRequiredState(),
	} {
		mql, err := authMethodFeatureConfiguration(a.MqlRuntime, base+"/"+name, c)
		if err != nil {
			return nil, err
		}
		args[name] = llx.ResourceData(mql, ResourceMicrosoftAuthenticationMethodsPolicyFeatureConfiguration)
		if mql == nil {
			missing[name] = true
		}
	}

	res, err := CreateResource(a.MqlRuntime, ResourceMicrosoftAuthenticationMethodsPolicyAuthenticatorFeatureSettings, args)
	if err != nil {
		return nil, err
	}

	// a feature the tenant has never configured is absent from the response
	// rather than reported as "default", so it is null and not a state
	mql := res.(*mqlMicrosoftAuthenticationMethodsPolicyAuthenticatorFeatureSettings)
	if missing["companionAppAllowedState"] {
		mql.CompanionAppAllowedState.State = plugin.StateIsSet | plugin.StateIsNull
	}
	if missing["displayAppInformationRequiredState"] {
		mql.DisplayAppInformationRequiredState.State = plugin.StateIsSet | plugin.StateIsNull
	}
	if missing["displayLocationInformationRequiredState"] {
		mql.DisplayLocationInformationRequiredState.State = plugin.StateIsSet | plugin.StateIsNull
	}
	if missing["numberMatchingRequiredState"] {
		mql.NumberMatchingRequiredState.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return mql, nil
}
