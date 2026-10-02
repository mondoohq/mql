// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/policies"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlMicrosoftPolicies) authorizationPolicy() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Policies().AuthorizationPolicy().Get(ctx, &policies.AuthorizationPolicyRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}

	return convert.JsonToDict(newAuthorizationPolicy(resp))
}

func (a *mqlMicrosoftPolicies) identitySecurityDefaultsEnforcementPolicy() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	policy, err := graphClient.Policies().IdentitySecurityDefaultsEnforcementPolicy().Get(ctx, &policies.IdentitySecurityDefaultsEnforcementPolicyRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}

	return convert.JsonToDict(newIdentitySecurityDefaultsEnforcementPolicy(policy))
}

// https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-powershell
// https://learn.microsoft.com/en-us/graph/api/permissiongrantpolicy-list?view=graph-rest-1.0&tabs=http
func (a *mqlMicrosoftPolicies) permissionGrantPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().PermissionGrantPolicies().Get(ctx, &policies.PermissionGrantPoliciesRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	grantPolicies, err := iterate[models.PermissionGrantPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreatePermissionGrantPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(newPermissionGrantPolicies(grantPolicies))
}

// https://learn.microsoft.com/en-us/graph/api/groupsetting-get?view=graph-rest-1.0&tabs=http

func (a *mqlMicrosoftPolicies) consentPolicySettings() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	resp, err := graphClient.GroupSettings().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	groupSettings, err := iterate[models.GroupSettingable](ctx, resp, graphClient.GetAdapter(), models.CreateGroupSettingCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	actualSettingsMap := make(map[string]map[string]any)
	for _, setting := range groupSettings {
		displayName := setting.GetDisplayName()
		if displayName != nil {
			if _, exists := actualSettingsMap[*displayName]; !exists {
				actualSettingsMap[*displayName] = make(map[string]any)
			}

			for _, settingValue := range setting.GetValues() {
				name := settingValue.GetName()
				value := settingValue.GetValue()
				if name != nil && value != nil {
					actualSettingsMap[*displayName][*name] = *value
				}
			}
		}
	}

	return convert.JsonToDict(actualSettingsMap)
}

func (a *mqlMicrosoftPolicies) authenticationMethodsPolicy() (*mqlMicrosoftAuthenticationMethodsPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	resp, err := fetchAuthenticationMethodsPolicy(context.Background(), graphClient)
	if err != nil {
		return nil, err
	}

	return newAuthenticationMethodsPolicy(a.MqlRuntime, resp)
}

// fetchAuthenticationMethodsPolicy reads the policy with a plain GET. Graph
// returns authenticationMethodConfigurations inline, each with its
// includeTargets. Adding $expand=authenticationMethodConfigurations makes
// Graph drop includeTargets (a navigation property) from every configuration,
// so every method would report no included users or groups.
func fetchAuthenticationMethodsPolicy(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient) (models.AuthenticationMethodsPolicyable, error) {
	resp, err := graphClient.Policies().AuthenticationMethodsPolicy().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	return resp, nil
}

func (a *mqlMicrosoftPolicies) activityBasedTimeoutPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().ActivityBasedTimeoutPolicies().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	timeoutPolicies, err := iterate[models.ActivityBasedTimeoutPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateActivityBasedTimeoutPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var activityBasedTimeoutPolicies []any
	for _, policy := range timeoutPolicies {
		mqlPolicy, err := CreateResource(a.MqlRuntime, "microsoft.policies.activityBasedTimeoutPolicy",
			map[string]*llx.RawData{
				"__id":                  llx.StringDataPtr(policy.GetId()),
				"id":                    llx.StringDataPtr(policy.GetId()),
				"definition":            llx.ArrayData(convert.SliceAnyToInterface(policy.GetDefinition()), types.String),
				"displayName":           llx.StringDataPtr(policy.GetDisplayName()),
				"isOrganizationDefault": llx.BoolDataPtr(policy.GetIsOrganizationDefault()),
			})
		if err != nil {
			return nil, err
		}
		activityBasedTimeoutPolicies = append(activityBasedTimeoutPolicies, mqlPolicy)
	}

	return activityBasedTimeoutPolicies, nil
}

func newAuthenticationMethodsPolicy(runtime *plugin.Runtime, policy models.AuthenticationMethodsPolicyable) (*mqlMicrosoftAuthenticationMethodsPolicy, error) {
	authMethodConfigs, err := newAuthenticationMethodConfigurations(runtime, policy.GetAuthenticationMethodConfigurations())
	if err != nil {
		return nil, err
	}

	mqlAuthenticationMethodsPolicy, err := CreateResource(runtime, ResourceMicrosoftAuthenticationMethodsPolicy,
		map[string]*llx.RawData{
			"__id":                               llx.StringDataPtr(policy.GetId()),
			"id":                                 llx.StringDataPtr(policy.GetId()),
			"description":                        llx.StringDataPtr(policy.GetDescription()),
			"displayName":                        llx.StringDataPtr(policy.GetDisplayName()),
			"lastModifiedDateTime":               graphTimeData(policy.GetLastModifiedDateTime()),
			"policyVersion":                      llx.StringDataPtr(policy.GetPolicyVersion()),
			"authenticationMethodConfigurations": llx.ArrayData(authMethodConfigs, types.Resource(string(ResourceMicrosoftAuthenticationMethodConfiguration))),
		})
	if err != nil {
		return nil, err
	}

	mqlPolicy := mqlAuthenticationMethodsPolicy.(*mqlMicrosoftAuthenticationMethodsPolicy)
	// cache the raw policy so the per-method accessors can resolve the
	// method-specific configuration without a second Graph call
	mqlPolicy.cachePolicy = policy
	return mqlPolicy, nil
}

func newAuthenticationMethodConfigurations(runtime *plugin.Runtime, configs []models.AuthenticationMethodConfigurationable) ([]any, error) {
	var configResources []any
	for _, config := range configs {
		excludeTargets := []any{}
		for _, target := range config.GetExcludeTargets() {
			targetDict := map[string]any{}
			if target.GetId() != nil {
				targetDict["id"] = *target.GetId()
			}
			if target.GetTargetType() != nil {
				targetDict["targetType"] = target.GetTargetType().String()
			}
			excludeTargets = append(excludeTargets, targetDict)
		}

		state := ""
		if config.GetState() != nil {
			state = config.GetState().String()
		}

		configData := map[string]*llx.RawData{
			"__id":           llx.StringDataPtr(config.GetId()),
			"id":             llx.StringDataPtr(config.GetId()),
			"state":          llx.StringData(state),
			"excludeTargets": llx.ArrayData(excludeTargets, types.Dict),
		}

		mqlConfig, err := CreateResource(runtime, ResourceMicrosoftAuthenticationMethodConfiguration, configData)
		if err != nil {
			return nil, err
		}

		configResources = append(configResources, mqlConfig)
	}

	return configResources, nil
}

func (a *mqlMicrosoftAuthenticationMethodsPolicy) systemCredentialPreferences() (*mqlMicrosoftSystemCredentialPreferences, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	betaGraphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policy, err := betaGraphClient.Policies().AuthenticationMethodsPolicy().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}

	systemCredPrefs := policy.GetSystemCredentialPreferences()
	if systemCredPrefs == nil {
		return nil, nil
	}

	// Convert include targets to []dict
	var includeTargets []any
	for _, target := range systemCredPrefs.GetIncludeTargets() {
		targetDict := map[string]any{}
		if target.GetId() != nil {
			targetDict["id"] = *target.GetId()
		}
		if target.GetTargetType() != nil {
			targetDict["targetType"] = target.GetTargetType().String()
		}
		includeTargets = append(includeTargets, targetDict)
	}

	// Convert exclude targets to []dict
	var excludeTargets []any
	for _, target := range systemCredPrefs.GetExcludeTargets() {
		targetDict := map[string]any{}
		if target.GetId() != nil {
			targetDict["id"] = *target.GetId()
		}
		if target.GetTargetType() != nil {
			targetDict["targetType"] = target.GetTargetType().String()
		}
		excludeTargets = append(excludeTargets, targetDict)
	}

	state := ""
	if systemCredPrefs.GetState() != nil {
		state = systemCredPrefs.GetState().String()
	}

	policyId := a.Id.Data

	mqlSystemCredPrefs, err := CreateResource(a.MqlRuntime, ResourceMicrosoftSystemCredentialPreferences,
		map[string]*llx.RawData{
			"__id":           llx.StringData(policyId + "/systemCredentialPreferences"),
			"state":          llx.StringData(state),
			"includeTargets": llx.ArrayData(includeTargets, types.Dict),
			"excludeTargets": llx.ArrayData(excludeTargets, types.Dict),
		})
	if err != nil {
		return nil, err
	}

	return mqlSystemCredPrefs.(*mqlMicrosoftSystemCredentialPreferences), nil
}

// https://learn.microsoft.com/en-us/graph/api/adminconsentrequestpolicy-get?view=graph-rest-1.0
func (a *mqlMicrosoftPolicies) adminConsentRequestPolicy() (*mqlMicrosoftAdminConsentRequestPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	adminConsentRequestPolicy, err := graphClient.Policies().AdminConsentRequestPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}

	if adminConsentRequestPolicy == nil {
		return nil, nil
	}

	pId := uuid.NewString()

	var reviewers []any
	if adminConsentRequestPolicy.GetReviewers() != nil {
		for i, reviewer := range adminConsentRequestPolicy.GetReviewers() {
			revId := fmt.Sprintf("%s-reviewer-scope-%d", pId, i)
			resource, err := CreateResource(a.MqlRuntime, "microsoft.graph.accessReviewReviewerScope",
				map[string]*llx.RawData{
					"__id":      llx.StringData(revId),
					"query":     llx.StringDataPtr(reviewer.GetQuery()),
					"queryRoot": llx.StringDataPtr(reviewer.GetQueryRoot()),
					"queryType": llx.StringDataPtr(reviewer.GetQueryType()),
				})
			if err != nil {
				return nil, err
			}

			reviewers = append(reviewers, resource)
		}
	}

	data := map[string]*llx.RawData{
		"__id":                  llx.StringData(pId),
		"reviewers":             llx.ArrayData(reviewers, "microsoft.graph.accessReviewReviewerScope"),
		"isEnabled":             llx.BoolDataPtr(adminConsentRequestPolicy.GetIsEnabled()),
		"notifyReviewers":       llx.BoolDataPtr(adminConsentRequestPolicy.GetNotifyReviewers()),
		"remindersEnabled":      llx.BoolDataPtr(adminConsentRequestPolicy.GetRemindersEnabled()),
		"requestDurationInDays": llx.IntDataPtr(adminConsentRequestPolicy.GetRequestDurationInDays()),
		"version":               llx.IntDataPtr(adminConsentRequestPolicy.GetVersion()),
	}

	resource, err := CreateResource(a.MqlRuntime, "microsoft.adminConsentRequestPolicy", data)
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftAdminConsentRequestPolicy), nil
}

func (a *mqlMicrosoftPolicies) externalIdentitiesPolicy() (*mqlMicrosoftExternalIdentitiesPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	betaGraphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	policy, err := betaGraphClient.Policies().ExternalIdentitiesPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}
	if policy == nil {
		return nil, fmt.Errorf("external identities policy not found")
	}

	mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceMicrosoftExternalIdentitiesPolicy,
		map[string]*llx.RawData{
			"__id":                           llx.StringDataPtr(policy.GetId()),
			"id":                             llx.StringDataPtr(policy.GetId()),
			"displayName":                    llx.StringDataPtr(policy.GetDisplayName()),
			"description":                    llx.StringDataPtr(policy.GetDescription()),
			"allowExternalIdentitiesToLeave": llx.BoolDataPtr(policy.GetAllowExternalIdentitiesToLeave()),
		})
	if err != nil {
		return nil, err
	}

	return mqlPolicy.(*mqlMicrosoftExternalIdentitiesPolicy), nil
}

// deviceRegistrationMembershipScope reads the scope out of one
// deviceRegistrationMembership: who it applies to, and the users and groups it
// names when it applies to a chosen set.
//
// The variant carries the meaning, and the concrete type is what identifies it,
// because the sibling interfaces add no methods over the shared base and so
// every variant satisfies all of them. A variant Graph adds later deserializes
// to the base type; that yields an empty scope, which the caller reports as
// null rather than inventing one.
func deviceRegistrationMembershipScope(m models.DeviceRegistrationMembershipable) (string, []any, []any) {
	users := []any{}
	groups := []any{}

	switch v := m.(type) {
	case *models.AllDeviceRegistrationMembership:
		return "all", users, groups
	case *models.NoDeviceRegistrationMembership:
		return "none", users, groups
	case *models.EnumeratedDeviceRegistrationMembership:
		for _, u := range v.GetUsers() {
			users = append(users, u)
		}
		for _, g := range v.GetGroups() {
			groups = append(groups, g)
		}
		return "selected", users, groups
	}
	log.Warn().
		Str("odataType", convert.ToValue(m.GetOdataType())).
		Msg("unrecognized device registration membership, reporting its scope as null")
	return "", users, groups
}

// deviceRegistrationMembership renders one deviceRegistrationMembership as a
// resource. The Graph type is a union whose variant carries the meaning: the
// membership either applies to everyone, to nobody, or to an enumerated set of
// users and groups. The concrete type is what identifies the variant, because
// the sibling interfaces add no methods over the shared base and so every
// variant satisfies all of them.
func deviceRegistrationMembership(runtime *plugin.Runtime, id string, m models.DeviceRegistrationMembershipable) (*mqlMicrosoftDeviceRegistrationPolicyMembership, error) {
	if m == nil {
		return nil, nil
	}

	appliesTo, users, groups := deviceRegistrationMembershipScope(m)

	args := map[string]*llx.RawData{
		"__id":          llx.StringData(id),
		"allowedUsers":  llx.ArrayData(users, types.String),
		"allowedGroups": llx.ArrayData(groups, types.String),
	}
	// a variant Graph adds later deserializes to the base type, which carries no
	// scope of its own; reporting null says that rather than inventing one
	if appliesTo == "" {
		args["appliesTo"] = llx.NilData
	} else {
		args["appliesTo"] = llx.StringData(appliesTo)
	}

	res, err := CreateResource(runtime, ResourceMicrosoftDeviceRegistrationPolicyMembership, args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftDeviceRegistrationPolicyMembership), nil
}

// deviceRegistrationLocalAdmins renders who becomes a local administrator on a
// device joined to Microsoft Entra.
func deviceRegistrationLocalAdmins(runtime *plugin.Runtime, id string, s models.LocalAdminSettingsable) (*mqlMicrosoftDeviceRegistrationPolicyLocalAdminSettings, error) {
	if s == nil {
		return nil, nil
	}

	registeringUsers, err := deviceRegistrationMembership(runtime, id+"/registeringUsers", s.GetRegisteringUsers())
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, ResourceMicrosoftDeviceRegistrationPolicyLocalAdminSettings,
		map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"enableGlobalAdmins": llx.BoolDataPtr(s.GetEnableGlobalAdmins()),
			"registeringUsers":   llx.ResourceData(registeringUsers, ResourceMicrosoftDeviceRegistrationPolicyMembership),
		})
	if err != nil {
		return nil, err
	}
	mql := res.(*mqlMicrosoftDeviceRegistrationPolicyLocalAdminSettings)
	if registeringUsers == nil {
		mql.RegisteringUsers.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return mql, nil
}

// deviceRegistrationPolicy reports the tenant's Entra device settings.
func (a *mqlMicrosoftPolicies) deviceRegistrationPolicy() (*mqlMicrosoftDeviceRegistrationPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	policy, err := graphClient.Policies().DeviceRegistrationPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}
	if policy == nil {
		return nil, fmt.Errorf("device registration policy not found")
	}

	var mfaConfiguration *string
	if v := policy.GetMultiFactorAuthConfiguration(); v != nil {
		s := v.String()
		mfaConfiguration = &s
	}

	var localAdminPasswordEnabled *bool
	if lap := policy.GetLocalAdminPassword(); lap != nil {
		localAdminPasswordEnabled = lap.GetIsEnabled()
	}

	policyId := convert.ToValue(policy.GetId())

	var mqlJoin *mqlMicrosoftDeviceRegistrationPolicyJoinPolicy
	if join := policy.GetAzureADJoin(); join != nil {
		allowedToJoin, err := deviceRegistrationMembership(a.MqlRuntime, policyId+"/azureADJoin/allowedToJoin", join.GetAllowedToJoin())
		if err != nil {
			return nil, err
		}
		localAdmins, err := deviceRegistrationLocalAdmins(a.MqlRuntime, policyId+"/azureADJoin/localAdmins", join.GetLocalAdmins())
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(a.MqlRuntime, ResourceMicrosoftDeviceRegistrationPolicyJoinPolicy,
			map[string]*llx.RawData{
				"__id":                llx.StringData(policyId + "/azureADJoin"),
				"allowedToJoin":       llx.ResourceData(allowedToJoin, ResourceMicrosoftDeviceRegistrationPolicyMembership),
				"isAdminConfigurable": llx.BoolDataPtr(join.GetIsAdminConfigurable()),
				"localAdmins":         llx.ResourceData(localAdmins, ResourceMicrosoftDeviceRegistrationPolicyLocalAdminSettings),
			})
		if err != nil {
			return nil, err
		}
		mqlJoin = res.(*mqlMicrosoftDeviceRegistrationPolicyJoinPolicy)
		if allowedToJoin == nil {
			mqlJoin.AllowedToJoin.State = plugin.StateIsSet | plugin.StateIsNull
		}
		if localAdmins == nil {
			mqlJoin.LocalAdmins.State = plugin.StateIsSet | plugin.StateIsNull
		}
	}

	var mqlRegistration *mqlMicrosoftDeviceRegistrationPolicyRegistrationPolicy
	if registration := policy.GetAzureADRegistration(); registration != nil {
		allowedToRegister, err := deviceRegistrationMembership(a.MqlRuntime, policyId+"/azureADRegistration/allowedToRegister", registration.GetAllowedToRegister())
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(a.MqlRuntime, ResourceMicrosoftDeviceRegistrationPolicyRegistrationPolicy,
			map[string]*llx.RawData{
				"__id":                llx.StringData(policyId + "/azureADRegistration"),
				"allowedToRegister":   llx.ResourceData(allowedToRegister, ResourceMicrosoftDeviceRegistrationPolicyMembership),
				"isAdminConfigurable": llx.BoolDataPtr(registration.GetIsAdminConfigurable()),
			})
		if err != nil {
			return nil, err
		}
		mqlRegistration = res.(*mqlMicrosoftDeviceRegistrationPolicyRegistrationPolicy)
		if allowedToRegister == nil {
			mqlRegistration.AllowedToRegister.State = plugin.StateIsSet | plugin.StateIsNull
		}
	}

	mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceMicrosoftDeviceRegistrationPolicy,
		map[string]*llx.RawData{
			"__id":                         llx.StringDataPtr(policy.GetId()),
			"id":                           llx.StringDataPtr(policy.GetId()),
			"displayName":                  llx.StringDataPtr(policy.GetDisplayName()),
			"description":                  llx.StringDataPtr(policy.GetDescription()),
			"multiFactorAuthConfiguration": llx.StringDataPtr(mfaConfiguration),
			"userDeviceQuota":              llx.IntDataPtr(policy.GetUserDeviceQuota()),
			"localAdminPasswordEnabled":    llx.BoolDataPtr(localAdminPasswordEnabled),
			"azureADJoin":                  llx.ResourceData(mqlJoin, ResourceMicrosoftDeviceRegistrationPolicyJoinPolicy),
			"azureADRegistration":          llx.ResourceData(mqlRegistration, ResourceMicrosoftDeviceRegistrationPolicyRegistrationPolicy),
		})
	if err != nil {
		return nil, err
	}

	res := mqlPolicy.(*mqlMicrosoftDeviceRegistrationPolicy)
	if mqlJoin == nil {
		res.AzureADJoin.State = plugin.StateIsSet | plugin.StateIsNull
	}
	if mqlRegistration == nil {
		res.AzureADRegistration.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func initMicrosoftExternalIdentitiesPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Create the parent policies resource and call its method
	policiesResource, err := CreateResource(runtime, ResourceMicrosoftPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	policy, err := policiesResource.(*mqlMicrosoftPolicies).externalIdentitiesPolicy()
	if err != nil {
		return nil, nil, err
	}

	return nil, policy, nil
}

// Internal struct for caching cross-tenant access policy data
// This will be embedded in mqlMicrosoftCrossTenantAccessPolicyDefault after code generation
type mqlMicrosoftCrossTenantAccessPolicyDefaultInternal struct {
	policyLock                                              sync.Mutex
	fetched                                                 bool
	fetchErr                                                error
	policy                                                  models.CrossTenantAccessPolicyConfigurationDefaultable
	cachedAutomaticUserConsentSettings                      *mqlMicrosoftCrossTenantAccessPolicyDefaultAutomaticUserConsentSettings
	cachedB2bCollaborationInbound                           *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting
	cachedB2bCollaborationOutbound                          *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting
	cachedB2bDirectConnectInbound                           *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting
	cachedB2bDirectConnectOutbound                          *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting
	cachedInvitationRedemptionIdentityProviderConfiguration *mqlMicrosoftCrossTenantAccessPolicyDefaultInvitationRedemptionIdentityProviderConfiguration
	cachedInboundTrust                                      *mqlMicrosoftCrossTenantAccessPolicyDefaultInboundTrust
	cachedTenantRestrictions                                *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting
}

func (a *mqlMicrosoftPolicies) crossTenantAccessPolicy() (*mqlMicrosoftCrossTenantAccessPolicyDefault, error) {
	resource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftCrossTenantAccessPolicyDefault,
		map[string]*llx.RawData{
			"__id": llx.StringData("crossTenantAccessPolicyDefault"),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftCrossTenantAccessPolicyDefault), nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) getCrossTenantAccessPolicy() error {
	a.policyLock.Lock()
	defer a.policyLock.Unlock()

	if a.fetched {
		return a.fetchErr
	}

	a.fetched = true

	errHandler := func(err error) error {
		a.fetchErr = err
		return err
	}

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return errHandler(err)
	}

	policy, err := graphClient.Policies().CrossTenantAccessPolicy().DefaultEscaped().Get(context.Background(), nil)
	if err != nil {
		return errHandler(transformError(err))
	}
	if policy == nil {
		return errHandler(fmt.Errorf("cross-tenant access policy not found"))
	}

	a.policy = policy

	if policy.GetAutomaticUserConsentSettings() != nil {
		consentResource, err := newAutomaticUserConsentSettings(a.MqlRuntime, policy.GetAutomaticUserConsentSettings(), a.__id+"-automaticUserConsentSettings")
		if err != nil {
			return errHandler(err)
		}
		a.cachedAutomaticUserConsentSettings = consentResource
	}

	if policy.GetB2bCollaborationInbound() != nil {
		b2bResource, err := newB2BSetting(a.MqlRuntime, policy.GetB2bCollaborationInbound(), a.__id+"-b2bCollaborationInbound")
		if err != nil {
			return errHandler(err)
		}
		a.cachedB2bCollaborationInbound = b2bResource
	}

	if policy.GetB2bCollaborationOutbound() != nil {
		b2bResource, err := newB2BSetting(a.MqlRuntime, policy.GetB2bCollaborationOutbound(), a.__id+"-b2bCollaborationOutbound")
		if err != nil {
			return errHandler(err)
		}
		a.cachedB2bCollaborationOutbound = b2bResource
	}

	if policy.GetB2bDirectConnectInbound() != nil {
		b2bResource, err := newB2BSetting(a.MqlRuntime, policy.GetB2bDirectConnectInbound(), a.__id+"-b2bDirectConnectInbound")
		if err != nil {
			return errHandler(err)
		}
		a.cachedB2bDirectConnectInbound = b2bResource
	}

	if policy.GetB2bDirectConnectOutbound() != nil {
		b2bResource, err := newB2BSetting(a.MqlRuntime, policy.GetB2bDirectConnectOutbound(), a.__id+"-b2bDirectConnectOutbound")
		if err != nil {
			return errHandler(err)
		}
		a.cachedB2bDirectConnectOutbound = b2bResource
	}

	if policy.GetInvitationRedemptionIdentityProviderConfiguration() != nil {
		invConfig := policy.GetInvitationRedemptionIdentityProviderConfiguration()
		var fallbackProvider string
		if invConfig.GetFallbackIdentityProvider() != nil {
			fallbackProvider = invConfig.GetFallbackIdentityProvider().String()
		}
		var precedenceOrder []any
		for _, provider := range invConfig.GetPrimaryIdentityProviderPrecedenceOrder() {
			precedenceOrder = append(precedenceOrder, provider.String())
		}

		invResource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftCrossTenantAccessPolicyDefaultInvitationRedemptionIdentityProviderConfiguration,
			map[string]*llx.RawData{
				"__id":                                   llx.StringData(a.__id + "-invitationRedemptionIdentityProviderConfiguration"),
				"fallbackIdentityProvider":               llx.StringData(fallbackProvider),
				"primaryIdentityProviderPrecedenceOrder": llx.ArrayData(precedenceOrder, types.String),
			})
		if err != nil {
			return errHandler(err)
		}
		a.cachedInvitationRedemptionIdentityProviderConfiguration = invResource.(*mqlMicrosoftCrossTenantAccessPolicyDefaultInvitationRedemptionIdentityProviderConfiguration)
	}

	if policy.GetInboundTrust() != nil {
		inboundTrustResource, err := newInboundTrust(a.MqlRuntime, policy.GetInboundTrust(), a.__id+"-inboundTrust")
		if err != nil {
			return errHandler(err)
		}
		a.cachedInboundTrust = inboundTrustResource
	}

	if policy.GetTenantRestrictions() != nil {
		b2bResource, err := newB2BSetting(a.MqlRuntime, policy.GetTenantRestrictions(), a.__id+"-tenantRestrictions")
		if err != nil {
			return errHandler(err)
		}
		a.cachedTenantRestrictions = b2bResource
	}

	return nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) automaticUserConsentSettings() (*mqlMicrosoftCrossTenantAccessPolicyDefaultAutomaticUserConsentSettings, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedAutomaticUserConsentSettings, nil
}

// isServiceDefault reports whether the tenant still runs the Microsoft-provided
// cross-tenant defaults. It is computed rather than assigned during the fetch:
// as a plain field it was only populated as a side effect of a sibling accessor
// running first, so it read true, null, or unset depending on which other
// fields the query happened to select -- and the fetch wrote it without the
// lock that guards the rest of the shared policy state.
func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) isServiceDefault() (bool, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return false, err
	}
	if a.policy == nil {
		return false, nil
	}
	// An absent value means Microsoft did not report a customization, which is
	// the service default. Returning explicit false instead of null also keeps
	// a { isServiceDefault && ... } assertion from passing vacuously, since MQL
	// evaluates null && null as true.
	return convert.ToValue(a.policy.GetIsServiceDefault()), nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) b2bCollaborationInbound() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedB2bCollaborationInbound, nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) b2bCollaborationOutbound() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedB2bCollaborationOutbound, nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) b2bDirectConnectInbound() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedB2bDirectConnectInbound, nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) b2bDirectConnectOutbound() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedB2bDirectConnectOutbound, nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) tenantRestrictions() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedTenantRestrictions, nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) inboundTrust() (*mqlMicrosoftCrossTenantAccessPolicyDefaultInboundTrust, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedInboundTrust, nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) invitationRedemptionIdentityProviderConfiguration() (*mqlMicrosoftCrossTenantAccessPolicyDefaultInvitationRedemptionIdentityProviderConfiguration, error) {
	if err := a.getCrossTenantAccessPolicy(); err != nil {
		return nil, err
	}

	return a.cachedInvitationRedemptionIdentityProviderConfiguration, nil
}

// https://learn.microsoft.com/en-us/graph/api/tenantappmanagementpolicy-get?view=graph-rest-1.0
func (a *mqlMicrosoftPolicies) defaultAppManagementPolicy() (*mqlMicrosoftDefaultAppManagementPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	policy, err := graphClient.Policies().DefaultAppManagementPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}
	if policy == nil {
		return nil, fmt.Errorf("default app management policy not found")
	}

	policyId := ""
	if policy.GetId() != nil {
		policyId = *policy.GetId()
	}

	appRestrictions, err := newAppManagementConfiguration(a.MqlRuntime, policy.GetApplicationRestrictions(), policyId+"/applicationRestrictions")
	if err != nil {
		return nil, err
	}
	spRestrictions, err := newAppManagementConfiguration(a.MqlRuntime, policy.GetServicePrincipalRestrictions(), policyId+"/servicePrincipalRestrictions")
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(a.MqlRuntime, "microsoft.defaultAppManagementPolicy",
		map[string]*llx.RawData{
			"__id":                         llx.StringData(policyId),
			"displayName":                  llx.StringDataPtr(policy.GetDisplayName()),
			"description":                  llx.StringDataPtr(policy.GetDescription()),
			"isEnabled":                    llx.BoolDataPtr(policy.GetIsEnabled()),
			"applicationRestrictions":      llx.ResourceData(appRestrictions, "microsoft.defaultAppManagementPolicy.appManagementConfiguration"),
			"servicePrincipalRestrictions": llx.ResourceData(spRestrictions, "microsoft.defaultAppManagementPolicy.appManagementConfiguration"),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftDefaultAppManagementPolicy), nil
}

func initMicrosoftDefaultAppManagementPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Create the parent policies resource and call its method
	policiesResource, err := CreateResource(runtime, ResourceMicrosoftPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	policy, err := policiesResource.(*mqlMicrosoftPolicies).defaultAppManagementPolicy()
	if err != nil {
		return nil, nil, err
	}

	return nil, policy, nil
}

// credentialRestrictionConfig captures the getters shared by the password and
// key credential configuration types, whose only differing getter is the
// restriction type (its enum type differs between the two).
type credentialRestrictionConfig interface {
	GetMaxLifetime() *serialization.ISODuration
	GetState() *models.AppManagementRestrictionState
	GetRestrictForAppsCreatedAfterDateTime() *time.Time
}

func mapCredentialRestrictions[T credentialRestrictionConfig](creds []T, restrictionType func(T) string) []any {
	restrictions := []any{}
	for _, c := range creds {
		d := map[string]any{}
		if rt := restrictionType(c); rt != "" {
			d["restrictionType"] = rt
		}
		if c.GetMaxLifetime() != nil {
			d["maxLifetime"] = c.GetMaxLifetime().String()
		}
		if c.GetState() != nil {
			d["state"] = c.GetState().String()
		}
		if c.GetRestrictForAppsCreatedAfterDateTime() != nil {
			d["restrictForAppsCreatedAfterDateTime"] = c.GetRestrictForAppsCreatedAfterDateTime().UTC().Format(time.RFC3339)
		}
		restrictions = append(restrictions, d)
	}
	return restrictions
}

func newAppManagementConfiguration(runtime *plugin.Runtime, config models.AppManagementConfigurationable, id string) (*mqlMicrosoftDefaultAppManagementPolicyAppManagementConfiguration, error) {
	passwordCredentials := []any{}
	keyCredentials := []any{}

	if config != nil {
		passwordCredentials = mapCredentialRestrictions(config.GetPasswordCredentials(), func(c models.PasswordCredentialConfigurationable) string {
			if c.GetRestrictionType() != nil {
				return c.GetRestrictionType().String()
			}
			return ""
		})
		keyCredentials = mapCredentialRestrictions(config.GetKeyCredentials(), func(c models.KeyCredentialConfigurationable) string {
			if c.GetRestrictionType() != nil {
				return c.GetRestrictionType().String()
			}
			return ""
		})
	}

	resource, err := CreateResource(runtime, "microsoft.defaultAppManagementPolicy.appManagementConfiguration",
		map[string]*llx.RawData{
			"__id":                llx.StringData(id),
			"passwordCredentials": llx.ArrayData(passwordCredentials, types.Dict),
			"keyCredentials":      llx.ArrayData(keyCredentials, types.Dict),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftDefaultAppManagementPolicyAppManagementConfiguration), nil
}

func newAutomaticUserConsentSettings(runtime *plugin.Runtime, settings models.InboundOutboundPolicyConfigurationable, id string) (*mqlMicrosoftCrossTenantAccessPolicyDefaultAutomaticUserConsentSettings, error) {
	resource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultAutomaticUserConsentSettings,
		map[string]*llx.RawData{
			"__id":            llx.StringData(id),
			"inboundAllowed":  llx.BoolDataPtr(settings.GetInboundAllowed()),
			"outboundAllowed": llx.BoolDataPtr(settings.GetOutboundAllowed()),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftCrossTenantAccessPolicyDefaultAutomaticUserConsentSettings), nil
}

func newInboundTrust(runtime *plugin.Runtime, trust models.CrossTenantAccessPolicyInboundTrustable, id string) (*mqlMicrosoftCrossTenantAccessPolicyDefaultInboundTrust, error) {
	resource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultInboundTrust,
		map[string]*llx.RawData{
			"__id":                                llx.StringData(id),
			"isMfaAccepted":                       llx.BoolDataPtr(trust.GetIsMfaAccepted()),
			"isCompliantDeviceAccepted":           llx.BoolDataPtr(trust.GetIsCompliantDeviceAccepted()),
			"isHybridAzureADJoinedDeviceAccepted": llx.BoolDataPtr(trust.GetIsHybridAzureADJoinedDeviceAccepted()),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftCrossTenantAccessPolicyDefaultInboundTrust), nil
}

func newB2BSetting(runtime *plugin.Runtime, setting models.CrossTenantAccessPolicyB2BSettingable, settingId string) (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting, error) {
	usersAndGroups, err := newCrossTenantAccessPolicyTarget(runtime, setting.GetUsersAndGroups(), settingId+"-usersAndGroups")
	if err != nil {
		return nil, err
	}

	applications, err := newCrossTenantAccessPolicyTarget(runtime, setting.GetApplications(), settingId+"-applications")
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultB2bSetting,
		map[string]*llx.RawData{
			"__id":           llx.StringData(settingId),
			"usersAndGroups": targetConfigData(usersAndGroups),
			"applications":   targetConfigData(applications),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting), nil
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting) usersAndGroups() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig, error) {
	return a.UsersAndGroups.Data, a.UsersAndGroups.Error
}

func (a *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSetting) applications() (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig, error) {
	return a.Applications.Data, a.Applications.Error
}

// targetConfigData wraps a target configuration for CreateResource, passing a
// nil configuration as null so the field reads null instead of an empty
// resource.
func targetConfigData(c *mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig) *llx.RawData {
	if c == nil {
		return llx.NilData
	}
	return llx.ResourceData(c, string(ResourceMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig))
}

// newCrossTenantAccessPolicyTarget returns nil for a nil configuration: Graph
// omits usersAndGroups or applications on a B2B setting that does not
// configure them.
func newCrossTenantAccessPolicyTarget(runtime *plugin.Runtime, accessPolicyTargetConfiguration models.CrossTenantAccessPolicyTargetConfigurationable, id string) (*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig, error) {
	if accessPolicyTargetConfiguration == nil {
		return nil, nil
	}
	var accessType string
	if accessPolicyTargetConfiguration.GetAccessType() != nil {
		accessType = accessPolicyTargetConfiguration.GetAccessType().String()
	}

	var targetResources []any
	for _, target := range accessPolicyTargetConfiguration.GetTargets() {
		if target == nil {
			continue
		}
		var targetType string
		if target.GetTargetType() != nil {
			targetType = target.GetTargetType().String()
		}
		var targetValue string
		if target.GetTarget() != nil {
			targetValue = *target.GetTarget()
		}

		targetResource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTarget,
			map[string]*llx.RawData{
				"__id":       llx.StringData(fmt.Sprintf("%s-%s", id, targetValue)),
				"target":     llx.StringData(targetValue),
				"targetType": llx.StringData(targetType),
			})
		if err != nil {
			return nil, err
		}
		targetResources = append(targetResources, targetResource)
	}

	resource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig,
		map[string]*llx.RawData{
			"__id":       llx.StringData(id),
			"accessType": llx.StringData(accessType),
			"targets":    llx.ArrayData(targetResources, types.Resource(string(ResourceMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTarget))),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftCrossTenantAccessPolicyDefaultB2bSettingTargetConfig), nil
}

// allowedUserRefs resolves the users an enumerated membership names.
//
// A principal that cannot be resolved fails the field rather than being
// skipped: this list is the scope of who may join or administer a device, and
// a list that quietly lost an entry still satisfies every assertion made
// about it.
func (a *mqlMicrosoftDeviceRegistrationPolicyMembership) allowedUserRefs() ([]any, error) {
	res := []any{}
	for _, id := range a.GetAllowedUsers().Data {
		s, ok := id.(string)
		if !ok || s == "" {
			continue
		}
		user, err := NewResource(a.MqlRuntime, ResourceMicrosoftUser, map[string]*llx.RawData{
			"id": llx.StringData(s),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, user)
	}
	return res, nil
}

// allowedGroupRefs resolves the groups an enumerated membership names.
func (a *mqlMicrosoftDeviceRegistrationPolicyMembership) allowedGroupRefs() ([]any, error) {
	res := []any{}
	for _, id := range a.GetAllowedGroups().Data {
		s, ok := id.(string)
		if !ok || s == "" {
			continue
		}
		group, err := NewResource(a.MqlRuntime, ResourceMicrosoftGroup, map[string]*llx.RawData{
			"id": llx.StringData(s),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, group)
	}
	return res, nil
}
