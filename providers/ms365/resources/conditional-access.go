// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// namedLocations exposes the tenant's named-location container, which holds
// the IP-based and country-based named locations.
func (a *mqlMicrosoftConditionalAccess) namedLocations() (*mqlMicrosoftConditionalAccessNamedLocations, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.namedLocations", map[string]*llx.RawData{
		"__id": llx.StringData("microsoft.conditionalAccess.namedLocations"),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftConditionalAccessNamedLocations), nil
}

type mqlMicrosoftConditionalAccessNamedLocationsInternal struct {
	// guards the named-locations Graph fetch so both ipLocations() and
	// countryLocations() share a single API call.
	namedLocationsOnce sync.Once
	namedLocations     []models.NamedLocationable
	namedLocationsErr  error
}

// loadNamedLocations fetches the tenant's named locations once and caches
// the result. Both ipLocations() and countryLocations() filter from the
// same backing slice instead of issuing duplicate Graph calls.
func (a *mqlMicrosoftConditionalAccessNamedLocations) loadNamedLocations() ([]models.NamedLocationable, error) {
	a.namedLocationsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			a.namedLocationsErr = err
			return
		}

		ctx := context.Background()
		resp, err := graphClient.Identity().ConditionalAccess().NamedLocations().Get(ctx, nil)
		if err != nil {
			a.namedLocationsErr = transformError(err)
			return
		}
		a.namedLocations, a.namedLocationsErr = iterate[models.NamedLocationable](ctx, resp, graphClient.GetAdapter(), models.CreateNamedLocationCollectionResponseFromDiscriminatorValue)
	})
	return a.namedLocations, a.namedLocationsErr
}

func (a *mqlMicrosoftConditionalAccessNamedLocations) ipLocations() ([]any, error) {
	namedLocations, err := a.loadNamedLocations()
	if err != nil {
		return nil, err
	}

	var locationDetails []any
	for _, location := range namedLocations {
		if ipLocation, ok := location.(*models.IpNamedLocation); ok {
			displayName := ipLocation.GetDisplayName()
			isTrusted := ipLocation.GetIsTrusted()

			if displayName != nil {
				trusted := false
				if isTrusted != nil {
					trusted = *isTrusted
				}

				locationInfo, err := CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.ipNamedLocation",
					map[string]*llx.RawData{
						"__id":             llx.StringDataPtr(ipLocation.GetId()),
						"id":               llx.StringDataPtr(ipLocation.GetId()),
						"name":             llx.StringDataPtr(displayName),
						"trusted":          llx.BoolData(trusted),
						"createdDateTime":  graphTimeData(ipLocation.GetCreatedDateTime()),
						"modifiedDateTime": graphTimeData(ipLocation.GetModifiedDateTime()),
					})
				if err != nil {
					return nil, err
				}
				locationDetails = append(locationDetails, locationInfo)
			}
		}
	}

	if len(locationDetails) == 0 {
		return nil, nil
	}

	return locationDetails, nil
}

func (a *mqlMicrosoftConditionalAccessNamedLocations) countryLocations() ([]any, error) {
	namedLocations, err := a.loadNamedLocations()
	if err != nil {
		return nil, err
	}

	var locationDetails []any
	for _, location := range namedLocations {
		if countryLocation, ok := location.(*models.CountryNamedLocation); ok {
			displayName := countryLocation.GetDisplayName()
			countryLookupMethod := countryLocation.GetCountryLookupMethod()

			var lookupMethodStr *string
			if countryLookupMethod != nil {
				method := countryLookupMethod.String()
				lookupMethodStr = &method
			}

			if displayName != nil && lookupMethodStr != nil {
				locationInfo, err := CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.countryNamedLocation",
					map[string]*llx.RawData{
						"__id":         llx.StringDataPtr(countryLocation.GetId()),
						"id":           llx.StringDataPtr(countryLocation.GetId()),
						"name":         llx.StringDataPtr(displayName),
						"lookupMethod": llx.StringDataPtr(lookupMethodStr),
					})
				if err != nil {
					return nil, err
				}
				locationDetails = append(locationDetails, locationInfo)
			}
		}
	}

	if len(locationDetails) == 0 {
		return nil, nil
	}

	return locationDetails, nil
}

func (m *mqlMicrosoftConditionalAccessPolicy) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftConditionalAccessPolicyConditions) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftConditionalAccessPolicyGrantControls) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftConditionalAccessPolicySessionControls) id() (string, error) {
	return m.Id.Data, nil
}

// Conditional Access Policies
func (a *mqlMicrosoftConditionalAccess) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	policies, err := iterate[models.ConditionalAccessPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateConditionalAccessPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var policyDetails []any
	for _, policy := range policies {
		id := policy.GetId()
		displayName := policy.GetDisplayName()

		if id != nil && displayName != nil {
			policyResource, err := a.createPolicyResource(policy)
			if err != nil {
				return nil, err
			}
			policyDetails = append(policyDetails, policyResource)
		}
	}

	return policyDetails, nil
}

// Helper methods for creating policy sub-resources
func (a *mqlMicrosoftConditionalAccess) createPolicyResource(policy models.ConditionalAccessPolicyable) (any, error) {
	id := policy.GetId()
	if id == nil {
		return nil, fmt.Errorf("policy ID cannot be nil")
	}

	var conditions plugin.Resource
	if mConditions := policy.GetConditions(); mConditions != nil {
		var err error
		// Create conditions resource
		conditions, err = a.createConditionsResource(*id, mConditions)
		if err != nil {
			return nil, fmt.Errorf("failed to create conditions resource: %w", err)
		}
	}

	// Create grant controls resource
	var grantControls plugin.Resource
	if mGrantControls := policy.GetGrantControls(); mGrantControls != nil {
		var err error
		grantControls, err = a.createGrantControlsResource(*id, mGrantControls)
		if err != nil {
			return nil, fmt.Errorf("failed to create grant controls resource: %w", err)
		}
	}

	var sessionControls plugin.Resource
	if mSessionControls := policy.GetSessionControls(); mSessionControls != nil {
		var err error
		// Create session controls resource
		sessionControls, err = a.createSessionControlsResource(*id, mSessionControls)
		if err != nil {
			return nil, fmt.Errorf("failed to create session controls resource: %w", err)
		}
	}

	policyInfo, err := CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy",
		map[string]*llx.RawData{
			"__id":             llx.StringDataPtr(id),
			"id":               llx.StringDataPtr(id),
			"templateId":       llx.StringDataPtr(policy.GetTemplateId()),
			"displayName":      llx.StringDataPtr(policy.GetDisplayName()),
			"createdDateTime":  graphTimeData(policy.GetCreatedDateTime()),
			"modifiedDateTime": graphTimeData(policy.GetModifiedDateTime()),
			"state":            llx.StringDataPtr(enumPtrString(policy.GetState())),
			"sessionControls":  llx.ResourceData(sessionControls, "microsoft.conditionalAccess.policy.sessionControls"),
			"conditions":       llx.ResourceData(conditions, "microsoft.conditionalAccess.policy.conditions"),
			"grantControls":    llx.ResourceData(grantControls, "microsoft.conditionalAccess.policy.grantControls"),
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create policy resource: %w", err)
	}

	return policyInfo, nil
}

func (a *mqlMicrosoftConditionalAccess) createConditionsResource(
	policyId string,
	conditions models.ConditionalAccessConditionSetable,
) (plugin.Resource, error) {
	conditionsId := policyId + "_conditions"

	var err error
	var mqlApplications plugin.Resource
	var mqlUsers plugin.Resource
	var mqlLocations plugin.Resource
	var mqlPlatforms plugin.Resource
	var mqlClientApplications plugin.Resource
	var mqlAuthenticationFlows plugin.Resource

	if conditions != nil && conditions.GetAuthenticationFlows() != nil {
		authenticationFlows := conditions.GetAuthenticationFlows()
		usersData := map[string]*llx.RawData{
			"__id":            llx.StringData(policyId + "_conditions_authflows"),
			"transferMethods": llx.StringDataPtr(enumPtrString(authenticationFlows.GetTransferMethods())),
		}

		mqlAuthenticationFlows, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions.authenticationFlows", usersData)
		if err != nil {
			return nil, err
		}
	}

	// Extract users
	if conditions != nil && conditions.GetUsers() != nil {
		users := conditions.GetUsers()
		usersData := map[string]*llx.RawData{
			"__id":         llx.StringData(policyId + "_conditions_users"),
			"includeUsers": llx.ArrayData(convert.SliceAnyToInterface(users.GetIncludeUsers()), types.String),
			"excludeUsers": llx.ArrayData(convert.SliceAnyToInterface(users.GetExcludeUsers()), types.String),
		}

		mqlUsers, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions.users", usersData)
		if err != nil {
			return nil, err
		}
		mqlConditionsUsers := mqlUsers.(*mqlMicrosoftConditionalAccessPolicyConditionsUsers)
		mqlConditionsUsers.cacheIncludeGroups = users.GetIncludeGroups()
		mqlConditionsUsers.cacheExcludeGroups = users.GetExcludeGroups()
		mqlConditionsUsers.cacheIncludeRoles = users.GetIncludeRoles()
		mqlConditionsUsers.cacheExcludeRoles = users.GetExcludeRoles()
	}

	if conditions != nil && conditions.GetApplications() != nil {
		apps := conditions.GetApplications()
		mqlApplications, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions.applications", map[string]*llx.RawData{
			"__id":                llx.StringData(policyId + "_conditions_applications"),
			"includeApplications": llx.ArrayData(convert.SliceAnyToInterface(apps.GetIncludeApplications()), types.String),
			"excludeApplications": llx.ArrayData(convert.SliceAnyToInterface(apps.GetExcludeApplications()), types.String),
			"includeUserActions":  llx.ArrayData(convert.SliceAnyToInterface(apps.GetIncludeUserActions()), types.String),
		})
		if err != nil {
			return nil, err
		}
	}

	// Extract locations and create mqlLocations resource
	if conditions != nil && conditions.GetLocations() != nil {
		locations := conditions.GetLocations()
		locationsData := map[string]*llx.RawData{
			"__id":             llx.StringData(policyId + "_conditions_locations"),
			"includeLocations": llx.ArrayData(convert.SliceAnyToInterface(locations.GetIncludeLocations()), types.String),
			"excludeLocations": llx.ArrayData(convert.SliceAnyToInterface(locations.GetExcludeLocations()), types.String),
		}
		mqlLocations, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions.locations", locationsData)
		if err != nil {
			return nil, err
		}
	}

	// Extract platforms and create mqlPlatforms resource
	if conditions != nil && conditions.GetPlatforms() != nil {
		platforms := conditions.GetPlatforms()
		platformsData := map[string]*llx.RawData{"__id": llx.StringData(policyId + "_conditions_platforms")}

		var includePlatformStrings []string
		for _, platform := range platforms.GetIncludePlatforms() {
			if platform.String() != "" {
				includePlatformStrings = append(includePlatformStrings, platform.String())
			}
		}
		platformsData["includePlatforms"] = llx.ArrayData(convert.SliceAnyToInterface(includePlatformStrings), types.String)

		var excludePlatformStrings []string
		for _, platform := range platforms.GetExcludePlatforms() {
			if platform.String() != "" {
				excludePlatformStrings = append(excludePlatformStrings, platform.String())
			}
		}
		platformsData["excludePlatforms"] = llx.ArrayData(convert.SliceAnyToInterface(excludePlatformStrings), types.String)

		mqlPlatforms, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions.platforms", platformsData)
		if err != nil {
			return nil, err
		}
	}

	// Extract client applications and create mqlClientApplications resource
	if conditions != nil && conditions.GetClientApplications() != nil {
		clientApps := conditions.GetClientApplications()
		clientApplicationsData := map[string]*llx.RawData{
			"__id":                     llx.StringData(policyId + "_conditions_client_applications"),
			"includeServicePrincipals": llx.ArrayData(convert.SliceAnyToInterface(clientApps.GetIncludeServicePrincipals()), types.String),
			"excludeServicePrincipals": llx.ArrayData(convert.SliceAnyToInterface(clientApps.GetExcludeServicePrincipals()), types.String),
		}
		mqlClientApplications, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions.clientApplications", clientApplicationsData)
		if err != nil {
			return nil, err
		}
	}

	var insiderRiskLevelsStr string
	if conditions != nil && conditions.GetInsiderRiskLevels() != nil {
		insiderRiskLevelsStr = conditions.GetInsiderRiskLevels().String()
	}

	conditionsResource, err := CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.conditions",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(conditionsId),
			"id":                         llx.StringData(conditionsId),
			"applications":               llx.ResourceData(mqlApplications, "microsoft.conditionalAccess.policy.conditions.applications"),
			"authenticationFlows":        llx.ResourceData(mqlAuthenticationFlows, "microsoft.conditionalAccess.policy.conditions.authenticationFlows"),
			"users":                      llx.ResourceData(mqlUsers, "microsoft.conditionalAccess.policy.conditions.users"),
			"locations":                  llx.ResourceData(mqlLocations, "microsoft.conditionalAccess.policy.conditions.locations"),
			"platforms":                  llx.ResourceData(mqlPlatforms, "microsoft.conditionalAccess.policy.conditions.platforms"),
			"clientApplications":         llx.ResourceData(mqlClientApplications, "microsoft.conditionalAccess.policy.conditions.clientApplications"),
			"insiderRiskLevels":          llx.StringData(insiderRiskLevelsStr),
			"clientAppTypes":             llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(conditions.GetClientAppTypes())), types.String),
			"userRiskLevels":             llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(conditions.GetUserRiskLevels())), types.String),
			"signInRiskLevels":           llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(conditions.GetSignInRiskLevels())), types.String),
			"servicePrincipalRiskLevels": llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(conditions.GetServicePrincipalRiskLevels())), types.String),
		})

	return conditionsResource, err
}

func (a *mqlMicrosoftConditionalAccess) createGrantControlsResource(
	policyId string,
	grantControls models.ConditionalAccessGrantControlsable,
) (plugin.Resource, error) {
	grantControlsId := policyId + "_grantControls"

	var mqlAuthStrength plugin.Resource

	// Create authenticationStrength resource if it exists
	if grantControls.GetAuthenticationStrength() != nil {
		authStrength := grantControls.GetAuthenticationStrength()
		authStrengthData := map[string]*llx.RawData{
			"__id":                  llx.StringDataPtr(authStrength.GetId()),
			"id":                    llx.StringDataPtr(authStrength.GetId()),
			"displayName":           llx.StringDataPtr(authStrength.GetDisplayName()),
			"description":           llx.StringDataPtr(authStrength.GetDescription()),
			"policyType":            llx.StringDataPtr(enumPtrString(authStrength.GetPolicyType())),
			"requirementsSatisfied": llx.StringDataPtr(enumPtrString(authStrength.GetRequirementsSatisfied())),
			"allowedCombinations":   llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(authStrength.GetAllowedCombinations())), types.String),
			"createdDateTime":       graphTimeData(authStrength.GetCreatedDateTime()),
			"modifiedDateTime":      graphTimeData(authStrength.GetModifiedDateTime()),
		}

		var err error
		mqlAuthStrength, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.grantControls.authenticationStrength", authStrengthData)
		if err != nil {
			return nil, err
		}
	}

	customAuthFactors := grantControls.GetCustomAuthenticationFactors()
	termsOfUse := grantControls.GetTermsOfUse()
	builtInControls := convertEnumCollectionToStrings(grantControls.GetBuiltInControls())

	return CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.grantControls",
		map[string]*llx.RawData{
			"__id":                        llx.StringData(grantControlsId),
			"id":                          llx.StringData(grantControlsId),
			"operator":                    llx.StringDataPtr(grantControls.GetOperator()),
			"builtInControls":             llx.ArrayData(convert.SliceAnyToInterface(builtInControls), types.String),
			"customAuthenticationFactors": llx.ArrayData(convert.SliceAnyToInterface(customAuthFactors), types.String),
			"termsOfUse":                  llx.ArrayData(convert.SliceAnyToInterface(termsOfUse), types.String),
			"authenticationStrength":      llx.ResourceData(mqlAuthStrength, "microsoft.conditionalAccess.policy.grantControls.authenticationStrength"),
		})
}

func (a *mqlMicrosoftConditionalAccess) createSessionControlsResource(
	policyId string,
	sessionControls models.ConditionalAccessSessionControlsable,
) (plugin.Resource, error) {
	sessionControlsId := policyId + "_sessionControls"

	var mqlSignInFreq plugin.Resource
	var mqlCloudAppSecurity plugin.Resource
	var mqlPersistentBrowser plugin.Resource
	var mqlAppEnforcedRestrictions plugin.Resource

	// Create signInFrequency resource
	if sessionControls != nil && sessionControls.GetSignInFrequency() != nil {
		signInFreq := sessionControls.GetSignInFrequency()
		var freqType *string
		if signInFreq.GetTypeEscaped() != nil {
			t := signInFreq.GetTypeEscaped().String()
			freqType = &t
		}
		signInFreqData := map[string]*llx.RawData{
			"__id":               llx.StringData(policyId + "_session_signInFrequency"),
			"authenticationType": llx.StringDataPtr(enumPtrString(signInFreq.GetAuthenticationType())),
			"frequencyInterval":  llx.StringDataPtr(enumPtrString(signInFreq.GetFrequencyInterval())),
			"isEnabled":          llx.BoolDataPtr(signInFreq.GetIsEnabled()),
			"type":               llx.StringDataPtr(freqType),
			"value":              llx.IntDataPtr(signInFreq.GetValue()),
		}
		var err error
		mqlSignInFreq, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.sessionControls.signInFrequency", signInFreqData)
		if err != nil {
			return nil, err
		}
	}

	// Create cloudAppSecurity resource
	if sessionControls != nil && sessionControls.GetCloudAppSecurity() != nil {
		cloudAppSecurity := sessionControls.GetCloudAppSecurity()
		cloudAppSecurityData := map[string]*llx.RawData{
			"__id":                 llx.StringData(policyId + "_session_cloudAppSecurity"),
			"cloudAppSecurityType": llx.StringDataPtr(enumPtrString(cloudAppSecurity.GetCloudAppSecurityType())),
			"isEnabled":            llx.BoolDataPtr(cloudAppSecurity.GetIsEnabled()),
		}
		var err error
		mqlCloudAppSecurity, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.sessionControls.cloudAppSecurity", cloudAppSecurityData)
		if err != nil {
			return nil, err
		}
	}

	// Create persistentBrowser resource
	if sessionControls != nil && sessionControls.GetPersistentBrowser() != nil {
		persistentBrowser := sessionControls.GetPersistentBrowser()
		persistentBrowserData := map[string]*llx.RawData{
			"__id":      llx.StringData(policyId + "_session_persistentBrowser"),
			"mode":      llx.StringDataPtr(enumPtrString(persistentBrowser.GetMode())),
			"isEnabled": llx.BoolDataPtr(persistentBrowser.GetIsEnabled()),
		}
		var err error
		mqlPersistentBrowser, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.sessionControls.persistentBrowser", persistentBrowserData)
		if err != nil {
			return nil, err
		}
	}

	// Create applicationEnforcedRestrictions resource
	if sessionControls != nil && sessionControls.GetApplicationEnforcedRestrictions() != nil {
		appEnforcedRestrictions := sessionControls.GetApplicationEnforcedRestrictions()
		appEnforcedRestrictionsData := map[string]*llx.RawData{
			"__id":      llx.StringData(policyId + "_session_appEnforcedRestrictions"),
			"isEnabled": llx.BoolDataPtr(appEnforcedRestrictions.GetIsEnabled()),
		}
		var err error
		mqlAppEnforcedRestrictions, err = CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.sessionControls.applicationEnforcedRestrictions", appEnforcedRestrictionsData)
		if err != nil {
			return nil, err
		}
	}

	// secureSignInSession is a dict, so it has to be built from JSON-native
	// values. It previously created a resource type that does not exist, out of
	// the unrelated disableResilienceDefaults scalar -- see secureSignInSessionDict.
	secureSignInSession := secureSignInSessionDict(sessionControls)

	var disableResilienceDefaults *bool
	if sessionControls != nil {
		disableResilienceDefaults = sessionControls.GetDisableResilienceDefaults()
	}

	return CreateResource(a.MqlRuntime, "microsoft.conditionalAccess.policy.sessionControls",
		map[string]*llx.RawData{
			"__id":                            llx.StringData(sessionControlsId),
			"id":                              llx.StringData(sessionControlsId),
			"signInFrequency":                 llx.ResourceData(mqlSignInFreq, "microsoft.conditionalAccess.policy.sessionControls.signInFrequency"),
			"cloudAppSecurity":                llx.ResourceData(mqlCloudAppSecurity, "microsoft.conditionalAccess.policy.sessionControls.cloudAppSecurity"),
			"persistentBrowser":               llx.ResourceData(mqlPersistentBrowser, "microsoft.conditionalAccess.policy.sessionControls.persistentBrowser"),
			"applicationEnforcedRestrictions": llx.ResourceData(mqlAppEnforcedRestrictions, "microsoft.conditionalAccess.policy.sessionControls.applicationEnforcedRestrictions"),
			"secureSignInSession":             llx.DictData(secureSignInSession),
			"disableResilienceDefaults":       llx.BoolDataPtr(disableResilienceDefaults),
		})
}

// secureSignInSessionDict renders the secureSignInSession session control as a
// JSON-native dict, or nil when the policy does not set the control.
//
// The .lr declares this field as a dict, so its value must be built from
// JSON-native types: a dict holding an llx resource fails conversion on read
// with "unsupported child type". It is sourced from GetSecureSignInSession,
// the property the field is named after -- disableResilienceDefaults is a
// separate scalar on sessionControls and is surfaced as its own field.
func secureSignInSessionDict(sessionControls models.ConditionalAccessSessionControlsable) map[string]any {
	if sessionControls == nil {
		return nil
	}
	control := sessionControls.GetSecureSignInSession()
	if control == nil {
		return nil
	}
	return map[string]any{
		"isEnabled": convert.ToValue(control.GetIsEnabled()),
	}
}

func convertEnumCollectionToStrings[T fmt.Stringer](enums []T) []string {
	var result []string
	if enums == nil {
		return nil
	}
	for _, enum := range enums {
		if enum.String() != "" {
			result = append(result, enum.String())
		}
	}
	return result
}

// initMicrosoftConditionalAccessAuthenticationMethodsPolicy populates the
// policy when it is queried directly
// (microsoft.conditionalAccess.authenticationMethodsPolicy) rather than through
// the microsoft.conditionalAccess accessor. Without this, a direct query
// returns a bare husk with all fields null. We build it through the parent
// accessor, which fetches and caches the policy.
func initMicrosoftConditionalAccessAuthenticationMethodsPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	caResource, err := CreateResource(runtime, "microsoft.conditionalAccess", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	policy, err := caResource.(*mqlMicrosoftConditionalAccess).authenticationMethodsPolicy()
	if err != nil {
		return nil, nil, err
	}

	return nil, policy, nil
}

func (a *mqlMicrosoftConditionalAccess) authenticationMethodsPolicy() (*mqlMicrosoftConditionalAccessAuthenticationMethodsPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	policy, err := graphClient.Policies().AuthenticationMethodsPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}

	if policy == nil {
		return nil, nil
	}

	return newMqlAuthenticationMethodsPolicy(a.MqlRuntime, policy)
}

func newMqlAuthenticationMethodsPolicy(runtime *plugin.Runtime, policy models.AuthenticationMethodsPolicyable) (*mqlMicrosoftConditionalAccessAuthenticationMethodsPolicy, error) {
	if policy.GetId() == nil {
		return nil, fmt.Errorf("authentication methods policy has a nil ID")
	}

	var authMethodConfigs []any
	for _, config := range policy.GetAuthenticationMethodConfigurations() {
		mqlConfig, err := newMqlAuthenticationMethodConfiguration(runtime, config)
		if err != nil {
			return nil, err
		}
		authMethodConfigs = append(authMethodConfigs, mqlConfig)
	}

	resource, err := CreateResource(runtime, "microsoft.conditionalAccess.authenticationMethodsPolicy", map[string]*llx.RawData{
		"__id":                               llx.StringDataPtr(policy.GetId()),
		"id":                                 llx.StringDataPtr(policy.GetId()),
		"displayName":                        llx.StringDataPtr(policy.GetDisplayName()),
		"description":                        llx.StringDataPtr(policy.GetDescription()),
		"lastModifiedDateTime":               graphTimeData(policy.GetLastModifiedDateTime()),
		"policyVersion":                      llx.StringDataPtr(policy.GetPolicyVersion()),
		"authenticationMethodConfigurations": llx.ArrayData(llx.TArr2Raw(authMethodConfigs), types.Resource("microsoft.conditionalAccess.authenticationMethodConfiguration")),
	})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftConditionalAccessAuthenticationMethodsPolicy), nil
}

// initMicrosoftConditionalAccessAuthenticationMethodConfiguration rejects a
// direct query of this resource. It is a member of
// authenticationMethodsPolicy.authenticationMethodConfigurations and has no
// standalone identity, so a bare binding resolves to an empty husk whose plain
// fields (id, state) then fail with "cannot convert primitive with NO type
// information". When it is built as a list element (with an __id), it passes
// through unchanged.
func initMicrosoftConditionalAccessAuthenticationMethodConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	return nil, nil, errors.New("microsoft.conditionalAccess.authenticationMethodConfiguration cannot be queried directly; read it through microsoft.conditionalAccess.authenticationMethodsPolicy.authenticationMethodConfigurations")
}

func newMqlAuthenticationMethodConfiguration(runtime *plugin.Runtime, config models.AuthenticationMethodConfigurationable) (*mqlMicrosoftConditionalAccessAuthenticationMethodConfiguration, error) {
	resource, err := CreateResource(runtime, "microsoft.conditionalAccess.authenticationMethodConfiguration", map[string]*llx.RawData{
		"__id":  llx.StringDataPtr(config.GetId()),
		"id":    llx.StringDataPtr(config.GetId()),
		"state": llx.StringDataPtr(enumPtrString(config.GetState())),
	})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftConditionalAccessAuthenticationMethodConfiguration), nil
}
