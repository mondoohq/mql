// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// initFromParentList resolves a resource queried directly by id, such as
// microsoft.security.riskyUser(id: "..."), by scanning the list the parent
// resource already fetched. Fully populated args (from CreateResource) pass
// through untouched, as do args without a usable id. An id missing from the
// parent's list is a not-found error rather than an empty resource.
func initFromParentList[T plugin.Resource](
	resourceName string,
	args map[string]*llx.RawData,
	list func() ([]any, error),
	idOf func(T) string,
) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	rawId, ok := args["id"]
	if !ok || rawId == nil {
		return args, nil, nil
	}
	id, ok := rawId.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	items, err := list()
	if err != nil {
		return nil, nil, err
	}
	for _, raw := range items {
		item, ok := raw.(T)
		if ok && idOf(item) == id {
			return nil, item, nil
		}
	}
	return nil, nil, fmt.Errorf("%s with id %q not found", resourceName, id)
}

// listOf adapts a generated list getter to the shape initFromParentList takes.
func listOf(tv *plugin.TValue[[]any]) ([]any, error) {
	return tv.Data, tv.Error
}

func microsoftSecurityParent(runtime *plugin.Runtime) (*mqlMicrosoftSecurity, error) {
	res, err := CreateResource(runtime, ResourceMicrosoftSecurity, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftSecurity), nil
}

func microsoftPoliciesParent(runtime *plugin.Runtime) (*mqlMicrosoftPolicies, error) {
	res, err := CreateResource(runtime, ResourceMicrosoftPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftPolicies), nil
}

func microsoftConditionalAccessParent(runtime *plugin.Runtime) (*mqlMicrosoftConditionalAccess, error) {
	res, err := CreateResource(runtime, ResourceMicrosoftConditionalAccess, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftConditionalAccess), nil
}

func securityList(runtime *plugin.Runtime, get func(*mqlMicrosoftSecurity) *plugin.TValue[[]any]) func() ([]any, error) {
	return func() ([]any, error) {
		sec, err := microsoftSecurityParent(runtime)
		if err != nil {
			return nil, err
		}
		return listOf(get(sec))
	}
}

func policiesList(runtime *plugin.Runtime, get func(*mqlMicrosoftPolicies) *plugin.TValue[[]any]) func() ([]any, error) {
	return func() ([]any, error) {
		pol, err := microsoftPoliciesParent(runtime)
		if err != nil {
			return nil, err
		}
		return listOf(get(pol))
	}
}

func namedLocationsList(runtime *plugin.Runtime, get func(*mqlMicrosoftConditionalAccessNamedLocations) *plugin.TValue[[]any]) func() ([]any, error) {
	return func() ([]any, error) {
		ca, err := microsoftConditionalAccessParent(runtime)
		if err != nil {
			return nil, err
		}
		locations := ca.GetNamedLocations()
		if locations.Error != nil {
			return nil, locations.Error
		}
		if locations.Data == nil {
			return nil, nil
		}
		return listOf(get(locations.Data))
	}
}

func initMicrosoftConditionalAccessPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftConditionalAccessPolicy, args,
		func() ([]any, error) {
			ca, err := microsoftConditionalAccessParent(runtime)
			if err != nil {
				return nil, err
			}
			return listOf(ca.GetPolicies())
		},
		func(r *mqlMicrosoftConditionalAccessPolicy) string { return r.Id.Data })
}

func initMicrosoftConditionalAccessIpNamedLocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftConditionalAccessIpNamedLocation, args,
		namedLocationsList(runtime, (*mqlMicrosoftConditionalAccessNamedLocations).GetIpLocations),
		func(r *mqlMicrosoftConditionalAccessIpNamedLocation) string { return r.Id.Data })
}

func initMicrosoftConditionalAccessCountryNamedLocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftConditionalAccessCountryNamedLocation, args,
		namedLocationsList(runtime, (*mqlMicrosoftConditionalAccessNamedLocations).GetCountryLocations),
		func(r *mqlMicrosoftConditionalAccessCountryNamedLocation) string { return r.Id.Data })
}

func initMicrosoftOauth2PermissionGrant(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftOauth2PermissionGrant, args,
		func() ([]any, error) {
			res, err := CreateResource(runtime, ResourceMicrosoft, map[string]*llx.RawData{})
			if err != nil {
				return nil, err
			}
			return listOf(res.(*mqlMicrosoft).GetOauth2PermissionGrants())
		},
		func(r *mqlMicrosoftOauth2PermissionGrant) string { return r.Id.Data })
}

func initMicrosoftSecurityRiskyUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftSecurityRiskyUser, args,
		securityList(runtime, (*mqlMicrosoftSecurity).GetRiskyUsers),
		func(r *mqlMicrosoftSecurityRiskyUser) string { return r.Id.Data })
}

func initMicrosoftSecurityRiskDetection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftSecurityRiskDetection, args,
		securityList(runtime, (*mqlMicrosoftSecurity).GetRiskDetections),
		func(r *mqlMicrosoftSecurityRiskDetection) string { return r.Id.Data })
}

func initMicrosoftSecurityRiskyServicePrincipal(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftSecurityRiskyServicePrincipal, args,
		securityList(runtime, (*mqlMicrosoftSecurity).GetRiskyServicePrincipals),
		func(r *mqlMicrosoftSecurityRiskyServicePrincipal) string { return r.Id.Data })
}

func initMicrosoftSecurityServicePrincipalRiskDetection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftSecurityServicePrincipalRiskDetection, args,
		securityList(runtime, (*mqlMicrosoftSecurity).GetServicePrincipalRiskDetections),
		func(r *mqlMicrosoftSecurityServicePrincipalRiskDetection) string { return r.Id.Data })
}

func initMicrosoftSecurityAlert(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftSecurityAlert, args,
		securityList(runtime, (*mqlMicrosoftSecurity).GetAlerts),
		func(r *mqlMicrosoftSecurityAlert) string { return r.Id.Data })
}

func initMicrosoftSecurityInformationProtectionSensitivityLabel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftSecurityInformationProtectionSensitivityLabel, args,
		func() ([]any, error) {
			sec, err := microsoftSecurityParent(runtime)
			if err != nil {
				return nil, err
			}
			ip := sec.GetInformationProtection()
			if ip.Error != nil {
				return nil, ip.Error
			}
			if ip.Data == nil {
				return nil, nil
			}
			return listOf(ip.Data.GetSensitivityLabels())
		},
		func(r *mqlMicrosoftSecurityInformationProtectionSensitivityLabel) string { return r.Id.Data })
}

func initMicrosoftPoliciesActivityBasedTimeoutPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftPoliciesActivityBasedTimeoutPolicy, args,
		policiesList(runtime, (*mqlMicrosoftPolicies).GetActivityBasedTimeoutPolicies),
		func(r *mqlMicrosoftPoliciesActivityBasedTimeoutPolicy) string { return r.Id.Data })
}

func initMicrosoftPoliciesTokenLifetimePolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftPoliciesTokenLifetimePolicy, args,
		policiesList(runtime, (*mqlMicrosoftPolicies).GetTokenLifetimePolicies),
		func(r *mqlMicrosoftPoliciesTokenLifetimePolicy) string { return r.Id.Data })
}

func initMicrosoftPoliciesClaimsMappingPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftPoliciesClaimsMappingPolicy, args,
		policiesList(runtime, (*mqlMicrosoftPolicies).GetClaimsMappingPolicies),
		func(r *mqlMicrosoftPoliciesClaimsMappingPolicy) string { return r.Id.Data })
}

func initMicrosoftPoliciesTokenIssuancePolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftPoliciesTokenIssuancePolicy, args,
		policiesList(runtime, (*mqlMicrosoftPolicies).GetTokenIssuancePolicies),
		func(r *mqlMicrosoftPoliciesTokenIssuancePolicy) string { return r.Id.Data })
}

func initMicrosoftPoliciesHomeRealmDiscoveryPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromParentList(ResourceMicrosoftPoliciesHomeRealmDiscoveryPolicy, args,
		policiesList(runtime, (*mqlMicrosoftPolicies).GetHomeRealmDiscoveryPolicies),
		func(r *mqlMicrosoftPoliciesHomeRealmDiscoveryPolicy) string { return r.Id.Data })
}
