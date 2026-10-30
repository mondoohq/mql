// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// securityPerimeters lists the network security perimeters in the subscription.
// The perimeter is the isolation boundary; its profiles and associations are
// resolved lazily so a listing query stays cheap.
func (a *mqlAzureSubscriptionNetworkService) securityPerimeters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewSecurityPerimetersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListBySubscriptionPager(&network.SecurityPerimetersClientListBySubscriptionOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, nsp := range page.Value {
			if nsp == nil {
				continue
			}
			var perimeterGuid, provisioningState string
			if nsp.Properties != nil {
				perimeterGuid = convert.ToValue(nsp.Properties.PerimeterGUID)
				if nsp.Properties.ProvisioningState != nil {
					provisioningState = string(*nsp.Properties.ProvisioningState)
				}
			}
			mqlNsp, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceSecurityPerimeter,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(nsp.ID),
					"name":              llx.StringDataPtr(nsp.Name),
					"location":          llx.StringDataPtr(nsp.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(nsp.Tags), types.String),
					"type":              llx.StringDataPtr(nsp.Type),
					"perimeterGuid":     llx.StringData(perimeterGuid),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(nsp.SystemData)
			if err != nil {
				return nil, err
			}
			mqlNsp.(*mqlAzureSubscriptionNetworkServiceSecurityPerimeter).cacheSystemData = sysData
			res = append(res, mqlNsp)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceSecurityPerimeterInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeter) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeter) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// profiles resolves the access-rule profiles defined on the perimeter. The
// list API is scoped to the perimeter, so we parse the resource group and
// perimeter name out of the perimeter's resource ID.
func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeter) profiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	nspName, err := resourceID.Component("networkSecurityPerimeters")
	if err != nil {
		return nil, err
	}
	client, err := network.NewSecurityPerimeterProfilesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, nspName, &network.SecurityPerimeterProfilesClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, profile := range page.Value {
			if profile == nil {
				continue
			}
			mqlProfile, err := azureNspProfileToMql(a.MqlRuntime, *profile)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlProfile)
		}
	}
	return res, nil
}

// associations resolves the resource associations that place PaaS resources
// inside the perimeter. Each association records the access mode enforced on
// the resource and the profile it is bound to.
func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeter) associations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	nspName, err := resourceID.Component("networkSecurityPerimeters")
	if err != nil {
		return nil, err
	}
	client, err := network.NewSecurityPerimeterAssociationsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, nspName, &network.SecurityPerimeterAssociationsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, assoc := range page.Value {
			if assoc == nil {
				continue
			}
			var accessMode, hasProvisioningIssues, provisioningState, resourceId string
			var profileId *string
			if assoc.Properties != nil {
				if assoc.Properties.AccessMode != nil {
					accessMode = string(*assoc.Properties.AccessMode)
				}
				hasProvisioningIssues = convert.ToValue(assoc.Properties.HasProvisioningIssues)
				if assoc.Properties.ProvisioningState != nil {
					provisioningState = string(*assoc.Properties.ProvisioningState)
				}
				if assoc.Properties.PrivateLinkResource != nil {
					resourceId = convert.ToValue(assoc.Properties.PrivateLinkResource.ID)
				}
				if assoc.Properties.Profile != nil {
					profileId = assoc.Properties.Profile.ID
				}
			}
			mqlAssoc, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceSecurityPerimeterAssociation,
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(assoc.ID),
					"name":                  llx.StringDataPtr(assoc.Name),
					"type":                  llx.StringDataPtr(assoc.Type),
					"accessMode":            llx.StringData(accessMode),
					"hasProvisioningIssues": llx.StringData(hasProvisioningIssues),
					"provisioningState":     llx.StringData(provisioningState),
					"resourceId":            llx.StringData(resourceId),
				})
			if err != nil {
				return nil, err
			}
			mqlAssoc.(*mqlAzureSubscriptionNetworkServiceSecurityPerimeterAssociation).cacheProfileId = profileId
			res = append(res, mqlAssoc)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeterProfile) id() (string, error) {
	return a.Id.Data, nil
}

// azureNspProfileToMql maps a perimeter profile into its MQL resource. It is
// shared by the perimeter's profile listing and the association's profile
// cross-reference so both paths produce identical resources.
func azureNspProfileToMql(runtime *plugin.Runtime, profile network.NspProfile) (*mqlAzureSubscriptionNetworkServiceSecurityPerimeterProfile, error) {
	var accessRulesVersion, diagnosticSettingsVersion string
	if profile.Properties != nil {
		accessRulesVersion = convert.ToValue(profile.Properties.AccessRulesVersion)
		diagnosticSettingsVersion = convert.ToValue(profile.Properties.DiagnosticSettingsVersion)
	}
	mqlProfile, err := CreateResource(runtime, ResourceAzureSubscriptionNetworkServiceSecurityPerimeterProfile,
		map[string]*llx.RawData{
			"id":                        llx.StringDataPtr(profile.ID),
			"name":                      llx.StringDataPtr(profile.Name),
			"type":                      llx.StringDataPtr(profile.Type),
			"accessRulesVersion":        llx.StringData(accessRulesVersion),
			"diagnosticSettingsVersion": llx.StringData(diagnosticSettingsVersion),
		})
	if err != nil {
		return nil, err
	}
	return mqlProfile.(*mqlAzureSubscriptionNetworkServiceSecurityPerimeterProfile), nil
}

// accessRules resolves the inbound and outbound access rules for the profile.
// The list API is scoped to (resource group, perimeter, profile), all of which
// are recoverable from the profile's resource ID.
func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeterProfile) accessRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	nspName, err := resourceID.Component("networkSecurityPerimeters")
	if err != nil {
		return nil, err
	}
	profileName, err := resourceID.Component("profiles")
	if err != nil {
		return nil, err
	}
	client, err := network.NewSecurityPerimeterAccessRulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, nspName, profileName, &network.SecurityPerimeterAccessRulesClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			direction, provisioningState, addressPrefixes, fqdns, subscriptions, serviceTags, emailAddresses := nspAccessRuleFields(rule.Properties)
			mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceSecurityPerimeterAccessRule,
				map[string]*llx.RawData{
					"id":                        llx.StringDataPtr(rule.ID),
					"name":                      llx.StringDataPtr(rule.Name),
					"type":                      llx.StringDataPtr(rule.Type),
					"direction":                 llx.StringData(direction),
					"provisioningState":         llx.StringData(provisioningState),
					"addressPrefixes":           llx.ArrayData(addressPrefixes, types.String),
					"fullyQualifiedDomainNames": llx.ArrayData(fqdns, types.String),
					"subscriptions":             llx.ArrayData(subscriptions, types.String),
					"serviceTags":               llx.ArrayData(serviceTags, types.String),
					"emailAddresses":            llx.ArrayData(emailAddresses, types.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeterAccessRule) id() (string, error) {
	return a.Id.Data, nil
}

// nspAccessRuleFields flattens the scalar and list fields of a perimeter access
// rule from its SDK properties. The SDK models subscriptions as a slice of
// {ID} structs, so we surface only their ARM IDs. A nil props (or any nil
// pointer within it) yields empty values so a sparsely populated rule still
// maps cleanly.
func nspAccessRuleFields(props *network.NspAccessRuleProperties) (direction, provisioningState string, addressPrefixes, fqdns, subscriptions, serviceTags, emailAddresses []any) {
	addressPrefixes = []any{}
	fqdns = []any{}
	subscriptions = []any{}
	serviceTags = []any{}
	emailAddresses = []any{}
	if props == nil {
		return
	}
	if props.Direction != nil {
		direction = string(*props.Direction)
	}
	if props.ProvisioningState != nil {
		provisioningState = string(*props.ProvisioningState)
	}
	addressPrefixes = strPtrsToAny(props.AddressPrefixes)
	fqdns = strPtrsToAny(props.FullyQualifiedDomainNames)
	serviceTags = strPtrsToAny(props.ServiceTags)
	emailAddresses = strPtrsToAny(props.EmailAddresses)
	for _, sub := range props.Subscriptions {
		if sub != nil && sub.ID != nil {
			subscriptions = append(subscriptions, *sub.ID)
		}
	}
	return
}

type mqlAzureSubscriptionNetworkServiceSecurityPerimeterAssociationInternal struct {
	cacheProfileId *string
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeterAssociation) id() (string, error) {
	return a.Id.Data, nil
}

// profile resolves the perimeter profile this association binds its resource
// to. The profile lives in the same perimeter, so we fetch it by name using
// the components parsed from the cached profile ID. Returns null when the
// association is not bound to a profile.
func (a *mqlAzureSubscriptionNetworkServiceSecurityPerimeterAssociation) profile() (*mqlAzureSubscriptionNetworkServiceSecurityPerimeterProfile, error) {
	if a.cacheProfileId == nil || *a.cacheProfileId == "" {
		a.Profile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(*a.cacheProfileId)
	if err != nil {
		return nil, err
	}
	nspName, err := resourceID.Component("networkSecurityPerimeters")
	if err != nil {
		return nil, err
	}
	profileName, err := resourceID.Component("profiles")
	if err != nil {
		return nil, err
	}
	client, err := network.NewSecurityPerimeterProfilesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(ctx, resourceID.ResourceGroup, nspName, profileName, &network.SecurityPerimeterProfilesClientGetOptions{})
	if err != nil {
		return nil, err
	}
	return azureNspProfileToMql(a.MqlRuntime, resp.NspProfile)
}
