// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// Tenant-wide settings: the management group hierarchy settings on the tenant
// root group, and the subscription policy that governs moving subscriptions
// between tenants. Both are singletons that Azure only materializes once an
// administrator changes them; before that the read is a 404 and Azure applies
// its defaults. The provider reports those effective defaults rather than null,
// because null would leave a check unable to tell "never configured" from
// "could not read", and only the second is unknown.

// isAzureNotFound reports whether err is an ARM 404.
func isAzureNotFound(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}

// hierarchySettingsValues is what azure.managementGroup.hierarchySettings
// reports, after Azure's defaults are applied.
type hierarchySettingsValues struct {
	id                                   string
	tenantID                             string
	defaultManagementGroup               string
	requireAuthorizationForGroupCreation bool
}

// effectiveHierarchySettings applies Azure's defaults to the hierarchy settings
// of the tenant whose root group is tenantID. props is nil when the tenant
// never set them (the read was a 404). Without a default group, Azure places
// new subscriptions in the root group, so that is the effective default; the
// authorization requirement is off unless it was turned on.
func effectiveHierarchySettings(tenantID string, props *armmanagementgroups.HierarchySettingsProperties) hierarchySettingsValues {
	rootID := managementGroupIDPrefix + tenantID
	res := hierarchySettingsValues{
		id:                     rootID + "/settings/default",
		tenantID:               tenantID,
		defaultManagementGroup: rootID,
	}
	if props == nil {
		return res
	}
	if v := convert.ToValue(props.DefaultManagementGroup); v != "" {
		res.defaultManagementGroup = v
	}
	res.requireAuthorizationForGroupCreation = convert.ToValue(props.RequireAuthorizationForGroupCreation)
	return res
}

// rootTenantID returns the tenant whose root group holds this group's hierarchy
// settings. The root group's name is the tenant ID.
func (a *mqlAzureManagementGroup) rootTenantID() string {
	if a.TenantId.Data != "" {
		return a.TenantId.Data
	}
	if a.IsRoot.Data {
		return a.Name.Data
	}
	return ""
}

func (a *mqlAzureManagementGroup) hierarchySettings() (*mqlAzureManagementGroupHierarchySettings, error) {
	tenantID := a.rootTenantID()
	if tenantID == "" {
		return nil, errors.New("cannot determine the tenant of management group " + a.Name.Data)
	}

	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := armmanagementgroups.NewHierarchySettingsClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	var props *armmanagementgroups.HierarchySettingsProperties
	resp, err := client.Get(context.Background(), tenantID, nil)
	switch {
	case err == nil:
		props = resp.Properties
	case isAzureNotFound(err):
		// Never configured: Azure applies the defaults.
	default:
		return nil, classifyAzureRefusal(err, "Microsoft.Management/managementGroups/settings/read")
	}

	v := effectiveHierarchySettings(tenantID, props)
	r, err := CreateResource(a.MqlRuntime, ResourceAzureManagementGroupHierarchySettings, map[string]*llx.RawData{
		"__id":                                 llx.StringData(v.id),
		"id":                                   llx.StringData(v.id),
		"tenantId":                             llx.StringData(v.tenantID),
		"defaultManagementGroup":               llx.StringData(v.defaultManagementGroup),
		"requireAuthorizationForGroupCreation": llx.BoolData(v.requireAuthorizationForGroupCreation),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureManagementGroupHierarchySettings), nil
}

// subscriptionPolicyID is the resource ID ARM gives the tenant's subscription
// policy.
const subscriptionPolicyID = "providers/Microsoft.Subscription/policies/default"

// subscriptionPolicyValues is what azure.subscriptionTenantPolicy reports, after
// Azure's defaults are applied.
type subscriptionPolicyValues struct {
	tenantID           string
	blockLeaving       bool
	blockInto          bool
	exemptedPrincipals []any
}

// effectiveSubscriptionPolicy applies Azure's defaults to the tenant's
// subscription policy. props is nil when the tenant never set one (the read
// was a 404): then nothing is blocked and no one is exempt. fallbackTenantID
// names the tenant when the response does not.
func effectiveSubscriptionPolicy(fallbackTenantID string, props *armsubscription.TenantPolicy) subscriptionPolicyValues {
	res := subscriptionPolicyValues{
		tenantID:           fallbackTenantID,
		exemptedPrincipals: []any{},
	}
	if props == nil {
		return res
	}
	if v := convert.ToValue(props.PolicyID); v != "" {
		res.tenantID = v
	}
	res.blockLeaving = convert.ToValue(props.BlockSubscriptionsLeavingTenant)
	res.blockInto = convert.ToValue(props.BlockSubscriptionsIntoTenant)
	for _, p := range props.ExemptedPrincipals {
		if p != nil && *p != "" {
			res.exemptedPrincipals = append(res.exemptedPrincipals, *p)
		}
	}
	return res
}

func (a *mqlAzure) subscriptionTenantPolicy() (*mqlAzureSubscriptionTenantPolicy, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := armsubscription.NewPolicyClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	var props *armsubscription.TenantPolicy
	resp, err := client.GetPolicyForTenant(context.Background(), nil)
	switch {
	case err == nil:
		props = resp.Properties
	case isAzureNotFound(err):
		// Never configured: Azure applies the defaults.
	default:
		return nil, classifyAzureRefusal(err, "Microsoft.Subscription/Policies/default/read")
	}

	fallbackTenantID := ""
	if props == nil || convert.ToValue(props.PolicyID) == "" {
		fallbackTenantID, err = connectedTenantID(a)
		if err != nil {
			return nil, err
		}
	}

	v := effectiveSubscriptionPolicy(fallbackTenantID, props)
	r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionTenantPolicy, map[string]*llx.RawData{
		"__id":                            llx.StringData(subscriptionPolicyID),
		"id":                              llx.StringData(subscriptionPolicyID),
		"tenantId":                        llx.StringData(v.tenantID),
		"blockSubscriptionsLeavingTenant": llx.BoolData(v.blockLeaving),
		"blockSubscriptionsIntoTenant":    llx.BoolData(v.blockInto),
		"exemptedPrincipals":              llx.ArrayData(v.exemptedPrincipals, types.String),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionTenantPolicy), nil
}

// connectedTenantID returns the tenant of the connected subscription.
func connectedTenantID(a *mqlAzure) (string, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return "", err
	}
	tenant := r.(*mqlAzureSubscription).GetTenantId()
	return tenant.Data, tenant.Error
}

func (a *mqlAzureManagementGroupHierarchySettings) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionTenantPolicy) id() (string, error) {
	return a.Id.Data, nil
}
