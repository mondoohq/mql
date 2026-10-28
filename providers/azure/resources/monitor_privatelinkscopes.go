// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	monitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v3"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionMonitorServicePrivateLinkScopeInternal struct {
	cachePrivateEndpointConnections []*monitor.PrivateEndpointConnection
	cacheSystemData                 any
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScope) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScopeScopedResource) id() (string, error) {
	return a.Id.Data, nil
}

// accessModeExclusionsToDicts converts the per-connection access mode
// overrides of a private link scope into dicts, skipping nil entries.
func accessModeExclusionsToDicts(exclusions []*monitor.AccessModeSettingsExclusion) []any {
	res := []any{}
	for _, e := range exclusions {
		if e == nil {
			continue
		}
		res = append(res, map[string]any{
			"privateEndpointConnectionName": convert.ToValue(e.PrivateEndpointConnectionName),
			"ingestionAccessMode":           convert.ToValue(stringEnumPtr(e.IngestionAccessMode)),
			"queryAccessMode":               convert.ToValue(stringEnumPtr(e.QueryAccessMode)),
		})
	}
	return res
}

// privateLinkScopeArgs maps an Azure Monitor private link scope onto the
// fields of azure.subscription.monitorService.privateLinkScope. The access
// modes read as null when the scope reports no access mode settings.
func privateLinkScopeArgs(scope *monitor.AzureMonitorPrivateLinkScope) map[string]*llx.RawData {
	var provisioningState, ingestionAccessMode, queryAccessMode *string
	exclusions := []any{}
	if p := scope.Properties; p != nil {
		provisioningState = stringEnumPtr(p.ProvisioningState)
		if s := p.AccessModeSettings; s != nil {
			ingestionAccessMode = stringEnumPtr(s.IngestionAccessMode)
			queryAccessMode = stringEnumPtr(s.QueryAccessMode)
			exclusions = accessModeExclusionsToDicts(s.Exclusions)
		}
	}
	return map[string]*llx.RawData{
		"id":                   llx.StringDataPtr(scope.ID),
		"name":                 llx.StringDataPtr(scope.Name),
		"location":             llx.StringDataPtr(scope.Location),
		"tags":                 llx.MapData(convert.PtrMapStrToInterface(scope.Tags), types.String),
		"provisioningState":    llx.StringDataPtr(provisioningState),
		"ingestionAccessMode":  llx.StringDataPtr(ingestionAccessMode),
		"queryAccessMode":      llx.StringDataPtr(queryAccessMode),
		"accessModeExclusions": llx.ArrayData(exclusions, types.Dict),
	}
}

func newPrivateLinkScopeResource(runtime *plugin.Runtime, scope *monitor.AzureMonitorPrivateLinkScope) (*mqlAzureSubscriptionMonitorServicePrivateLinkScope, error) {
	res, err := CreateResource(runtime, ResourceAzureSubscriptionMonitorServicePrivateLinkScope, privateLinkScopeArgs(scope))
	if err != nil {
		return nil, err
	}
	mqlScope := res.(*mqlAzureSubscriptionMonitorServicePrivateLinkScope)
	if scope.Properties != nil {
		mqlScope.cachePrivateEndpointConnections = scope.Properties.PrivateEndpointConnections
	}
	sysData, err := convert.JsonToDict(scope.SystemData)
	if err != nil {
		return nil, err
	}
	mqlScope.cacheSystemData = sysData
	return mqlScope, nil
}

func (a *mqlAzureSubscriptionMonitorService) privateLinkScopes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := monitor.NewPrivateLinkScopesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Insights/privateLinkScopes/read")
		}
		for _, scope := range page.Value {
			if scope == nil {
				continue
			}
			mqlScope, err := newPrivateLinkScopeResource(a.MqlRuntime, scope)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlScope)
		}
	}
	return res, nil
}

// initAzureSubscriptionMonitorServicePrivateLinkScope resolves a private link
// scope by its ARM id, from the subscription's list when it is there and with
// a Get when it is not (a scope in another subscription).
func initAzureSubscriptionMonitorServicePrivateLinkScope(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil {
		return nil, nil, missingResourceID(ResourceAzureSubscriptionMonitorServicePrivateLinkScope)
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, missingResourceID(ResourceAzureSubscriptionMonitorServicePrivateLinkScope)
	}

	if scope := lookupInServiceList(runtime, ResourceAzureSubscriptionMonitorService,
		func(s *mqlAzureSubscriptionMonitorService) *plugin.TValue[[]any] { return s.GetPrivateLinkScopes() },
		id); scope != nil {
		return args, scope, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := resourceID.Component("privateLinkScopes")
	if err != nil {
		return nil, nil, err
	}
	client, err := monitor.NewPrivateLinkScopesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), resourceID.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, classifyAzureRefusal(err, "Microsoft.Insights/privateLinkScopes/read")
	}
	mqlScope, err := newPrivateLinkScopeResource(runtime, &resp.AzureMonitorPrivateLinkScope)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlScope, nil
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScope) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScope) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// scopedResourceArgs maps a private link scoped resource onto the fields of
// azure.subscription.monitorService.privateLinkScope.scopedResource.
func scopedResourceArgs(sr *monitor.ScopedResource) map[string]*llx.RawData {
	var kind, provisioningState, subscriptionLocation, linkedResourceID *string
	if p := sr.Properties; p != nil {
		kind = stringEnumPtr(p.Kind)
		provisioningState = stringEnumPtr(p.ProvisioningState)
		subscriptionLocation = p.SubscriptionLocation
		linkedResourceID = p.LinkedResourceID
	}
	return map[string]*llx.RawData{
		"id":                   llx.StringDataPtr(sr.ID),
		"name":                 llx.StringDataPtr(sr.Name),
		"kind":                 llx.StringDataPtr(kind),
		"provisioningState":    llx.StringDataPtr(provisioningState),
		"subscriptionLocation": llx.StringDataPtr(subscriptionLocation),
		"linkedResourceId":     llx.StringDataPtr(linkedResourceID),
	}
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScope) scopedResources() ([]any, error) {
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	client, err := monitor.NewPrivateLinkScopedResourcesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	res := []any{}
	pager := client.NewListByPrivateLinkScopePager(resourceID.ResourceGroup, a.Name.Data, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Insights/privateLinkScopes/scopedResources/read")
		}
		for _, sr := range page.Value {
			if sr == nil {
				continue
			}
			mqlSr, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServicePrivateLinkScopeScopedResource, scopedResourceArgs(sr))
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSr)
		}
	}
	return res, nil
}

// Kinds of Azure Monitor resource a private link scope can link to that have a
// typed resource in this provider.
const (
	monitorLinkedWorkspace          = "workspace"
	monitorLinkedApplicationInsight = "applicationInsight"
)

// monitorLinkedResourceKind reports which typed resource a scoped resource's
// linked resource ID names, or "" when it is neither a Log Analytics
// workspace nor an Application Insights component (for example a data
// collection endpoint). ARM ids are case-insensitive, and Azure Monitor
// returns the provider namespace in lowercase.
func monitorLinkedResourceKind(linkedResourceID string) string {
	lower := strings.ToLower(linkedResourceID)
	switch {
	case strings.Contains(lower, "/providers/microsoft.operationalinsights/workspaces/"):
		return monitorLinkedWorkspace
	case strings.Contains(lower, "/providers/microsoft.insights/components/"):
		return monitorLinkedApplicationInsight
	}
	return ""
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScopeScopedResource) workspace() (*mqlAzureSubscriptionMonitorServiceWorkspace, error) {
	id := a.LinkedResourceId.Data
	if monitorLinkedResourceKind(id) != monitorLinkedWorkspace {
		a.Workspace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspace, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceWorkspace), nil
}

func (a *mqlAzureSubscriptionMonitorServicePrivateLinkScopeScopedResource) applicationInsight() (*mqlAzureSubscriptionMonitorServiceApplicationInsight, error) {
	id := a.LinkedResourceId.Data
	if monitorLinkedResourceKind(id) != monitorLinkedApplicationInsight {
		a.ApplicationInsight.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if ai := lookupInServiceList(a.MqlRuntime, ResourceAzureSubscriptionMonitorService,
		func(s *mqlAzureSubscriptionMonitorService) *plugin.TValue[[]any] { return s.GetApplicationInsights() },
		id); ai != nil {
		if mqlAI, ok := ai.(*mqlAzureSubscriptionMonitorServiceApplicationInsight); ok {
			return mqlAI, nil
		}
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceApplicationInsight, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceApplicationInsight), nil
}

// privateLinkScopeIDsFromScopedResources returns the ARM ids of the private
// link scopes a workspace is attached to, in order and without duplicates.
// Each entry's resource ID names either the scope or one of its scoped
// resources (`<scope id>/scopedResources/<name>`); the latter is cut back to
// the scope.
func privateLinkScopeIDsFromScopedResources(entries []*armoperationalinsights.PrivateLinkScopedResource) []string {
	res := []string{}
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e == nil || e.ResourceID == nil || *e.ResourceID == "" {
			continue
		}
		id := *e.ResourceID
		if i := strings.Index(strings.ToLower(id), "/scopedresources/"); i >= 0 {
			id = id[:i]
		}
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		res = append(res, id)
	}
	return res
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspace) privateLinkScopes() ([]any, error) {
	res := []any{}
	for _, id := range privateLinkScopeIDsFromScopedResources(a.cachePrivateLinkScopedResources) {
		scope, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServicePrivateLinkScope, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, scope)
	}
	return res, nil
}
