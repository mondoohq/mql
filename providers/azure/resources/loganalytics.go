// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionMonitorServiceWorkspaceInternal struct {
	cacheCapping                    *armoperationalinsights.WorkspaceCapping
	cacheFeatures                   *armoperationalinsights.WorkspaceFeatures
	cachePrivateLinkScopedResources []*armoperationalinsights.PrivateLinkScopedResource
	cacheReplication                *armoperationalinsights.WorkspaceReplicationProperties
	cacheFailover                   *armoperationalinsights.WorkspaceFailoverProperties
	cacheSystemData                 any
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionMonitorServiceApplicationInsightInternal struct {
	cacheWorkspaceResourceId string
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspace) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMonitorService) workspaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armoperationalinsights.NewWorkspacesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ws := range page.Value {
			if ws == nil {
				continue
			}
			mqlWs, err := createWorkspaceResource(a.MqlRuntime, ws)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlWs)
		}
	}
	return res, nil
}

// parseAzureDateString parses an Azure date string to *llx.RawData containing a time value.
func parseAzureDateString(s *string) *llx.RawData {
	if s == nil || *s == "" {
		return llx.NilData
	}
	// Azure returns dates in RFC3339 format
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		// Try RFC3339Nano as fallback
		t, err = time.Parse(time.RFC3339Nano, *s)
		if err != nil {
			log.Warn().Str("value", *s).Msg("failed to parse Azure date string")
			return llx.NilData
		}
	}
	return llx.TimeData(t)
}

func createWorkspaceResource(runtime *plugin.Runtime, ws *armoperationalinsights.Workspace) (*mqlAzureSubscriptionMonitorServiceWorkspace, error) {
	props := ws.Properties
	if props == nil {
		props = &armoperationalinsights.WorkspaceProperties{}
	}

	var skuName string
	var skuCapacityReservationLevel int64
	if props.SKU != nil {
		if props.SKU.Name != nil {
			skuName = string(*props.SKU.Name)
		}
		if props.SKU.CapacityReservationLevel != nil {
			skuCapacityReservationLevel = int64(*props.SKU.CapacityReservationLevel)
		}
	}

	var retentionInDays int64
	if props.RetentionInDays != nil {
		retentionInDays = int64(*props.RetentionInDays)
	}

	var publicNetworkAccessForIngestion, publicNetworkAccessForQuery string
	if props.PublicNetworkAccessForIngestion != nil {
		publicNetworkAccessForIngestion = string(*props.PublicNetworkAccessForIngestion)
	}
	if props.PublicNetworkAccessForQuery != nil {
		publicNetworkAccessForQuery = string(*props.PublicNetworkAccessForQuery)
	}

	var provisioningState string
	if props.ProvisioningState != nil {
		provisioningState = string(*props.ProvisioningState)
	}

	identity, err := convert.JsonToDict(ws.Identity)
	if err != nil {
		return nil, err
	}

	wsArgs := map[string]*llx.RawData{
		"id":                                  llx.StringDataPtr(ws.ID),
		"name":                                llx.StringDataPtr(ws.Name),
		"location":                            llx.StringDataPtr(ws.Location),
		"type":                                llx.StringDataPtr(ws.Type),
		"tags":                                llx.MapData(convert.PtrMapStrToInterface(ws.Tags), types.String),
		"skuName":                             llx.StringData(skuName),
		"skuCapacityReservationLevel":         llx.IntData(skuCapacityReservationLevel),
		"retentionInDays":                     llx.IntData(retentionInDays),
		"publicNetworkAccessForIngestion":     llx.StringData(publicNetworkAccessForIngestion),
		"publicNetworkAccessForQuery":         llx.StringData(publicNetworkAccessForQuery),
		"forceCmkForQuery":                    llx.BoolDataPtr(props.ForceCmkForQuery),
		"createdDate":                         llx.TimeDataPtr(props.CreatedDate),
		"modifiedDate":                        llx.TimeDataPtr(props.ModifiedDate),
		"provisioningState":                   llx.StringData(provisioningState),
		"customerId":                          llx.StringDataPtr(props.CustomerID),
		"identity":                            llx.DictData(identity),
		"defaultDataCollectionRuleResourceId": llx.StringDataPtr(props.DefaultDataCollectionRuleResourceID),
	}
	wsIdentity := orZero(ws.Identity)
	if err := setResourceIdentity(runtime, wsArgs, sortedUserAssignedIdentityIDs(wsIdentity.UserAssignedIdentities),
		identityType(wsIdentity.Type), identityPrincipalId(wsIdentity.PrincipalID), identityTenantId(wsIdentity.TenantID)); err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionMonitorServiceWorkspace, wsArgs)
	if err != nil {
		return nil, err
	}

	mqlWs := resource.(*mqlAzureSubscriptionMonitorServiceWorkspace)
	mqlWs.cacheCapping = props.WorkspaceCapping
	mqlWs.cacheFeatures = props.Features
	mqlWs.cachePrivateLinkScopedResources = props.PrivateLinkScopedResources
	mqlWs.cacheReplication = props.Replication
	mqlWs.cacheFailover = props.Failover
	sysData, err := convert.JsonToDict(ws.SystemData)
	if err != nil {
		return nil, err
	}
	mqlWs.cacheSystemData = sysData

	return mqlWs, nil
}

// initAzureSubscriptionMonitorServiceWorkspace fetches a workspace by ID for cross-ref resolution.
func initAzureSubscriptionMonitorServiceWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok || idRaw == nil {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	// The subscription's list already holds this workspace, and holds it for every
	// other reference to it too. Only pay for a Get when the list cannot
	// answer -- a reference into another subscription, or one since deleted.
	if ws := lookupInServiceList(runtime, ResourceAzureSubscriptionMonitorService,
		func(s *mqlAzureSubscriptionMonitorService) *plugin.TValue[[]any] { return s.GetWorkspaces() },
		id); ws != nil {
		return args, ws, nil
	}

	client, err := armoperationalinsights.NewWorkspacesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Get(ctx, resourceID.ResourceGroup, workspaceName, nil)
	if err != nil {
		return nil, nil, err
	}

	mqlWs, err := createWorkspaceResource(runtime, &resp.Workspace)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlWs, nil
}

// capping builds the capping sub-resource from cached data.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) capping() (*mqlAzureSubscriptionMonitorServiceWorkspaceCapping, error) {
	cap := a.cacheCapping
	if cap == nil {
		a.Capping.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var dailyQuotaGb float64
	if cap.DailyQuotaGb != nil {
		dailyQuotaGb = *cap.DailyQuotaGb
	}

	var dataIngestionStatus string
	if cap.DataIngestionStatus != nil {
		dataIngestionStatus = string(*cap.DataIngestionStatus)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceCapping,
		map[string]*llx.RawData{
			"id":                  llx.StringData(a.Id.Data + "/capping"),
			"dailyQuotaGb":        llx.FloatData(dailyQuotaGb),
			"dataIngestionStatus": llx.StringData(dataIngestionStatus),
			"quotaNextResetTime":  llx.StringDataPtr(cap.QuotaNextResetTime),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceWorkspaceCapping), nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceCapping) id() (string, error) {
	return a.Id.Data, nil
}

// features builds the features sub-resource from cached data.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) features() (*mqlAzureSubscriptionMonitorServiceWorkspaceFeatures, error) {
	feat := a.cacheFeatures
	if feat == nil {
		a.Features.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var associations []any
	for _, assoc := range feat.Associations {
		if assoc != nil {
			associations = append(associations, *assoc)
		}
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceFeatures,
		map[string]*llx.RawData{
			"id":               llx.StringData(a.Id.Data + "/features"),
			"disableLocalAuth": llx.BoolDataPtr(feat.DisableLocalAuth),
			"enableDataExport": llx.BoolDataPtr(feat.EnableDataExport),
			"enableLogAccessUsingOnlyResourcePermissions": llx.BoolDataPtr(feat.EnableLogAccessUsingOnlyResourcePermissions),
			"immediatePurgeDataOn30Days":                  llx.BoolDataPtr(feat.ImmediatePurgeDataOn30Days),
			"clusterResourceId":                           llx.StringDataPtr(feat.ClusterResourceID),
			"unifiedSentinelBillingOnly":                  llx.BoolDataPtr(feat.UnifiedSentinelBillingOnly),
			"associations":                                llx.ArrayData(associations, types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceWorkspaceFeatures), nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceFeatures) id() (string, error) {
	return a.Id.Data, nil
}

// privateLinkScopedResources returns the private link scoped resources as dicts.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) privateLinkScopedResources() ([]any, error) {
	var res []any
	for _, plsr := range a.cachePrivateLinkScopedResources {
		if plsr == nil {
			continue
		}
		d, err := convert.JsonToDict(plsr)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

// dataExports fetches data export rules for the workspace.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) dataExports() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, err
	}

	client, err := armoperationalinsights.NewDataExportsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByWorkspacePager(resourceID.ResourceGroup, workspaceName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, de := range page.Value {
			if de == nil {
				continue
			}

			var enabled bool
			var destinationResourceId string
			var tableNames []any
			var createdDate, lastModifiedDate *string
			if de.Properties != nil {
				if de.Properties.Enable != nil {
					enabled = *de.Properties.Enable
				}
				if de.Properties.Destination != nil && de.Properties.Destination.ResourceID != nil {
					destinationResourceId = *de.Properties.Destination.ResourceID
				}
				createdDate = de.Properties.CreatedDate
				lastModifiedDate = de.Properties.LastModifiedDate
				for _, tn := range de.Properties.TableNames {
					if tn != nil {
						tableNames = append(tableNames, *tn)
					}
				}
			}

			mqlDe, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceDataExport,
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(de.ID),
					"name":                  llx.StringDataPtr(de.Name),
					"type":                  llx.StringDataPtr(de.Type),
					"enabled":               llx.BoolData(enabled),
					"tableNames":            llx.ArrayData(tableNames, types.String),
					"destinationResourceId": llx.StringData(destinationResourceId),
					"createdDate":           parseAzureDateString(createdDate),
					"lastModifiedDate":      parseAzureDateString(lastModifiedDate),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(de.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDe.(*mqlAzureSubscriptionMonitorServiceWorkspaceDataExport).cacheSystemData = sysData
			res = append(res, mqlDe)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMonitorServiceWorkspaceDataExportInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceDataExport) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceDataExport) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// linkedServices fetches linked services for the workspace.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) linkedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, err
	}

	client, err := armoperationalinsights.NewLinkedServicesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByWorkspacePager(resourceID.ResourceGroup, workspaceName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ls := range page.Value {
			if ls == nil {
				continue
			}

			var resourceId, writeAccessResourceId, provisioningState string
			if ls.Properties != nil {
				if ls.Properties.ResourceID != nil {
					resourceId = *ls.Properties.ResourceID
				}
				if ls.Properties.WriteAccessResourceID != nil {
					writeAccessResourceId = *ls.Properties.WriteAccessResourceID
				}
				if ls.Properties.ProvisioningState != nil {
					provisioningState = string(*ls.Properties.ProvisioningState)
				}
			}

			mqlLs, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceLinkedService,
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(ls.ID),
					"name":                  llx.StringDataPtr(ls.Name),
					"type":                  llx.StringDataPtr(ls.Type),
					"resourceId":            llx.StringData(resourceId),
					"writeAccessResourceId": llx.StringData(writeAccessResourceId),
					"provisioningState":     llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ls.SystemData)
			if err != nil {
				return nil, err
			}
			mqlLs.(*mqlAzureSubscriptionMonitorServiceWorkspaceLinkedService).cacheSystemData = sysData
			res = append(res, mqlLs)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMonitorServiceWorkspaceLinkedServiceInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceLinkedService) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceLinkedService) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// replication builds the replication sub-resource from cached data.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) replication() (*mqlAzureSubscriptionMonitorServiceWorkspaceReplication, error) {
	repl := a.cacheReplication
	if repl == nil {
		a.Replication.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var location, provisioningState string
	if repl.Location != nil {
		location = *repl.Location
	}
	if repl.ProvisioningState != nil {
		provisioningState = string(*repl.ProvisioningState)
	}

	createdDate := llx.NilData
	if repl.CreatedDate != nil {
		createdDate = llx.TimeDataPtr(repl.CreatedDate)
	}
	lastModifiedDate := llx.NilData
	if repl.LastModifiedDate != nil {
		lastModifiedDate = llx.TimeDataPtr(repl.LastModifiedDate)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceReplication,
		map[string]*llx.RawData{
			"id":                llx.StringData(a.Id.Data + "/replication"),
			"enabled":           llx.BoolDataPtr(repl.Enabled),
			"location":          llx.StringData(location),
			"createdDate":       createdDate,
			"lastModifiedDate":  lastModifiedDate,
			"provisioningState": llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceWorkspaceReplication), nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceReplication) id() (string, error) {
	return a.Id.Data, nil
}

// failover builds the failover sub-resource from cached data.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) failover() (*mqlAzureSubscriptionMonitorServiceWorkspaceFailover, error) {
	fo := a.cacheFailover
	if fo == nil {
		a.Failover.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var state string
	if fo.State != nil {
		state = string(*fo.State)
	}
	lastModifiedDate := llx.NilData
	if fo.LastModifiedDate != nil {
		lastModifiedDate = llx.TimeDataPtr(fo.LastModifiedDate)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceFailover,
		map[string]*llx.RawData{
			"id":               llx.StringData(a.Id.Data + "/failover"),
			"state":            llx.StringData(state),
			"lastModifiedDate": lastModifiedDate,
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceWorkspaceFailover), nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceFailover) id() (string, error) {
	return a.Id.Data, nil
}

// tables fetches all tables for the workspace.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) tables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, err
	}

	client, err := armoperationalinsights.NewTablesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByWorkspacePager(resourceID.ResourceGroup, workspaceName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}

			var plan, lastPlanModifiedDate, provisioningState string
			var retentionInDays, totalRetentionInDays, archiveRetentionInDays int64
			var retentionInDaysAsDefault, totalRetentionInDaysAsDefault bool
			var schema, restoredLogs, searchResults, resultStatistics any
			if t.Properties != nil {
				if t.Properties.Plan != nil {
					plan = string(*t.Properties.Plan)
				}
				if t.Properties.LastPlanModifiedDate != nil {
					lastPlanModifiedDate = *t.Properties.LastPlanModifiedDate
				}
				if t.Properties.ProvisioningState != nil {
					provisioningState = string(*t.Properties.ProvisioningState)
				}
				if t.Properties.RetentionInDays != nil {
					retentionInDays = int64(*t.Properties.RetentionInDays)
				}
				if t.Properties.TotalRetentionInDays != nil {
					totalRetentionInDays = int64(*t.Properties.TotalRetentionInDays)
				}
				if t.Properties.ArchiveRetentionInDays != nil {
					archiveRetentionInDays = int64(*t.Properties.ArchiveRetentionInDays)
				}
				if t.Properties.RetentionInDaysAsDefault != nil {
					retentionInDaysAsDefault = *t.Properties.RetentionInDaysAsDefault
				}
				if t.Properties.TotalRetentionInDaysAsDefault != nil {
					totalRetentionInDaysAsDefault = *t.Properties.TotalRetentionInDaysAsDefault
				}
				if t.Properties.Schema != nil {
					if d, err := convert.JsonToDict(t.Properties.Schema); err == nil {
						schema = d
					}
				}
				if t.Properties.RestoredLogs != nil {
					if d, err := convert.JsonToDict(t.Properties.RestoredLogs); err == nil {
						restoredLogs = d
					}
				}
				if t.Properties.SearchResults != nil {
					if d, err := convert.JsonToDict(t.Properties.SearchResults); err == nil {
						searchResults = d
					}
				}
				if t.Properties.ResultStatistics != nil {
					if d, err := convert.JsonToDict(t.Properties.ResultStatistics); err == nil {
						resultStatistics = d
					}
				}
			}

			mqlT, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceTable,
				map[string]*llx.RawData{
					"id":                            llx.StringDataPtr(t.ID),
					"name":                          llx.StringDataPtr(t.Name),
					"type":                          llx.StringDataPtr(t.Type),
					"plan":                          llx.StringData(plan),
					"retentionInDays":               llx.IntData(retentionInDays),
					"totalRetentionInDays":          llx.IntData(totalRetentionInDays),
					"archiveRetentionInDays":        llx.IntData(archiveRetentionInDays),
					"retentionInDaysAsDefault":      llx.BoolData(retentionInDaysAsDefault),
					"totalRetentionInDaysAsDefault": llx.BoolData(totalRetentionInDaysAsDefault),
					"lastPlanModifiedDate":          llx.StringData(lastPlanModifiedDate),
					"provisioningState":             llx.StringData(provisioningState),
					"schema":                        llx.DictData(schema),
					"restoredLogs":                  llx.DictData(restoredLogs),
					"searchResults":                 llx.DictData(searchResults),
					"resultStatistics":              llx.DictData(resultStatistics),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(t.SystemData)
			if err != nil {
				return nil, err
			}
			mqlT.(*mqlAzureSubscriptionMonitorServiceWorkspaceTable).cacheSystemData = sysData
			res = append(res, mqlT)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceTable) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionMonitorServiceWorkspaceTableInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceTable) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// flattenNspProperties lifts the nested "properties" object of a Network
// Security Perimeter access rule or provisioning issue into the top-level dict,
// so callers can query e.g. accessRules['direction'] instead of the
// SDK-shaped accessRules['properties']['direction']. The Azure NSP wire format
// is identical across resource providers, so the same flattening applies to
// every resource that exposes NSP configurations.
func flattenNspProperties(d any) any {
	m, ok := d.(map[string]any)
	if !ok {
		return d
	}
	props, ok := m["properties"].(map[string]any)
	if !ok {
		return d
	}
	out := make(map[string]any, len(m)+len(props)-1)
	for k, v := range m {
		if k == "properties" {
			continue
		}
		out[k] = v
	}
	maps.Copy(out, props)
	return out
}

// networkSecurityPerimeterConfigurations fetches all NSP configurations for the workspace.
func (a *mqlAzureSubscriptionMonitorServiceWorkspace) networkSecurityPerimeterConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	workspaceName, err := resourceID.Component("workspaces")
	if err != nil {
		return nil, err
	}

	client, err := armoperationalinsights.NewWorkspacesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListNSPPager(resourceID.ResourceGroup, workspaceName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list network security perimeter configurations due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, nsp := range page.Value {
			if nsp == nil {
				continue
			}

			args := map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(nsp.ID),
				"name":                      llx.StringDataPtr(nsp.Name),
				"type":                      llx.StringDataPtr(nsp.Type),
				"provisioningState":         llx.StringData(""),
				"perimeterId":               llx.StringData(""),
				"perimeterLocation":         llx.StringData(""),
				"perimeterGuid":             llx.StringData(""),
				"profileName":               llx.StringData(""),
				"accessRulesVersion":        llx.IntData(0),
				"diagnosticSettingsVersion": llx.IntData(0),
				"enabledLogCategories":      llx.ArrayData(nil, types.String),
				"accessRules":               llx.ArrayData(nil, types.Dict),
				"associationName":           llx.StringData(""),
				"associationAccessMode":     llx.StringData(""),
				"provisioningIssues":        llx.ArrayData(nil, types.Dict),
			}

			if props := nsp.Properties; props != nil {
				if props.ProvisioningState != nil {
					args["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
				}
				if props.NetworkSecurityPerimeter != nil {
					if props.NetworkSecurityPerimeter.ID != nil {
						args["perimeterId"] = llx.StringDataPtr(props.NetworkSecurityPerimeter.ID)
					}
					if props.NetworkSecurityPerimeter.Location != nil {
						args["perimeterLocation"] = llx.StringDataPtr(props.NetworkSecurityPerimeter.Location)
					}
					if props.NetworkSecurityPerimeter.PerimeterGUID != nil {
						args["perimeterGuid"] = llx.StringDataPtr(props.NetworkSecurityPerimeter.PerimeterGUID)
					}
				}
				if props.Profile != nil {
					if props.Profile.Name != nil {
						args["profileName"] = llx.StringDataPtr(props.Profile.Name)
					}
					if props.Profile.AccessRulesVersion != nil {
						args["accessRulesVersion"] = llx.IntData(int64(*props.Profile.AccessRulesVersion))
					}
					if props.Profile.DiagnosticSettingsVersion != nil {
						args["diagnosticSettingsVersion"] = llx.IntData(int64(*props.Profile.DiagnosticSettingsVersion))
					}
					var logCats []any
					for _, lc := range props.Profile.EnabledLogCategories {
						if lc != nil {
							logCats = append(logCats, *lc)
						}
					}
					args["enabledLogCategories"] = llx.ArrayData(logCats, types.String)
					var rules []any
					for _, rule := range props.Profile.AccessRules {
						if rule == nil {
							continue
						}
						if d, err := convert.JsonToDict(rule); err == nil {
							rules = append(rules, flattenNspProperties(d))
						}
					}
					args["accessRules"] = llx.ArrayData(rules, types.Dict)
				}
				if props.ResourceAssociation != nil {
					if props.ResourceAssociation.Name != nil {
						args["associationName"] = llx.StringDataPtr(props.ResourceAssociation.Name)
					}
					if props.ResourceAssociation.AccessMode != nil {
						args["associationAccessMode"] = llx.StringData(string(*props.ResourceAssociation.AccessMode))
					}
				}
				var issues []any
				for _, iss := range props.ProvisioningIssues {
					if iss == nil {
						continue
					}
					if d, err := convert.JsonToDict(iss); err == nil {
						issues = append(issues, flattenNspProperties(d))
					}
				}
				args["provisioningIssues"] = llx.ArrayData(issues, types.Dict)
			}

			mqlNsp, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspaceNspConfiguration, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(nsp.SystemData)
			if err != nil {
				return nil, err
			}
			mqlNsp.(*mqlAzureSubscriptionMonitorServiceWorkspaceNspConfiguration).cacheSystemData = sysData
			res = append(res, mqlNsp)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMonitorServiceWorkspaceNspConfigurationInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceNspConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMonitorServiceWorkspaceNspConfiguration) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// workspace returns a typed reference to the Log Analytics workspace from an Application Insight.
func (a *mqlAzureSubscriptionMonitorServiceApplicationInsight) workspace() (*mqlAzureSubscriptionMonitorServiceWorkspace, error) {
	if a.cacheWorkspaceResourceId == "" {
		a.Workspace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceWorkspace,
		map[string]*llx.RawData{
			"id": llx.StringData(a.cacheWorkspaceResourceId),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceWorkspace), nil
}

// queryPacks fetches all Log Analytics QueryPacks in the subscription.
func (a *mqlAzureSubscriptionMonitorService) queryPacks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armoperationalinsights.NewQueryPacksClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, qp := range page.Value {
			if qp == nil {
				continue
			}

			var queryPackId, provisioningState string
			var timeCreated, timeModified *llx.RawData
			if qp.Properties != nil {
				if qp.Properties.QueryPackID != nil {
					queryPackId = *qp.Properties.QueryPackID
				}
				if qp.Properties.ProvisioningState != nil {
					provisioningState = *qp.Properties.ProvisioningState
				}
				if qp.Properties.TimeCreated != nil {
					timeCreated = llx.TimeDataPtr(qp.Properties.TimeCreated)
				}
				if qp.Properties.TimeModified != nil {
					timeModified = llx.TimeDataPtr(qp.Properties.TimeModified)
				}
			}
			if timeCreated == nil {
				timeCreated = llx.NilData
			}
			if timeModified == nil {
				timeModified = llx.NilData
			}

			mqlQp, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceQueryPack,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(qp.ID),
					"name":              llx.StringDataPtr(qp.Name),
					"location":          llx.StringDataPtr(qp.Location),
					"type":              llx.StringDataPtr(qp.Type),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(qp.Tags), types.String),
					"queryPackId":       llx.StringData(queryPackId),
					"provisioningState": llx.StringData(provisioningState),
					"timeCreated":       timeCreated,
					"timeModified":      timeModified,
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(qp.SystemData)
			if err != nil {
				return nil, err
			}
			mqlQp.(*mqlAzureSubscriptionMonitorServiceQueryPack).cacheSystemData = sysData
			res = append(res, mqlQp)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMonitorServiceQueryPackInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionMonitorServiceQueryPackQueryInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMonitorServiceQueryPack) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMonitorServiceQueryPackQuery) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMonitorServiceQueryPack) id() (string, error) {
	return a.Id.Data, nil
}

// queries fetches all saved KQL queries within a QueryPack.
func (a *mqlAzureSubscriptionMonitorServiceQueryPack) queries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	queryPackName, err := resourceID.Component("queryPacks")
	if err != nil {
		return nil, err
	}

	client, err := armoperationalinsights.NewQueriesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, queryPackName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, q := range page.Value {
			if q == nil {
				continue
			}

			var displayName, description, body, author string
			var timeCreated, timeModified *llx.RawData
			var tagsDict any
			if q.Properties != nil {
				if q.Properties.DisplayName != nil {
					displayName = *q.Properties.DisplayName
				}
				if q.Properties.Description != nil {
					description = *q.Properties.Description
				}
				if q.Properties.Body != nil {
					body = *q.Properties.Body
				}
				if q.Properties.Author != nil {
					author = *q.Properties.Author
				}
				if q.Properties.TimeCreated != nil {
					timeCreated = llx.TimeDataPtr(q.Properties.TimeCreated)
				}
				if q.Properties.TimeModified != nil {
					timeModified = llx.TimeDataPtr(q.Properties.TimeModified)
				}
				if len(q.Properties.Tags) > 0 {
					if d, err := convert.JsonToDict(q.Properties.Tags); err == nil {
						tagsDict = d
					}
				}
			}
			if timeCreated == nil {
				timeCreated = llx.NilData
			}
			if timeModified == nil {
				timeModified = llx.NilData
			}

			mqlQ, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceQueryPackQuery,
				map[string]*llx.RawData{
					"id":           llx.StringDataPtr(q.ID),
					"name":         llx.StringDataPtr(q.Name),
					"type":         llx.StringDataPtr(q.Type),
					"displayName":  llx.StringData(displayName),
					"description":  llx.StringData(description),
					"body":         llx.StringData(body),
					"author":       llx.StringData(author),
					"timeCreated":  timeCreated,
					"timeModified": timeModified,
					"tags":         llx.DictData(tagsDict),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(q.SystemData)
			if err != nil {
				return nil, err
			}
			mqlQ.(*mqlAzureSubscriptionMonitorServiceQueryPackQuery).cacheSystemData = sysData
			res = append(res, mqlQ)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMonitorServiceQueryPackQuery) id() (string, error) {
	return a.Id.Data, nil
}
