// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionSentinelService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionSentinelService) id() (string, error) {
	return "azure.subscription.sentinelService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionSentinelServiceWorkspaceInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionSentinelServiceAlertRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSentinelService) workspaces() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	subId := a.SubscriptionId.Data
	ctx := context.Background()

	wsClient, err := armoperationalinsights.NewWorkspacesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	onboardClient, err := armsecurityinsights.NewSentinelOnboardingStatesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	wsPager := wsClient.NewListPager(nil)
	for wsPager.More() {
		page, err := wsPager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Log Analytics workspaces due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ws := range page.Value {
			if ws == nil || ws.ID == nil {
				continue
			}
			parsed, err := ParseResourceID(*ws.ID)
			if err != nil {
				continue
			}
			workspaceName := ""
			if ws.Name != nil {
				workspaceName = *ws.Name
			}
			onboarded, err := sentinelOnboarded(ctx, onboardClient, parsed.ResourceGroup, workspaceName)
			if err != nil {
				return nil, err
			}
			if !onboarded {
				continue
			}
			mqlWs, err := CreateResource(a.MqlRuntime, "azure.subscription.sentinelService.workspace", map[string]*llx.RawData{
				"id":             llx.StringDataPtr(ws.ID),
				"name":           llx.StringData(workspaceName),
				"resourceGroup":  llx.StringData(parsed.ResourceGroup),
				"subscriptionId": llx.StringData(parsed.SubscriptionID),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ws.SystemData)
			if err != nil {
				return nil, err
			}
			mqlWs.(*mqlAzureSubscriptionSentinelServiceWorkspace).cacheSystemData = sysData
			res = append(res, mqlWs)
		}
	}
	return res, nil
}

// sentinelOnboarded reports whether Microsoft Sentinel is onboarded on
// the given Log Analytics workspace. Returns false (without erroring)
// on 404, which is the response when the SecurityInsights solution has
// never been onboarded on the workspace.
func sentinelOnboarded(ctx context.Context, client *armsecurityinsights.SentinelOnboardingStatesClient, resourceGroup, workspaceName string) (bool, error) {
	resp, err := client.List(ctx, resourceGroup, workspaceName, nil)
	if err != nil {
		if respErr, ok := errors.AsType[*azcore.ResponseError](err); ok {
			if respErr.StatusCode == http.StatusNotFound {
				return false, nil
			}
			if respErr.StatusCode == http.StatusForbidden {
				log.Debug().Str("workspace", workspaceName).Err(err).Msg("could not read Sentinel onboarding state due to access denied")
				return false, nil
			}
		}
		return false, err
	}
	return len(resp.Value) > 0, nil
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) workspace() (*mqlAzureSubscriptionMonitorServiceWorkspace, error) {
	mqlWs, err := NewResource(a.MqlRuntime, "azure.subscription.monitorService.workspace",
		map[string]*llx.RawData{"id": llx.StringData(a.Id.Data)})
	if err != nil {
		return nil, err
	}
	return mqlWs.(*mqlAzureSubscriptionMonitorServiceWorkspace), nil
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) alertRules() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armsecurityinsights.NewAlertRulesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(a.ResourceGroup.Data, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Sentinel alert rules due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, raw := range page.Value {
			if raw == nil {
				continue
			}
			mqlRule, err := sentinelAlertRuleToMql(a.MqlRuntime, raw)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func sentinelAlertRuleToMql(runtime *plugin.Runtime, raw armsecurityinsights.AlertRuleClassification) (*mqlAzureSubscriptionSentinelServiceAlertRule, error) {
	base := raw.GetAlertRule()
	var kind, displayName, description, severity string
	// modeled tracks whether the SDK gave us a concrete rule type. For kinds it
	// cannot model, none of the scalars below are knowable, so they are
	// reported as null instead of a fabricated zero value.
	modeled := true
	var enabled bool
	tactics := []any{}

	if base.Kind != nil {
		kind = string(*base.Kind)
	}

	var propsDict any
	switch r := raw.(type) {
	case *armsecurityinsights.ScheduledAlertRule:
		if p := r.Properties; p != nil {
			if p.DisplayName != nil {
				displayName = *p.DisplayName
			}
			if p.Enabled != nil {
				enabled = *p.Enabled
			}
			if p.Description != nil {
				description = *p.Description
			}
			if p.Severity != nil {
				severity = string(*p.Severity)
			}
			for _, t := range p.Tactics {
				if t != nil {
					tactics = append(tactics, string(*t))
				}
			}
			d, err := convert.JsonToDict(p)
			if err != nil {
				return nil, err
			}
			propsDict = d
		}
	case *armsecurityinsights.FusionAlertRule:
		if p := r.Properties; p != nil {
			if p.DisplayName != nil {
				displayName = *p.DisplayName
			}
			if p.Enabled != nil {
				enabled = *p.Enabled
			}
			if p.Description != nil {
				description = *p.Description
			}
			if p.Severity != nil {
				severity = string(*p.Severity)
			}
			for _, t := range p.Tactics {
				if t != nil {
					tactics = append(tactics, string(*t))
				}
			}
			d, err := convert.JsonToDict(p)
			if err != nil {
				return nil, err
			}
			propsDict = d
		}
	case *armsecurityinsights.MicrosoftSecurityIncidentCreationAlertRule:
		if p := r.Properties; p != nil {
			if p.DisplayName != nil {
				displayName = *p.DisplayName
			}
			if p.Enabled != nil {
				enabled = *p.Enabled
			}
			if p.Description != nil {
				description = *p.Description
			}
			d, err := convert.JsonToDict(p)
			if err != nil {
				return nil, err
			}
			propsDict = d
		}
	default:
		// Kinds without a dedicated concrete type in this SDK version (NRT,
		// MLBehaviorAnalytics, ThreatIntelligence, ...) deserialize as
		// *armsecurityinsights.AlertRule, which has no Properties field at
		// all -- the wire payload is discarded during unmarshal, so there is
		// nothing left to marshal back out. Report the scalars as null rather
		// than claiming the rule is disabled: an NRT detection that is in fact
		// running must not read as `enabled: false`.
		modeled = false
	}

	enabledData, displayNameData := llx.BoolData(enabled), llx.StringData(displayName)
	severityData, descriptionData := llx.StringData(severity), llx.StringData(description)
	if !modeled {
		enabledData, displayNameData = llx.NilData, llx.NilData
		severityData, descriptionData = llx.NilData, llx.NilData
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionSentinelServiceAlertRule, map[string]*llx.RawData{
		"id":          llx.StringDataPtr(base.ID),
		"name":        llx.StringDataPtr(base.Name),
		"kind":        llx.StringData(kind),
		"enabled":     enabledData,
		"displayName": displayNameData,
		"severity":    severityData,
		"tactics":     llx.ArrayData(tactics, types.String),
		"description": descriptionData,
		"properties":  llx.DictData(propsDict),
	})
	if err != nil {
		return nil, err
	}

	sysData, err := convert.JsonToDict(base.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionSentinelServiceAlertRule).cacheSystemData = sysData

	return res.(*mqlAzureSubscriptionSentinelServiceAlertRule), nil
}

type mqlAzureSubscriptionSentinelServiceAlertRuleInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionSentinelServiceAlertRule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionSentinelServiceIncidentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionSentinelServiceIncident) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSentinelServiceIncident) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) incidents() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armsecurityinsights.NewIncidentsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(a.ResourceGroup.Data, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Sentinel incidents due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, inc := range page.Value {
			if inc == nil {
				continue
			}
			mqlInc, err := sentinelIncidentToMql(a.MqlRuntime, inc)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlInc)
		}
	}
	return res, nil
}

func sentinelIncidentToMql(runtime *plugin.Runtime, inc *armsecurityinsights.Incident) (*mqlAzureSubscriptionSentinelServiceIncident, error) {
	var title, severity, status, classification, classificationReason, classificationComment, description, incidentUrl string
	var ownerAssignedTo, ownerObjectId, ownerUpn, ownerEmail string
	var incidentNumber int64
	var createdTime, lastModifiedTime, firstActivityTime, lastActivityTime *time.Time
	labels := []any{}
	relatedRuleIds := []any{}

	if p := inc.Properties; p != nil {
		title = convert.ToValue(p.Title)
		if p.Severity != nil {
			severity = string(*p.Severity)
		}
		if p.Status != nil {
			status = string(*p.Status)
		}
		if p.Classification != nil {
			classification = string(*p.Classification)
		}
		if p.ClassificationReason != nil {
			classificationReason = string(*p.ClassificationReason)
		}
		classificationComment = convert.ToValue(p.ClassificationComment)
		description = convert.ToValue(p.Description)
		incidentUrl = convert.ToValue(p.IncidentURL)
		if p.IncidentNumber != nil {
			incidentNumber = int64(*p.IncidentNumber)
		}
		createdTime = p.CreatedTimeUTC
		lastModifiedTime = p.LastModifiedTimeUTC
		firstActivityTime = p.FirstActivityTimeUTC
		lastActivityTime = p.LastActivityTimeUTC
		if o := p.Owner; o != nil {
			ownerAssignedTo = convert.ToValue(o.AssignedTo)
			ownerObjectId = convert.ToValue(o.ObjectID)
			ownerUpn = convert.ToValue(o.UserPrincipalName)
			ownerEmail = convert.ToValue(o.Email)
		}
		for _, l := range p.Labels {
			if l != nil && l.LabelName != nil {
				labels = append(labels, *l.LabelName)
			}
		}
		for _, rid := range p.RelatedAnalyticRuleIDs {
			if rid != nil {
				relatedRuleIds = append(relatedRuleIds, *rid)
			}
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.sentinelService.incident", map[string]*llx.RawData{
		"id":                     llx.StringDataPtr(inc.ID),
		"name":                   llx.StringDataPtr(inc.Name),
		"title":                  llx.StringData(title),
		"severity":               llx.StringData(severity),
		"status":                 llx.StringData(status),
		"incidentNumber":         llx.IntData(incidentNumber),
		"incidentUrl":            llx.StringData(incidentUrl),
		"classification":         llx.StringData(classification),
		"classificationReason":   llx.StringData(classificationReason),
		"classificationComment":  llx.StringData(classificationComment),
		"description":            llx.StringData(description),
		"labels":                 llx.ArrayData(labels, types.String),
		"ownerAssignedTo":        llx.StringData(ownerAssignedTo),
		"ownerObjectId":          llx.StringData(ownerObjectId),
		"ownerUserPrincipalName": llx.StringData(ownerUpn),
		"ownerEmail":             llx.StringData(ownerEmail),
		"relatedAnalyticRuleIds": llx.ArrayData(relatedRuleIds, types.String),
		"createdTime":            llx.TimeDataPtr(createdTime),
		"lastModifiedTime":       llx.TimeDataPtr(lastModifiedTime),
		"firstActivityTime":      llx.TimeDataPtr(firstActivityTime),
		"lastActivityTime":       llx.TimeDataPtr(lastActivityTime),
	})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(inc.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionSentinelServiceIncident).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionSentinelServiceIncident), nil
}

type mqlAzureSubscriptionSentinelServiceWatchlistInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionSentinelServiceWatchlist) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSentinelServiceWatchlist) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) watchlists() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armsecurityinsights.NewWatchlistsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(a.ResourceGroup.Data, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Sentinel watchlists due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, wl := range page.Value {
			if wl == nil {
				continue
			}
			var watchlistAlias, displayName, provider, source, itemsSearchKey string
			var contentType, defaultDuration, description, uploadStatus, tenantId string
			var created, updated *time.Time
			var createdBy, updatedBy any
			labels := []any{}
			if p := wl.Properties; p != nil {
				watchlistAlias = convert.ToValue(p.WatchlistAlias)
				displayName = convert.ToValue(p.DisplayName)
				provider = convert.ToValue(p.Provider)
				if p.Source != nil {
					source = string(*p.Source)
				}
				itemsSearchKey = convert.ToValue(p.ItemsSearchKey)
				contentType = convert.ToValue(p.ContentType)
				defaultDuration = convert.ToValue(p.DefaultDuration)
				description = convert.ToValue(p.Description)
				uploadStatus = convert.ToValue(p.UploadStatus)
				tenantId = convert.ToValue(p.TenantID)
				created = p.Created
				updated = p.Updated
				for _, l := range p.Labels {
					if l != nil {
						labels = append(labels, *l)
					}
				}
				if p.CreatedBy != nil {
					createdBy, err = convert.JsonToDict(p.CreatedBy)
					if err != nil {
						return nil, err
					}
				}
				if p.UpdatedBy != nil {
					updatedBy, err = convert.JsonToDict(p.UpdatedBy)
					if err != nil {
						return nil, err
					}
				}
			}
			mqlWl, err := CreateResource(a.MqlRuntime, "azure.subscription.sentinelService.watchlist", map[string]*llx.RawData{
				"id":              llx.StringDataPtr(wl.ID),
				"name":            llx.StringDataPtr(wl.Name),
				"watchlistAlias":  llx.StringData(watchlistAlias),
				"displayName":     llx.StringData(displayName),
				"provider":        llx.StringData(provider),
				"source":          llx.StringData(source),
				"itemsSearchKey":  llx.StringData(itemsSearchKey),
				"contentType":     llx.StringData(contentType),
				"defaultDuration": llx.StringData(defaultDuration),
				"description":     llx.StringData(description),
				"labels":          llx.ArrayData(labels, types.String),
				"uploadStatus":    llx.StringData(uploadStatus),
				"tenantId":        llx.StringData(tenantId),
				"created":         llx.TimeDataPtr(created),
				"updated":         llx.TimeDataPtr(updated),
				"createdBy":       llx.DictData(createdBy),
				"updatedBy":       llx.DictData(updatedBy),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(wl.SystemData)
			if err != nil {
				return nil, err
			}
			mqlWl.(*mqlAzureSubscriptionSentinelServiceWatchlist).cacheSystemData = sysData
			res = append(res, mqlWl)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionSentinelServiceAutomationRuleInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionSentinelServiceAutomationRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSentinelServiceAutomationRule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) automationRules() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armsecurityinsights.NewAutomationRulesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(a.ResourceGroup.Data, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Sentinel automation rules due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ar := range page.Value {
			if ar == nil {
				continue
			}
			var displayName, triggersOn, triggersWhen string
			var order int64
			var isEnabled *bool
			var createdTime, lastModifiedTime *time.Time
			var triggeringLogic, createdBy, lastModifiedBy any
			actions := []any{}
			if p := ar.Properties; p != nil {
				displayName = convert.ToValue(p.DisplayName)
				if p.Order != nil {
					order = int64(*p.Order)
				}
				createdTime = p.CreatedTimeUTC
				lastModifiedTime = p.LastModifiedTimeUTC
				if tl := p.TriggeringLogic; tl != nil {
					isEnabled = tl.IsEnabled
					if tl.TriggersOn != nil {
						triggersOn = string(*tl.TriggersOn)
					}
					if tl.TriggersWhen != nil {
						triggersWhen = string(*tl.TriggersWhen)
					}
					triggeringLogic, err = convert.JsonToDict(tl)
					if err != nil {
						return nil, err
					}
				}
				for _, action := range p.Actions {
					if action == nil {
						continue
					}
					d, err := convert.JsonToDict(action)
					if err != nil {
						return nil, err
					}
					actions = append(actions, d)
				}
				if p.CreatedBy != nil {
					createdBy, err = convert.JsonToDict(p.CreatedBy)
					if err != nil {
						return nil, err
					}
				}
				if p.LastModifiedBy != nil {
					lastModifiedBy, err = convert.JsonToDict(p.LastModifiedBy)
					if err != nil {
						return nil, err
					}
				}
			}
			mqlAr, err := CreateResource(a.MqlRuntime, "azure.subscription.sentinelService.automationRule", map[string]*llx.RawData{
				"id":               llx.StringDataPtr(ar.ID),
				"name":             llx.StringDataPtr(ar.Name),
				"displayName":      llx.StringData(displayName),
				"order":            llx.IntData(order),
				"isEnabled":        llx.BoolDataPtr(isEnabled),
				"triggersOn":       llx.StringData(triggersOn),
				"triggersWhen":     llx.StringData(triggersWhen),
				"triggeringLogic":  llx.DictData(triggeringLogic),
				"actions":          llx.ArrayData(actions, types.Dict),
				"createdTime":      llx.TimeDataPtr(createdTime),
				"lastModifiedTime": llx.TimeDataPtr(lastModifiedTime),
				"createdBy":        llx.DictData(createdBy),
				"lastModifiedBy":   llx.DictData(lastModifiedBy),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ar.SystemData)
			if err != nil {
				return nil, err
			}
			mqlAr.(*mqlAzureSubscriptionSentinelServiceAutomationRule).cacheSystemData = sysData
			res = append(res, mqlAr)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionSentinelServiceWorkspace) dataConnectors() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armsecurityinsights.NewDataConnectorsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(a.ResourceGroup.Data, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Sentinel data connectors due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, raw := range page.Value {
			if raw == nil {
				continue
			}
			base := raw.GetDataConnector()
			entry := map[string]any{}
			if base.Name != nil {
				entry["name"] = *base.Name
			}
			if base.Kind != nil {
				entry["kind"] = string(*base.Kind)
			}
			if base.ID != nil {
				entry["id"] = *base.ID
			}
			propsDict, err := convert.JsonToDict(raw)
			if err != nil {
				return nil, err
			}
			entry["properties"] = propsDict
			res = append(res, entry)
		}
	}
	return res, nil
}
