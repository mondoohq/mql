// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	securitymodels "github.com/microsoftgraph/msgraph-sdk-go/models/security"
	"github.com/microsoftgraph/msgraph-sdk-go/security"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// enumStringPtr renders a Microsoft Graph enum pointer as its string value,
// preserving nil so unset enums map to a null field rather than an empty string.
func enumStringPtr[T fmt.Stringer](v *T) *string {
	if v == nil {
		return nil
	}
	s := (*v).String()
	return &s
}

// newAlertComments converts the analyst comments on an alert or incident into
// dict entries.
func newAlertComments(comments []securitymodels.AlertCommentable) []any {
	res := []any{}
	for _, c := range comments {
		entry := map[string]any{
			"comment":              convert.ToValue(c.GetComment()),
			"createdByDisplayName": convert.ToValue(c.GetCreatedByDisplayName()),
		}
		if t := c.GetCreatedDateTime(); t != nil {
			entry["createdDateTime"] = t.Format(time.RFC3339)
		}
		res = append(res, entry)
	}
	return res
}

// alerts lists Microsoft Defender XDR alerts.
// Requires the SecurityAlert.Read.All application permission.
// see https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2
func (a *mqlMicrosoftSecurity) alerts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	resp, err := graphClient.Security().Alerts_v2().Get(ctx, &security.Alerts_v2RequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}

	alerts, err := iterate[securitymodels.Alertable](ctx, resp, graphClient.GetAdapter(), securitymodels.CreateAlertCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, alert := range alerts {
		mqlAlert, err := newMqlSecurityAlert(a.MqlRuntime, alert)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}
	return res, nil
}

func newMqlSecurityAlert(runtime *plugin.Runtime, alert securitymodels.Alertable) (*mqlMicrosoftSecurityAlert, error) {
	mqlResource, err := CreateResource(runtime, "microsoft.security.alert", map[string]*llx.RawData{
		"__id":                  llx.StringDataPtr(alert.GetId()),
		"id":                    llx.StringDataPtr(alert.GetId()),
		"title":                 llx.StringDataPtr(alert.GetTitle()),
		"description":           llx.StringDataPtr(alert.GetDescription()),
		"category":              llx.StringDataPtr(alert.GetCategory()),
		"categories":            llx.ArrayData(convert.SliceAnyToInterface(alert.GetCategories()), types.String),
		"severity":              llx.StringDataPtr(enumStringPtr(alert.GetSeverity())),
		"status":                llx.StringDataPtr(enumStringPtr(alert.GetStatus())),
		"classification":        llx.StringDataPtr(enumStringPtr(alert.GetClassification())),
		"determination":         llx.StringDataPtr(enumStringPtr(alert.GetDetermination())),
		"serviceSource":         llx.StringDataPtr(enumStringPtr(alert.GetServiceSource())),
		"detectionSource":       llx.StringDataPtr(enumStringPtr(alert.GetDetectionSource())),
		"providerAlertId":       llx.StringDataPtr(alert.GetProviderAlertId()),
		"incidentId":            llx.StringDataPtr(alert.GetIncidentId()),
		"assignedTo":            llx.StringDataPtr(alert.GetAssignedTo()),
		"recommendedActions":    llx.StringDataPtr(alert.GetRecommendedActions()),
		"mitreTechniques":       llx.ArrayData(convert.SliceAnyToInterface(alert.GetMitreTechniques()), types.String),
		"systemTags":            llx.ArrayData(convert.SliceAnyToInterface(alert.GetSystemTags()), types.String),
		"tenantId":              llx.StringDataPtr(alert.GetTenantId()),
		"alertWebUrl":           llx.StringDataPtr(alert.GetAlertWebUrl()),
		"createdDateTime":       graphTimeData(alert.GetCreatedDateTime()),
		"lastUpdateDateTime":    graphTimeData(alert.GetLastUpdateDateTime()),
		"firstActivityDateTime": graphTimeData(alert.GetFirstActivityDateTime()),
		"lastActivityDateTime":  graphTimeData(alert.GetLastActivityDateTime()),
		"resolvedDateTime":      graphTimeData(alert.GetResolvedDateTime()),
		"comments":              llx.ArrayData(newAlertComments(alert.GetComments()), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftSecurityAlert), nil
}

// incident resolves the incident this alert is correlated into.
func (a *mqlMicrosoftSecurityAlert) incident() (*mqlMicrosoftSecurityIncident, error) {
	incidentId := a.IncidentId.Data
	if incidentId == "" {
		a.Incident.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "microsoft.security.incident", map[string]*llx.RawData{
		"id": llx.StringData(incidentId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftSecurityIncident), nil
}

// incidents lists Microsoft Defender XDR incidents.
// Requires the SecurityIncident.Read.All application permission.
// see https://learn.microsoft.com/en-us/graph/api/security-list-incidents
func (a *mqlMicrosoftSecurity) incidents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	resp, err := graphClient.Security().Incidents().Get(ctx, &security.IncidentsRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}

	incidents, err := iterate[securitymodels.Incidentable](ctx, resp, graphClient.GetAdapter(), securitymodels.CreateIncidentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, incident := range incidents {
		mqlIncident, err := newMqlSecurityIncident(a.MqlRuntime, incident)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIncident)
	}
	return res, nil
}

func newMqlSecurityIncident(runtime *plugin.Runtime, incident securitymodels.Incidentable) (*mqlMicrosoftSecurityIncident, error) {
	mqlResource, err := CreateResource(runtime, "microsoft.security.incident", map[string]*llx.RawData{
		"__id":               llx.StringDataPtr(incident.GetId()),
		"id":                 llx.StringDataPtr(incident.GetId()),
		"displayName":        llx.StringDataPtr(incident.GetDisplayName()),
		"description":        llx.StringDataPtr(incident.GetDescription()),
		"summary":            llx.StringDataPtr(incident.GetSummary()),
		"severity":           llx.StringDataPtr(enumStringPtr(incident.GetSeverity())),
		"status":             llx.StringDataPtr(enumStringPtr(incident.GetStatus())),
		"classification":     llx.StringDataPtr(enumStringPtr(incident.GetClassification())),
		"determination":      llx.StringDataPtr(enumStringPtr(incident.GetDetermination())),
		"assignedTo":         llx.StringDataPtr(incident.GetAssignedTo()),
		"lastModifiedBy":     llx.StringDataPtr(incident.GetLastModifiedBy()),
		"redirectIncidentId": llx.StringDataPtr(incident.GetRedirectIncidentId()),
		"tenantId":           llx.StringDataPtr(incident.GetTenantId()),
		"customTags":         llx.ArrayData(convert.SliceAnyToInterface(incident.GetCustomTags()), types.String),
		"systemTags":         llx.ArrayData(convert.SliceAnyToInterface(incident.GetSystemTags()), types.String),
		"incidentWebUrl":     llx.StringDataPtr(incident.GetIncidentWebUrl()),
		"createdDateTime":    graphTimeData(incident.GetCreatedDateTime()),
		"lastUpdateDateTime": graphTimeData(incident.GetLastUpdateDateTime()),
		"comments":           llx.ArrayData(newAlertComments(incident.GetComments()), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftSecurityIncident), nil
}

// initMicrosoftSecurityIncident resolves an incident by its id by locating it
// in the tenant's incident collection, so typed references such as
// microsoft.security.alert.incident can navigate to the full record.
func initMicrosoftSecurityIncident(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	rawId, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := rawId.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	mqlResource, err := CreateResource(runtime, "microsoft.security", nil)
	if err != nil {
		return nil, nil, err
	}
	mqlSecurity := mqlResource.(*mqlMicrosoftSecurity)
	incidents := mqlSecurity.GetIncidents()
	if incidents.Error != nil {
		return nil, nil, incidents.Error
	}
	for _, raw := range incidents.Data {
		incident := raw.(*mqlMicrosoftSecurityIncident)
		if incident.Id.Data == id {
			return nil, incident, nil
		}
	}

	// the incident is not in the collection (e.g. merged or out of scope) — keep
	// the bare resource so the id remains queryable
	args["__id"] = args["id"]
	return args, nil, nil
}

// alerts lists the alerts correlated into the incident.
func (i *mqlMicrosoftSecurityIncident) alerts() ([]any, error) {
	incidentId := i.Id.Data
	if incidentId == "" {
		return []any{}, nil
	}
	conn := i.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	resp, err := graphClient.Security().Incidents().ByIncidentId(incidentId).Alerts().Get(ctx, &security.IncidentsItemAlertsRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}

	alerts, err := iterate[securitymodels.Alertable](ctx, resp, graphClient.GetAdapter(), securitymodels.CreateAlertCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, alert := range alerts {
		mqlAlert, err := newMqlSecurityAlert(i.MqlRuntime, alert)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAlert)
	}
	return res, nil
}
