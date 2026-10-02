// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/microsoftgraph/msgraph-sdk-go/admin"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	permReportSettingsRead = "ReportSettings.Read.All"
	permPeopleSettingsRead = "PeopleSettings.Read.All"
	permServiceHealthRead  = "ServiceHealth.Read.All"
)

// reportSettings reads admin/reportSettings.
// Least privileged permission: ReportSettings.Read.All
func (a *mqlMicrosoftTenant) reportSettings() (*mqlMicrosoftTenantReportSettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	settings, err := graphClient.Admin().ReportSettings().Get(context.Background(), nil)
	if err != nil {
		return nil, classifyGraphError(err, permReportSettingsRead)
	}
	return a.reportSettingsFrom(settings)
}

// reportSettingsFrom builds the report settings from the admin reportSettings
// answer. An empty answer reads null: nothing was read, so nothing can be
// claimed about whether names are concealed.
func (a *mqlMicrosoftTenant) reportSettingsFrom(settings models.AdminReportSettingsable) (*mqlMicrosoftTenantReportSettings, error) {
	if settings == nil {
		a.ReportSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, ResourceMicrosoftTenantReportSettings, map[string]*llx.RawData{
		"__id":                  llx.StringData(a.Id.Data + "-report-settings"),
		"displayConcealedNames": llx.BoolDataPtr(settings.GetDisplayConcealedNames()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftTenantReportSettings), nil
}

func (a *mqlMicrosoftTenant) peopleSettings() (*mqlMicrosoftTenantPeopleSettings, error) {
	res, err := CreateResource(a.MqlRuntime, ResourceMicrosoftTenantPeopleSettings, map[string]*llx.RawData{
		"__id": llx.StringData(a.Id.Data + "-people-settings"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftTenantPeopleSettings), nil
}

type mqlMicrosoftTenantPeopleSettingsInternal struct {
	itemInsightsLock    sync.Mutex
	itemInsightsFetched bool
	itemInsights        models.InsightsSettingsable
	itemInsightsErr     error
}

// fetchItemInsights reads admin/people/itemInsights once; both item insights
// fields come from the same answer.
func (a *mqlMicrosoftTenantPeopleSettings) fetchItemInsights() (models.InsightsSettingsable, error) {
	a.itemInsightsLock.Lock()
	defer a.itemInsightsLock.Unlock()
	if a.itemInsightsFetched {
		return a.itemInsights, a.itemInsightsErr
	}
	a.itemInsightsFetched = true

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		a.itemInsightsErr = err
		return nil, err
	}
	a.itemInsights, err = graphClient.Admin().People().ItemInsights().Get(context.Background(), nil)
	if err != nil {
		a.itemInsightsErr = classifyGraphError(err, permPeopleSettingsRead)
	}
	return a.itemInsights, a.itemInsightsErr
}

func (a *mqlMicrosoftTenantPeopleSettings) itemInsightsEnabledInOrganization() (bool, error) {
	settings, err := a.fetchItemInsights()
	if err != nil {
		return false, err
	}
	if settings == nil || settings.GetIsEnabledInOrganization() == nil {
		a.ItemInsightsEnabledInOrganization.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *settings.GetIsEnabledInOrganization(), nil
}

func (a *mqlMicrosoftTenantPeopleSettings) itemInsightsDisabledForGroup() (*mqlMicrosoftGroup, error) {
	settings, err := a.fetchItemInsights()
	if err != nil {
		return nil, err
	}
	groupId := ""
	if settings != nil && settings.GetDisabledForGroup() != nil {
		groupId = *settings.GetDisabledForGroup()
	}
	if groupId == "" {
		a.ItemInsightsDisabledForGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftGroup, map[string]*llx.RawData{
		"id": llx.StringData(groupId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftGroup), nil
}

// pronounsEnabledInOrganization reads admin/people/pronouns.
func (a *mqlMicrosoftTenantPeopleSettings) pronounsEnabledInOrganization() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return false, err
	}
	settings, err := graphClient.Admin().People().Pronouns().Get(context.Background(), nil)
	if err != nil {
		return false, classifyGraphError(err, permPeopleSettingsRead)
	}
	if settings == nil || settings.GetIsEnabledInOrganization() == nil {
		a.PronounsEnabledInOrganization.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *settings.GetIsEnabledInOrganization(), nil
}

// profileCardProperties lists admin/people/profileCardProperties.
func (a *mqlMicrosoftTenantPeopleSettings) profileCardProperties() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Admin().People().ProfileCardProperties().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permPeopleSettingsRead)
	}
	props, err := iterate[models.ProfileCardPropertyable](ctx, resp, graphClient.GetAdapter(), models.CreateProfileCardPropertyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permPeopleSettingsRead)
	}

	res := []any{}
	for _, prop := range props {
		if prop == nil || prop.GetDirectoryPropertyName() == nil {
			continue
		}
		name := *prop.GetDirectoryPropertyName()
		mqlProp, err := CreateResource(a.MqlRuntime, ResourceMicrosoftTenantPeopleSettingsProfileCardProperty, map[string]*llx.RawData{
			"__id":                  llx.StringData(a.__id + "/profileCardProperty/" + name),
			"directoryPropertyName": llx.StringData(name),
			"annotations":           llx.ArrayData(profileCardAnnotations(prop.GetAnnotations()), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProp)
	}
	return res, nil
}

// profileCardAnnotations flattens a profile card property's labels into dicts
// with keys displayName and localizations.
func profileCardAnnotations(annotations []models.ProfileCardAnnotationable) []any {
	res := []any{}
	for _, an := range annotations {
		if an == nil {
			continue
		}
		localizations := []any{}
		for _, loc := range an.GetLocalizations() {
			if loc == nil {
				continue
			}
			localizations = append(localizations, map[string]any{
				"languageTag": strPtrOrNil(loc.GetLanguageTag()),
				"displayName": strPtrOrNil(loc.GetDisplayName()),
			})
		}
		res = append(res, map[string]any{
			"displayName":   strPtrOrNil(an.GetDisplayName()),
			"localizations": localizations,
		})
	}
	return res
}

func strPtrOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// serviceHealth lists admin/serviceAnnouncement/healthOverviews with their
// issues expanded, so one request answers both the overview and its issues.
// Least privileged permission: ServiceHealth.Read.All
func (a *mqlMicrosoftTenant) serviceHealth() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Admin().ServiceAnnouncement().HealthOverviews().Get(ctx, &admin.ServiceAnnouncementHealthOverviewsRequestBuilderGetRequestConfiguration{
		QueryParameters: &admin.ServiceAnnouncementHealthOverviewsRequestBuilderGetQueryParameters{
			Expand: []string{"issues"},
		},
	})
	if err != nil {
		return nil, classifyGraphError(err, permServiceHealthRead)
	}
	overviews, err := iterate[models.ServiceHealthable](ctx, resp, graphClient.GetAdapter(), models.CreateServiceHealthCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permServiceHealthRead)
	}

	res := []any{}
	for _, overview := range overviews {
		if overview == nil || overview.GetId() == nil {
			continue
		}
		issues, err := newServiceHealthIssues(a.MqlRuntime, overview.GetIssues())
		if err != nil {
			return nil, err
		}
		mqlOverview, err := CreateResource(a.MqlRuntime, ResourceMicrosoftServiceHealth, map[string]*llx.RawData{
			"__id":    llx.StringData("microsoft.serviceHealth/" + *overview.GetId()),
			"id":      llx.StringDataPtr(overview.GetId()),
			"service": llx.StringDataPtr(overview.GetService()),
			"status":  llx.StringDataPtr(enumStringPtr(overview.GetStatus())),
			"issues":  llx.ArrayData(issues, types.Resource(ResourceMicrosoftServiceHealthIssue)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlOverview)
	}
	return res, nil
}

// serviceHealthIssues lists admin/serviceAnnouncement/issues.
// Least privileged permission: ServiceHealth.Read.All
func (a *mqlMicrosoftTenant) serviceHealthIssues() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Admin().ServiceAnnouncement().Issues().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permServiceHealthRead)
	}
	issues, err := iterate[models.ServiceHealthIssueable](ctx, resp, graphClient.GetAdapter(), models.CreateServiceHealthIssueCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permServiceHealthRead)
	}
	return newServiceHealthIssues(a.MqlRuntime, issues)
}

func newServiceHealthIssues(runtime *plugin.Runtime, issues []models.ServiceHealthIssueable) ([]any, error) {
	res := []any{}
	for _, issue := range issues {
		if issue == nil || issue.GetId() == nil {
			continue
		}
		mqlIssue, err := CreateResource(runtime, ResourceMicrosoftServiceHealthIssue, serviceHealthIssueArgs(issue))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIssue)
	}
	return res, nil
}

// serviceHealthIssueArgs maps a Graph service health issue onto the resource's
// fields. Absent enums and timestamps stay null.
func serviceHealthIssueArgs(issue models.ServiceHealthIssueable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                 llx.StringData("microsoft.serviceHealthIssue/" + *issue.GetId()),
		"id":                   llx.StringDataPtr(issue.GetId()),
		"title":                llx.StringDataPtr(issue.GetTitle()),
		"service":              llx.StringDataPtr(issue.GetService()),
		"feature":              llx.StringDataPtr(issue.GetFeature()),
		"featureGroup":         llx.StringDataPtr(issue.GetFeatureGroup()),
		"status":               llx.StringDataPtr(enumStringPtr(issue.GetStatus())),
		"classification":       llx.StringDataPtr(enumStringPtr(issue.GetClassification())),
		"origin":               llx.StringDataPtr(enumStringPtr(issue.GetOrigin())),
		"impactDescription":    llx.StringDataPtr(issue.GetImpactDescription()),
		"isResolved":           llx.BoolDataPtr(issue.GetIsResolved()),
		"startDateTime":        llx.TimeDataPtr(issue.GetStartDateTime()),
		"endDateTime":          llx.TimeDataPtr(issue.GetEndDateTime()),
		"lastModifiedDateTime": llx.TimeDataPtr(issue.GetLastModifiedDateTime()),
	}
}
