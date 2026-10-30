// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// mqlAzuredevopsAdvancedSecurityInternal ties the Advanced Security state to
// its repository, whose alerts it lists.
type mqlAzuredevopsAdvancedSecurityInternal struct {
	repo *mqlAzuredevopsRepository
}

func (r *mqlAzuredevopsRepository) advancedSecurity() (*mqlAzuredevopsAdvancedSecurity, error) {
	e, err := connectionOf(r.MqlRuntime).Client().AdvSecEnablement(apiContext(), r.ProjectName.Data, r.Id.Data)
	switch {
	case connection.IsAdvSecDisabled(err):
		e = &connection.AdvSecEnablement{}
	case err != nil:
		return nil, classifyForbidden(err)
	}

	res, err := CreateResource(r.MqlRuntime, "azuredevops.advancedSecurity", map[string]*llx.RawData{
		"__id":                      llx.StringData("azuredevops.advancedSecurity/" + r.Id.Data),
		"enabled":                   llx.BoolData(e.Enabled),
		"enablementLastChangedDate": llx.TimeDataPtr(e.LastChanged()),
	})
	if err != nil {
		return nil, err
	}
	as := res.(*mqlAzuredevopsAdvancedSecurity)
	as.repo = r
	return as, nil
}

// alerts is null, without a request, when Advanced Security is off: an empty
// list would pass every alert check of a repository nothing scans.
func (a *mqlAzuredevopsAdvancedSecurity) alerts() ([]any, error) {
	if !a.Enabled.Data {
		a.Alerts.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	alerts, err := connectionOf(a.MqlRuntime).Client().Alerts(apiContext(), a.repo.ProjectName.Data, a.repo.Id.Data)
	if connection.IsAdvSecDisabled(err) {
		a.Alerts.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if err != nil {
		return nil, classifyForbidden(err)
	}

	out := make([]any, 0, len(alerts))
	for _, al := range alerts {
		res, err := CreateResource(a.MqlRuntime, "azuredevops.alert", map[string]*llx.RawData{
			"__id":          llx.StringData("azuredevops.alert/" + a.repo.Id.Data + "/" + strconv.FormatInt(al.ID, 10)),
			"id":            llx.IntData(al.ID),
			"alertType":     llx.StringData(al.AlertType),
			"severity":      llx.StringData(al.Severity),
			"state":         llx.StringData(al.State),
			"title":         llx.StringData(al.Title),
			"gitRef":        llx.StringData(al.GitRef),
			"firstSeenDate": llx.TimeDataPtr(al.FirstSeen()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
