// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

// appsiteServerFarmID reads the App Service plan id out of a site's raw
// properties, or "" when the site reports none.
func appsiteServerFarmID(props map[string]any) string {
	if props == nil {
		return ""
	}
	id, _ := props["serverFarmId"].(string)
	return id
}

// appsiteHostingEnvironmentID reads the App Service Environment id out of a
// site's raw properties, or "" when the site does not run in one.
func appsiteHostingEnvironmentID(props map[string]any) string {
	if props == nil {
		return ""
	}
	profile, ok := props["hostingEnvironmentProfile"].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := profile["id"].(string)
	return id
}

// webServiceFor returns the subscription's web service, whose lists hold the
// plans and environments apps refer to.
func webServiceFor(runtime *plugin.Runtime) (*mqlAzureSubscriptionWebService, error) {
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, ResourceAzureSubscriptionWebService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionWebService), nil
}

// findByID returns the entry of a list whose ARM id matches, compared
// case-insensitively because ARM does not agree with itself on id casing.
func findByID[T azureListedResource](list []any, id string) (T, bool) {
	var zero T
	if id == "" {
		return zero, false
	}
	for _, entry := range list {
		item, ok := entry.(T)
		if ok && strings.EqualFold(item.GetId().Data, id) {
			return item, true
		}
	}
	return zero, false
}

func (a *mqlAzureSubscriptionWebServiceAppsite) appServicePlan() (*mqlAzureSubscriptionWebServiceAppServicePlan, error) {
	props, _ := a.Properties.Data.(map[string]any)
	planID := appsiteServerFarmID(props)
	if planID == "" {
		a.AppServicePlan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	svc, err := webServiceFor(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	plans := svc.GetAppServicePlans()
	if plans.Error != nil {
		return nil, plans.Error
	}
	plan, ok := findByID[*mqlAzureSubscriptionWebServiceAppServicePlan](plans.Data, planID)
	if !ok {
		a.AppServicePlan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return plan, nil
}

func (a *mqlAzureSubscriptionWebServiceAppsite) hostingEnvironment() (*mqlAzureSubscriptionWebServiceHostingEnvironment, error) {
	props, _ := a.Properties.Data.(map[string]any)
	envID := appsiteHostingEnvironmentID(props)
	if envID == "" {
		a.HostingEnvironment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	svc, err := webServiceFor(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	envs := svc.GetHostingEnvironments()
	if envs.Error != nil {
		return nil, envs.Error
	}
	env, ok := findByID[*mqlAzureSubscriptionWebServiceHostingEnvironment](envs.Data, envID)
	if !ok {
		a.HostingEnvironment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return env, nil
}

func initAzureSubscriptionWebServiceAppServicePlan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionWebService,
		func(s *mqlAzureSubscriptionWebService) *plugin.TValue[[]any] { return s.GetAppServicePlans() },
		ResourceAzureSubscriptionWebServiceAppServicePlan)
}

func initAzureSubscriptionWebServiceHostingEnvironment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionWebService,
		func(s *mqlAzureSubscriptionWebService) *plugin.TValue[[]any] { return s.GetHostingEnvironments() },
		ResourceAzureSubscriptionWebServiceHostingEnvironment)
}
