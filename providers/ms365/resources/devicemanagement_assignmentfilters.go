// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// assignmentFilters lists the Intune assignment filters used to scope policy
// and app assignments. Uses the beta Graph SDK because v1 does not expose
// /deviceManagement/assignmentFilters.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) assignmentFilters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().AssignmentFilters().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	filters, err := iterate[betamodels.DeviceAndAppManagementAssignmentFilterable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDeviceAndAppManagementAssignmentFilterCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, f := range filters {
		mqlFilter, err := newMqlAssignmentFilter(a.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFilter)
	}
	return res, nil
}

func newMqlAssignmentFilter(runtime *plugin.Runtime, f betamodels.DeviceAndAppManagementAssignmentFilterable) (plugin.Resource, error) {
	return CreateResource(runtime, "microsoft.devicemanagement.assignmentFilter",
		map[string]*llx.RawData{
			"__id":                           llx.StringDataPtr(f.GetId()),
			"id":                             llx.StringDataPtr(f.GetId()),
			"displayName":                    llx.StringDataPtr(f.GetDisplayName()),
			"description":                    llx.StringDataPtr(f.GetDescription()),
			"platform":                       llx.StringDataPtr(enumPtrString(f.GetPlatform())),
			"rule":                           llx.StringDataPtr(f.GetRule()),
			"assignmentFilterManagementType": llx.StringDataPtr(enumPtrString(f.GetAssignmentFilterManagementType())),
			"roleScopeTags":                  llx.ArrayData(llx.TArr2Raw(f.GetRoleScopeTags()), types.String),
			"createdDateTime":                graphTimeData(f.GetCreatedDateTime()),
			"lastModifiedDateTime":           graphTimeData(f.GetLastModifiedDateTime()),
		})
}

// initMicrosoftDevicemanagementAssignmentFilter resolves a single assignment
// filter by its ID, enabling the typed policyAssignment.filter reference.
func initMicrosoftDevicemanagementAssignmentFilter(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	rawId, ok := args["id"]
	if !ok {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, nil, err
	}
	f, err := graphClient.DeviceManagement().AssignmentFilters().
		ByDeviceAndAppManagementAssignmentFilterId(rawId.Value.(string)).
		Get(context.Background(), nil)
	if err != nil {
		return nil, nil, transformError(err)
	}
	mqlFilter, err := newMqlAssignmentFilter(runtime, f)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlFilter, nil
}

// filter resolves the assignment filter applied to the target, when one is set.
func (m *mqlMicrosoftDevicemanagementPolicyAssignment) filter() (*mqlMicrosoftDevicemanagementAssignmentFilter, error) {
	id := m.cacheFilterID
	if id == "" {
		m.Filter.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "microsoft.devicemanagement.assignmentFilter", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftDevicemanagementAssignmentFilter), nil
}
