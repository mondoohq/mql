// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// Least privileged permissions: PrivilegedAssignmentSchedule.Read.AzureADGroup
func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagement) groupAssignmentScheduleInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	groupIDs, err := tenantGroupIDs(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	builder := graphClient.IdentityGovernance().PrivilegedAccess().Group().AssignmentScheduleInstances()
	config := func(groupID string) *identitygovernance.PrivilegedAccessGroupAssignmentScheduleInstancesRequestBuilderGetRequestConfiguration {
		filter := odataEqFilter("groupId", groupID)
		return &identitygovernance.PrivilegedAccessGroupAssignmentScheduleInstancesRequestBuilderGetRequestConfiguration{
			QueryParameters: &identitygovernance.PrivilegedAccessGroupAssignmentScheduleInstancesRequestBuilderGetQueryParameters{Filter: &filter},
		}
	}
	instances, err := listPerGroup[*models.PrivilegedAccessGroupAssignmentScheduleInstanceCollectionResponse, models.PrivilegedAccessGroupAssignmentScheduleInstanceable](
		ctx, graphClient, groupIDs,
		func(groupID string) (*abstractions.RequestInformation, error) {
			return builder.ToGetRequestInformation(ctx, config(groupID))
		},
		func(groupID string) (any, error) {
			return builder.Get(ctx, config(groupID))
		},
		models.CreatePrivilegedAccessGroupAssignmentScheduleInstanceCollectionResponseFromDiscriminatorValue,
		permPrivilegedAssignmentGroup,
	)
	if err != nil {
		return nil, err
	}
	return newGroupAssignmentScheduleInstances(ctx, a.MqlRuntime, graphClient, instances)
}

// tenantGroupIDs returns the IDs of every group in the tenant, read from the
// cached microsoft.groups list.
func tenantGroupIDs(runtime *plugin.Runtime) ([]string, error) {
	res, err := CreateResource(runtime, "microsoft", nil)
	if err != nil {
		return nil, err
	}
	groups := res.(*mqlMicrosoft).GetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	list := groups.Data.GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	ids := make([]string, 0, len(list.Data))
	for _, item := range list.Data {
		if grp, ok := item.(*mqlMicrosoftGroup); ok && grp.Id.Data != "" {
			ids = append(ids, grp.Id.Data)
		}
	}
	return ids, nil
}

// listPerGroup lists PIM for Groups schedule instances one group at a time.
// Graph refuses an unfiltered list of these collections (MissingParameters:
// GroupId or PrincipalId), so each group is asked for separately, sent through
// $batch to keep the round trips down. A $batch sub-response keeps only the
// status of a failure, so a failed group is asked again directly to recover
// the error Graph gave, which is what tells a missing license from a missing
// permission.
func listPerGroup[C serialization.Parsable, I any](
	ctx context.Context,
	graphClient *msgraphsdkgo.GraphServiceClient,
	groupIDs []string,
	request func(groupID string) (*abstractions.RequestInformation, error),
	direct func(groupID string) (any, error),
	factory serialization.ParsableFactory,
	permission string,
) ([]I, error) {
	adapter := graphClient.GetAdapter()
	reqs := make([]batchItemRequest, 0, len(groupIDs))
	for _, id := range groupIDs {
		info, err := request(id)
		if err != nil {
			return nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: info})
	}
	batch, err := batchGet[C](ctx, adapter, reqs, factory)
	if err != nil {
		return nil, classifyPimError(err, permission)
	}

	res := []I{}
	for _, id := range groupIDs {
		var page any
		if _, failed := batch.errs[id]; failed {
			page, err = direct(id)
			if err != nil {
				return nil, classifyPimError(err, permission)
			}
		} else if coll, ok := batch.results[id]; ok {
			page = coll
		} else {
			continue
		}
		// a $batch sub-response carries only the first page
		items, err := iterate[I](ctx, page, adapter, factory)
		if err != nil {
			return nil, classifyPimError(err, permission)
		}
		res = append(res, items...)
	}
	return res, nil
}

func newGroupAssignmentScheduleInstances(ctx context.Context, runtime *plugin.Runtime, graphClient *msgraphsdkgo.GraphServiceClient, instances []models.PrivilegedAccessGroupAssignmentScheduleInstanceable) ([]any, error) {
	principalIDs := make([]string, 0, len(instances))
	for _, inst := range instances {
		principalIDs = append(principalIDs, strVal(inst.GetPrincipalId()))
	}
	principalTypes, err := principalTypesByID(ctx, graphClient, principalIDs)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, inst := range instances {
		if inst.GetId() == nil {
			continue
		}
		r, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupAssignmentScheduleInstance, groupAssignmentInstanceArgs(inst, principalTypes))
		if err != nil {
			return nil, err
		}
		mqlInst := r.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupAssignmentScheduleInstance)
		mqlInst.cacheGroupID = strVal(inst.GetGroupId())
		res = append(res, mqlInst)
	}
	return res, nil
}

// groupAssignmentInstanceArgs maps a PIM for Groups assignment schedule
// instance onto the fields of its MQL resource.
func groupAssignmentInstanceArgs(inst models.PrivilegedAccessGroupAssignmentScheduleInstanceable, principalTypes map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                 llx.StringDataPtr(inst.GetId()),
		"id":                   llx.StringDataPtr(inst.GetId()),
		"accessId":             llx.StringDataPtr(enumString(inst.GetAccessId())),
		"principalId":          llx.StringDataPtr(inst.GetPrincipalId()),
		"principalType":        llx.StringData(principalTypes[strVal(inst.GetPrincipalId())]),
		"assignmentType":       llx.StringDataPtr(enumString(inst.GetAssignmentType())),
		"memberType":           llx.StringDataPtr(enumString(inst.GetMemberType())),
		"startDateTime":        llx.TimeDataPtr(inst.GetStartDateTime()),
		"endDateTime":          llx.TimeDataPtr(inst.GetEndDateTime()),
		"assignmentScheduleId": llx.StringDataPtr(inst.GetAssignmentScheduleId()),
	}
}

// groupEligibilityInstanceArgs maps a PIM for Groups eligibility schedule
// instance onto the fields of its MQL resource.
func groupEligibilityInstanceArgs(inst models.PrivilegedAccessGroupEligibilityScheduleInstanceable, principalTypes map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                  llx.StringDataPtr(inst.GetId()),
		"id":                    llx.StringDataPtr(inst.GetId()),
		"accessId":              llx.StringDataPtr(enumString(inst.GetAccessId())),
		"principalId":           llx.StringDataPtr(inst.GetPrincipalId()),
		"principalType":         llx.StringData(principalTypes[strVal(inst.GetPrincipalId())]),
		"memberType":            llx.StringDataPtr(enumString(inst.GetMemberType())),
		"startDateTime":         llx.TimeDataPtr(inst.GetStartDateTime()),
		"endDateTime":           llx.TimeDataPtr(inst.GetEndDateTime()),
		"eligibilityScheduleId": llx.StringDataPtr(inst.GetEligibilityScheduleId()),
	}
}

type mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupAssignmentScheduleInstanceInternal struct {
	cacheGroupID string
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupAssignmentScheduleInstance) group() (*mqlMicrosoftGroup, error) {
	return directoryRefByID(a.MqlRuntime, &a.Group, a.cacheGroupID, ResourceMicrosoftGroup)
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupAssignmentScheduleInstance) principalUser() (*mqlMicrosoftUser, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalUser, a.PrincipalType.Data, "user", a.PrincipalId.Data, ResourceMicrosoftUser)
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupAssignmentScheduleInstance) principalGroup() (*mqlMicrosoftGroup, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalGroup, a.PrincipalType.Data, "group", a.PrincipalId.Data, ResourceMicrosoftGroup)
}

// Least privileged permissions: PrivilegedEligibilitySchedule.Read.AzureADGroup
func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagement) groupEligibilityScheduleInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	groupIDs, err := tenantGroupIDs(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	builder := graphClient.IdentityGovernance().PrivilegedAccess().Group().EligibilityScheduleInstances()
	config := func(groupID string) *identitygovernance.PrivilegedAccessGroupEligibilityScheduleInstancesRequestBuilderGetRequestConfiguration {
		filter := odataEqFilter("groupId", groupID)
		return &identitygovernance.PrivilegedAccessGroupEligibilityScheduleInstancesRequestBuilderGetRequestConfiguration{
			QueryParameters: &identitygovernance.PrivilegedAccessGroupEligibilityScheduleInstancesRequestBuilderGetQueryParameters{Filter: &filter},
		}
	}
	instances, err := listPerGroup[*models.PrivilegedAccessGroupEligibilityScheduleInstanceCollectionResponse, models.PrivilegedAccessGroupEligibilityScheduleInstanceable](
		ctx, graphClient, groupIDs,
		func(groupID string) (*abstractions.RequestInformation, error) {
			return builder.ToGetRequestInformation(ctx, config(groupID))
		},
		func(groupID string) (any, error) {
			return builder.Get(ctx, config(groupID))
		},
		models.CreatePrivilegedAccessGroupEligibilityScheduleInstanceCollectionResponseFromDiscriminatorValue,
		permPrivilegedEligibilityGroup,
	)
	if err != nil {
		return nil, err
	}
	return newGroupEligibilityScheduleInstances(ctx, a.MqlRuntime, graphClient, instances)
}

func newGroupEligibilityScheduleInstances(ctx context.Context, runtime *plugin.Runtime, graphClient *msgraphsdkgo.GraphServiceClient, instances []models.PrivilegedAccessGroupEligibilityScheduleInstanceable) ([]any, error) {
	principalIDs := make([]string, 0, len(instances))
	for _, inst := range instances {
		principalIDs = append(principalIDs, strVal(inst.GetPrincipalId()))
	}
	principalTypes, err := principalTypesByID(ctx, graphClient, principalIDs)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, inst := range instances {
		if inst.GetId() == nil {
			continue
		}
		r, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupEligibilityScheduleInstance, groupEligibilityInstanceArgs(inst, principalTypes))
		if err != nil {
			return nil, err
		}
		mqlInst := r.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupEligibilityScheduleInstance)
		mqlInst.cacheGroupID = strVal(inst.GetGroupId())
		res = append(res, mqlInst)
	}
	return res, nil
}

type mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupEligibilityScheduleInstanceInternal struct {
	cacheGroupID string
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupEligibilityScheduleInstance) group() (*mqlMicrosoftGroup, error) {
	return directoryRefByID(a.MqlRuntime, &a.Group, a.cacheGroupID, ResourceMicrosoftGroup)
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupEligibilityScheduleInstance) principalUser() (*mqlMicrosoftUser, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalUser, a.PrincipalType.Data, "user", a.PrincipalId.Data, ResourceMicrosoftUser)
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementGroupEligibilityScheduleInstance) principalGroup() (*mqlMicrosoftGroup, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalGroup, a.PrincipalType.Data, "group", a.PrincipalId.Data, ResourceMicrosoftGroup)
}
