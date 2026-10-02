// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"sync"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/rs/zerolog/log"
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

// pimGroupChunkSize is how many groups one $batch call asks for. Graph caps a
// $batch payload at 20 sub-requests.
const pimGroupChunkSize = 19

// pimGroupConcurrency bounds how many $batch calls run at once, so a tenant
// with thousands of groups is not read one chunk at a time without tripping
// Graph throttling either.
const pimGroupConcurrency = 4

// listPerGroup lists PIM for Groups schedule instances one group at a time.
// Graph requires these collections to be filtered with groupId eq or
// principalId eq (an unfiltered list fails with MissingParameters), so each
// group is asked for separately, sent through $batch to keep the round trips
// down, with a few $batch calls in flight at once. A $batch sub-response keeps
// only the status of a failure, so a failed group is asked again directly to
// recover the error Graph gave, which is what tells a missing license from a
// missing permission.
//
// A failure that belongs to one group (it was deleted during the scan, or PIM
// cannot manage it) skips that group and keeps the others. A failure that
// holds for the whole tenant (401, a permission or license refusal,
// throttling, an unavailable service) fails the field.
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

	type chunkResult struct {
		items   []I
		read    int
		skipped []error
		err     error
	}
	chunks := chunkBatchRequests(reqs, pimGroupChunkSize)
	results := make([]chunkResult, len(chunks))
	sem := make(chan struct{}, pimGroupConcurrency)
	var wg sync.WaitGroup
	for i, chunk := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, chunk []batchItemRequest) {
			defer wg.Done()
			defer func() { <-sem }()
			out := &results[i]
			batch, err := batchGet[C](ctx, adapter, chunk, factory)
			if err != nil {
				out.err = classifyPimError(err, permission)
				return
			}
			for _, r := range chunk {
				id := r.key
				var page any
				if _, failed := batch.errs[id]; failed {
					page, err = direct(id)
					if err != nil {
						if isGroupLocalPimError(err) {
							log.Debug().Err(err).Str("group", id).Msg("ms365> skipping group in PIM for Groups list")
							out.skipped = append(out.skipped, err)
							continue
						}
						out.err = classifyPimError(err, permission)
						return
					}
				} else if coll, ok := batch.results[id]; ok {
					page = coll
				} else {
					out.read++
					continue
				}
				// a $batch sub-response carries only the first page
				items, err := iterate[I](ctx, page, adapter, factory)
				if err != nil {
					out.err = classifyPimError(err, permission)
					return
				}
				out.read++
				out.items = append(out.items, items...)
			}
		}(i, chunk)
	}
	wg.Wait()

	res := []I{}
	read := 0
	var skipped []error
	for _, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		read += r.read
		skipped = append(skipped, r.skipped...)
		res = append(res, r.items...)
	}
	// When every group failed, the failure is not about one group: the
	// request itself is wrong for this tenant. Report it instead of an empty
	// list that reads as "no PIM for Groups assignments".
	if read == 0 && len(skipped) > 0 {
		return nil, classifyPimError(skipped[0], permission)
	}
	if len(skipped) > 0 {
		log.Warn().Int("skipped", len(skipped)).Int("groups", len(groupIDs)).Msg("ms365> some groups could not be read for PIM for Groups and were skipped")
	}
	return res, nil
}

// chunkBatchRequests splits reqs into consecutive chunks of at most size
// requests, keeping their order.
func chunkBatchRequests(reqs []batchItemRequest, size int) [][]batchItemRequest {
	var chunks [][]batchItemRequest
	for start := 0; start < len(reqs); start += size {
		end := min(start+size, len(reqs))
		chunks = append(chunks, reqs[start:end])
	}
	return chunks
}

// isGroupLocalPimError reports whether a failed PIM for Groups request is
// about the one group it named rather than the tenant: a 404 (the group was
// deleted during the scan) or a 400 other than the license refusal (PIM cannot
// manage that group). A 401, 403, 429, 5xx, a license refusal, or a transport
// failure with no status holds for every group, so it is not group-local.
func isGroupLocalPimError(err error) bool {
	if isPremiumLicenseRequired(err) {
		return false
	}
	switch graphStatusCode(err) {
	case http.StatusNotFound, http.StatusBadRequest:
		return true
	}
	return false
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
		"startDateTime":        graphTimeData(inst.GetStartDateTime()),
		"endDateTime":          graphTimeData(inst.GetEndDateTime()),
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
		"startDateTime":         graphTimeData(inst.GetStartDateTime()),
		"endDateTime":           graphTimeData(inst.GetEndDateTime()),
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
