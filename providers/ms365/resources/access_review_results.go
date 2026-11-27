// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

const permAccessReviewRead = "AccessReview.Read.All"

func (a *mqlMicrosoftIdentityAndAccessAccessReviewDefinition) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	instances, err := fetchAccessReviewInstances(context.Background(), graphClient, a.Id.Data)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(instances))
	for _, inst := range instances {
		r, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessAccessReviewInstance, map[string]*llx.RawData{
			"__id":          llx.StringData(a.Id.Data + "/" + strVal(inst.GetId())),
			"id":            llx.StringDataPtr(inst.GetId()),
			"status":        llx.StringDataPtr(inst.GetStatus()),
			"startDateTime": graphTimeData(inst.GetStartDateTime()),
			"endDateTime":   graphTimeData(inst.GetEndDateTime()),
		})
		if err != nil {
			return nil, err
		}
		mqlInst := r.(*mqlMicrosoftIdentityAndAccessAccessReviewInstance)
		mqlInst.cacheDefinitionID = a.Id.Data
		res = append(res, mqlInst)
	}
	return res, nil
}

// fetchAccessReviewInstances lists every instance of an access review
// definition.
func fetchAccessReviewInstances(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, definitionID string) ([]models.AccessReviewInstanceable, error) {
	resp, err := graphClient.IdentityGovernance().AccessReviews().Definitions().ByAccessReviewScheduleDefinitionId(definitionID).Instances().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permAccessReviewRead)
	}
	all, err := iterate[models.AccessReviewInstanceable](ctx, resp, graphClient.GetAdapter(), models.CreateAccessReviewInstanceCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	res := make([]models.AccessReviewInstanceable, 0, len(all))
	for _, inst := range all {
		if inst != nil && inst.GetId() != nil && *inst.GetId() != "" {
			res = append(res, inst)
		}
	}
	return res, nil
}

type mqlMicrosoftIdentityAndAccessAccessReviewInstanceInternal struct {
	cacheDefinitionID string
}

func (a *mqlMicrosoftIdentityAndAccessAccessReviewInstance) decisions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	items, err := fetchAccessReviewDecisions(context.Background(), graphClient, a.cacheDefinitionID, a.Id.Data)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(items))
	for _, item := range items {
		r, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessAccessReviewDecision, accessReviewDecisionArgs(a.__id, item))
		if err != nil {
			return nil, err
		}
		mqlDecision := r.(*mqlMicrosoftIdentityAndAccessAccessReviewDecision)
		if reviewer := item.GetReviewedBy(); reviewer != nil {
			mqlDecision.cacheReviewerID = reviewerID(reviewer.GetId())
		}
		res = append(res, mqlDecision)
	}
	return res, nil
}

// fetchAccessReviewDecisions lists every decision of one access review
// instance.
func fetchAccessReviewDecisions(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, definitionID, instanceID string) ([]models.AccessReviewInstanceDecisionItemable, error) {
	resp, err := graphClient.IdentityGovernance().AccessReviews().Definitions().ByAccessReviewScheduleDefinitionId(definitionID).
		Instances().ByAccessReviewInstanceId(instanceID).Decisions().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permAccessReviewRead)
	}
	all, err := iterate[models.AccessReviewInstanceDecisionItemable](ctx, resp, graphClient.GetAdapter(), models.CreateAccessReviewInstanceDecisionItemCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	res := make([]models.AccessReviewInstanceDecisionItemable, 0, len(all))
	for _, item := range all {
		if item != nil && item.GetId() != nil && *item.GetId() != "" {
			res = append(res, item)
		}
	}
	return res, nil
}

// accessReviewDecisionArgs maps one decision item onto the decision resource.
func accessReviewDecisionArgs(instanceKey string, item models.AccessReviewInstanceDecisionItemable) map[string]*llx.RawData {
	var principalID, principalDisplayName, principalType string
	if p := item.GetPrincipal(); p != nil {
		principalID = strVal(p.GetId())
		principalDisplayName = strVal(p.GetDisplayName())
		principalType = identityPrincipalType(p.GetOdataType())
	}
	var resourceID, resourceType, resourceDisplayName string
	if r := item.GetResource(); r != nil {
		resourceID = strVal(r.GetId())
		resourceType = strVal(r.GetTypeEscaped())
		resourceDisplayName = strVal(r.GetDisplayName())
	}
	return map[string]*llx.RawData{
		"__id":                 llx.StringData(instanceKey + "/" + strVal(item.GetId())),
		"id":                   llx.StringDataPtr(item.GetId()),
		"decision":             llx.StringDataPtr(item.GetDecision()),
		"recommendation":       llx.StringDataPtr(item.GetRecommendation()),
		"justification":        llx.StringDataPtr(item.GetJustification()),
		"reviewedDateTime":     graphTimeData(item.GetReviewedDateTime()),
		"appliedDateTime":      graphTimeData(item.GetAppliedDateTime()),
		"applyResult":          llx.StringDataPtr(item.GetApplyResult()),
		"principalId":          llx.StringData(principalID),
		"principalType":        llx.StringData(principalType),
		"principalDisplayName": llx.StringData(principalDisplayName),
		"resourceId":           llx.StringData(resourceID),
		"resourceType":         llx.StringData(resourceType),
		"resourceDisplayName":  llx.StringData(resourceDisplayName),
	}
}

// identityPrincipalType turns the type of a Graph identity
// ("#microsoft.graph.userIdentity") into the principal type this provider
// uses ("user"), or "" for an identity type it does not resolve.
func identityPrincipalType(odataType *string) string {
	switch strings.ToLower(strings.TrimPrefix(strVal(odataType), "#")) {
	case "microsoft.graph.useridentity":
		return "user"
	case "microsoft.graph.serviceprincipalidentity":
		return "servicePrincipal"
	}
	return ""
}

// reviewerID returns the reviewer's user id, or "" when the decision carries
// no human reviewer: Graph reports an empty or all-zero id for a decision
// nobody has made yet and for one the system applied.
func reviewerID(id *string) string {
	v := strings.TrimSpace(strVal(id))
	if strings.Trim(v, "0-") == "" {
		return ""
	}
	return v
}

type mqlMicrosoftIdentityAndAccessAccessReviewDecisionInternal struct {
	cacheReviewerID string
}

func (a *mqlMicrosoftIdentityAndAccessAccessReviewDecision) reviewedBy() (*mqlMicrosoftUser, error) {
	if a.cacheReviewerID == "" {
		a.ReviewedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftUser, map[string]*llx.RawData{"id": llx.StringData(a.cacheReviewerID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftUser), nil
}

func (a *mqlMicrosoftIdentityAndAccessAccessReviewDecision) principalUser() (*mqlMicrosoftUser, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalUser, a.PrincipalType.Data, "user", a.PrincipalId.Data, ResourceMicrosoftUser)
}

func (a *mqlMicrosoftIdentityAndAccessAccessReviewDecision) principalServicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalServicePrincipal, a.PrincipalType.Data, "servicePrincipal", a.PrincipalId.Data, ResourceMicrosoftServiceprincipal)
}

func (a *mqlMicrosoftIdentityAndAccessAccessReviewDecision) resourceGroup() (*mqlMicrosoftGroup, error) {
	if !strings.EqualFold(a.ResourceType.Data, "group") {
		a.ResourceGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return principalOfType(a.MqlRuntime, &a.ResourceGroup, "group", "group", a.ResourceId.Data, ResourceMicrosoftGroup)
}
