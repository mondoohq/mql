// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// accessReviewReviewerScopeTypes name the well-known reviewers Microsoft Graph
// reports for an access review reviewer scope.
const (
	accessReviewReviewerScopeTypeUser  = "user"
	accessReviewReviewerScopeTypeGroup = "group"
)

// accessReviewReviewerScopeType renders the reviewer scope type Microsoft Graph
// reported. An absent scope type reads as an empty string rather than as the
// Kiota enum's zero value: that zero value is "user", so dereferencing without
// the nil check would report every query-selected reviewer as a directly named
// user.
func accessReviewReviewerScopeType(scopeType *models.AccessReviewReviewerScopeType) string {
	if scopeType == nil {
		return ""
	}
	return scopeType.String()
}

// newMqlAccessReviewReviewerScopes maps the reviewer scopes of one access
// review schedule definition. A reviewer scope carries no identifier of its
// own, so the cache key is the definition it belongs to plus the position of
// the entry: two scopes on the same definition are otherwise free to hold
// identical values and would collapse onto one cached resource.
func newMqlAccessReviewReviewerScopes(runtime *plugin.Runtime, definitionID string, reviewers []models.AccessReviewReviewerScopeable) ([]any, error) {
	res := []any{}
	for i, reviewer := range reviewers {
		if reviewer == nil {
			continue
		}
		resource, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessAccessReviewDefinitionReviewerScope,
			newAccessReviewReviewerScopeArgs(definitionID, i, reviewer))
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

// newAccessReviewReviewerScopeArgs maps one reviewer scope onto the arguments
// of the reviewer scope resource.
func newAccessReviewReviewerScopeArgs(definitionID string, index int, reviewer models.AccessReviewReviewerScopeable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(fmt.Sprintf("%s/reviewerScopes/%d", definitionID, index)),
		"query":      llx.StringDataPtr(reviewer.GetQuery()),
		"queryType":  llx.StringDataPtr(reviewer.GetQueryType()),
		"queryRoot":  llx.StringDataPtr(reviewer.GetQueryRoot()),
		"reviewerId": llx.StringDataPtr(reviewer.GetReviewerId()),
		"scopeType":  llx.StringData(accessReviewReviewerScopeType(reviewer.GetScopeType())),
	}
}

// user resolves the reviewing user a scope names directly.
func (m *mqlMicrosoftIdentityAndAccessAccessReviewDefinitionReviewerScope) user() (*mqlMicrosoftUser, error) {
	if m.ScopeType.Data != accessReviewReviewerScopeTypeUser || m.ReviewerId.Data == "" {
		m.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, ResourceMicrosoftUser, map[string]*llx.RawData{
		"id": llx.StringData(m.ReviewerId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftUser), nil
}

// group resolves the reviewing group a scope names directly.
func (m *mqlMicrosoftIdentityAndAccessAccessReviewDefinitionReviewerScope) group() (*mqlMicrosoftGroup, error) {
	if m.ScopeType.Data != accessReviewReviewerScopeTypeGroup || m.ReviewerId.Data == "" {
		m.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, ResourceMicrosoftGroup, map[string]*llx.RawData{
		"id": llx.StringData(m.ReviewerId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftGroup), nil
}
