// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"github.com/microsoftgraph/msgraph-sdk-go/identityprotection"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// riskyUsersFilter selects the users who are currently at risk. A user an admin
// confirmed as compromised is the most severe case and carries the
// confirmedCompromised state instead of atRisk, so both states are included.
// Remediated, dismissed and none are users no longer at risk.
const riskyUsersFilter = "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"

// riskyUsers returns a list of risky users
// requires IdentityRiskyUser.Read.All permission
// see https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0
func (a *mqlMicrosoftSecurity) riskyUsers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	filter := riskyUsersFilter
	resp, err := graphClient.IdentityProtection().RiskyUsers().Get(ctx, &identityprotection.RiskyUsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &identityprotection.RiskyUsersRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})
	if err != nil {
		return nil, transformError(err)
	}
	users, err := iterate[models.RiskyUserable](ctx, resp, graphClient.GetAdapter(), models.CreateRiskyUserCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range users {
		riskyUser := users[i]
		mqlResource, err := newMqlMicrosoftRiskyUser(a.MqlRuntime, riskyUser)
		if err != nil {
			return nil, err
		}

		res = append(res, mqlResource)
	}
	return res, nil
}

func newMqlMicrosoftRiskyUser(runtime *plugin.Runtime, riskyUser models.RiskyUserable) (*mqlMicrosoftSecurityRiskyUser, error) {
	if riskyUser == nil {
		return nil, nil
	}

	var detail *string
	if riskyUser.GetRiskDetail() != nil {
		detailData := riskyUser.GetRiskDetail().String()
		detail = &detailData
	}

	var riskLevel *string
	if riskyUser.GetRiskLevel() != nil {
		riskLevelData := riskyUser.GetRiskLevel().String()
		riskLevel = &riskLevelData
	}

	var riskState *string
	if riskyUser.GetRiskState() != nil {
		riskStateData := riskyUser.GetRiskState().String()
		riskState = &riskStateData
	}

	mqlResource, err := CreateResource(runtime, "microsoft.security.riskyUser",
		map[string]*llx.RawData{
			"__id":          llx.StringDataPtr(riskyUser.GetId()),
			"id":            llx.StringDataPtr(riskyUser.GetId()),
			"name":          llx.StringDataPtr(riskyUser.GetUserDisplayName()),
			"principalName": llx.StringDataPtr(riskyUser.GetUserPrincipalName()),
			"riskDetail":    llx.StringDataPtr(detail),
			"riskLevel":     llx.StringDataPtr(riskLevel),
			"riskState":     llx.StringDataPtr(riskState),
			"lastUpdatedAt": llx.TimeDataPtr(riskyUser.GetRiskLastUpdatedDateTime()),
			"isDeleted":     llx.BoolDataPtr(riskyUser.GetIsDeleted()),
			"isProcessing":  llx.BoolDataPtr(riskyUser.GetIsProcessing()),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftSecurityRiskyUser), nil
}

func (r *mqlMicrosoftSecurityRiskyUser) user() (*mqlMicrosoftUser, error) {
	user, err := NewResource(r.MqlRuntime, "microsoft.user", map[string]*llx.RawData{
		"id": llx.StringData(r.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return user.(*mqlMicrosoftUser), nil
}
