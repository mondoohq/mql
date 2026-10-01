// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// claude.organization.effectiveSpendLimit

type mqlClaudeOrganizationEffectiveSpendLimitInternal struct {
	cacheUserID            string
	cacheSourceRbacGroupID string
	cacheSourceWorkspaceID string
}

func (r *mqlClaudeOrganization) effectiveSpendLimits() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	rows, err := collectCursorPages(client.Beta.Organization.SpendLimits.Effective.List(
		context.Background(), anthropic.BetaOrganizationSpendLimitEffectiveListParams{Limit: anthropic.Int(100)}))
	if err != nil {
		return nil, classifyAdminError(fmt.Errorf("listing effective spend limits: %w", err), endpointUnavailable)
	}

	res := make([]interface{}, 0, len(rows))
	for _, row := range rows {
		args, err := effectiveSpendLimitArgs(row)
		if err != nil {
			return nil, err
		}
		mqlRow, err := CreateResource(r.MqlRuntime, "claude.organization.effectiveSpendLimit", args)
		if err != nil {
			return nil, err
		}
		limit := mqlRow.(*mqlClaudeOrganizationEffectiveSpendLimit)
		limit.cacheUserID = effectiveSpendLimitUserID(row)
		limit.cacheSourceRbacGroupID = row.Source.RBACGroupID
		limit.cacheSourceWorkspaceID = row.Source.WorkspaceID
		res = append(res, mqlRow)
	}
	return res, nil
}

// effectiveSpendLimitUserID names the member a row is for. The actor carries
// the id for a user; a user-scoped row names the same member in its scope,
// which is used when the actor does not.
func effectiveSpendLimitUserID(row anthropic.BetaSpendSummary) string {
	if row.Actor.UserID != "" {
		return row.Actor.UserID
	}
	return row.Scope.UserID
}

// effectiveSpendLimitArgs maps an effective spend limit row onto resource
// arguments.
//
// The API sends both amounts as decimal strings in the currency's minor unit.
// They are read as numbers so a policy can compare spend against the limit.
// A null amount means no limit applies for the period, which has to stay null:
// zero would read as a limit that blocks all spend.
func effectiveSpendLimitArgs(row anthropic.BetaSpendSummary) (map[string]*llx.RawData, error) {
	amount := llx.NilData
	if row.JSON.Amount.Valid() && row.Amount != "" {
		v, err := strconv.ParseInt(row.Amount, 10, 64)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("parsing spend limit amount %q: %w", row.Amount, err))
		}
		amount = llx.IntData(v)
	}

	spend := llx.NilData
	if row.JSON.PeriodToDateSpend.Valid() && row.PeriodToDateSpend != "" {
		v, err := strconv.ParseFloat(row.PeriodToDateSpend, 64)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("parsing period-to-date spend %q: %w", row.PeriodToDateSpend, err))
		}
		spend = llx.FloatData(v)
	}

	actorID := row.Actor.UserID
	if actorID == "" {
		actorID = row.Actor.ScopedAPIKeyID
	}
	key := strings.Join([]string{
		"spend", row.Actor.Type, actorID, string(row.Period),
		row.Scope.Type, row.Scope.UserID + row.Scope.WorkspaceID + row.Scope.RBACGroupID + row.Scope.SeatTier + row.Scope.Service,
	}, "/")

	return map[string]*llx.RawData{
		"__id":              llx.StringData(key),
		"actorType":         llx.StringDataPtr(nullableString(row.Actor.Type)),
		"actorEmail":        llx.StringDataPtr(nullableString(row.Actor.EmailAddress)),
		"scopedApiKeyId":    llx.StringDataPtr(nullableString(row.Actor.ScopedAPIKeyID)),
		"period":            llx.StringData(string(row.Period)),
		"amount":            amount,
		"periodToDateSpend": spend,
		"currency":          llx.StringData(row.Currency),
		"scopeType":         llx.StringDataPtr(nullableString(row.Scope.Type)),
		"sourceType":        llx.StringDataPtr(nullableString(row.Source.Type)),
		"sourceSeatTier":    llx.StringDataPtr(nullableString(row.Source.SeatTier)),
		"sourceService":     llx.StringDataPtr(nullableString(row.Source.Service)),
		"spendLimitId":      llx.StringDataPtr(nullableString(row.SpendLimitID)),
	}, nil
}

func (r *mqlClaudeOrganizationEffectiveSpendLimit) user() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cacheUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.User.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

func (r *mqlClaudeOrganizationEffectiveSpendLimit) sourceRbacGroup() (*mqlClaudeOrganizationRbacGroup, error) {
	group, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationRbacGroup](
		r.MqlRuntime, r.cacheSourceRbacGroupID, (*mqlClaudeOrganization).GetRbacGroups)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.SourceRbacGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return group, nil
}

func (r *mqlClaudeOrganizationEffectiveSpendLimit) sourceWorkspace() (*mqlClaudeOrganizationWorkspace, error) {
	ws, ok, err := lookupWorkspace(r.MqlRuntime, r.cacheSourceWorkspaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.SourceWorkspace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return ws, nil
}
