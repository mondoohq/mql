// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// adminSDKClient returns an SDK client authenticated with the organization
// admin key.
//
// The connection's own client carries the workspace API key, which the
// organization endpoints reject. Both keys travel in the same header, so the
// only difference is which credential is used.
func adminSDKClient(runtime *plugin.Runtime) (*anthropic.Client, error) {
	c := conn(runtime)
	if c.AdminToken() == "" {
		return nil, fmt.Errorf("admin API key required: set --admin-token or ANTHROPIC_ADMIN_API_KEY")
	}
	client := anthropic.NewClient(
		option.WithAPIKey(c.AdminToken()),
		option.WithBaseURL(c.Host()),
	)
	return &client, nil
}

// nullableTime returns nil for the zero time so an absent timestamp reaches
// MQL as null. The SDK decodes a JSON null into the zero time, which would
// otherwise report 1 January year 1 as a real date.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// nullableString returns nil for the empty string so an absent value reaches
// MQL as null rather than as "", which compares unequal to every real value
// while looking like one.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// rawJSONDict decodes the SDK's captured response body for a nested object
// into the map a dict field expects. An object the API omitted arrives as an
// empty raw string and reads as null rather than as an empty object.
func rawJSONDict(raw string) (map[string]any, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("decoding nested object: %w", err)
	}
	return out, nil
}

// organizationList reads one of the lists hanging off the shared
// claude.organization resource.
func organizationList(runtime *plugin.Runtime, get func(*mqlClaudeOrganization) *plugin.TValue[[]any]) ([]any, error) {
	res, err := CreateResource(runtime, "claude.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := get(res.(*mqlClaudeOrganization))
	if list.Error != nil {
		return nil, list.Error
	}
	return list.Data, nil
}

// claude.organization.serviceAccount

func (r *mqlClaudeOrganization) serviceAccounts() ([]any, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	pager := client.Beta.Organization.ServiceAccounts.ListAutoPaging(
		context.Background(), anthropic.BetaOrganizationServiceAccountListParams{})

	var res []any
	for pager.Next() {
		sa := pager.Current()
		mqlSA, err := CreateResource(r.MqlRuntime, "claude.organization.serviceAccount",
			serviceAccountArgs(sa))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSA)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing service accounts: %w", err)
	}
	return res, nil
}

// serviceAccountArgs maps a service account onto resource arguments.
func serviceAccountArgs(sa anthropic.BetaServiceAccount) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":              llx.StringData(sa.ID),
		"id":                llx.StringData(sa.ID),
		"name":              llx.StringData(sa.Name),
		"description":       llx.StringData(sa.Description),
		"organizationRole":  llx.StringData(string(sa.OrganizationRole)),
		"createdAt":         llx.TimeDataPtr(nullableTime(sa.CreatedAt)),
		"updatedAt":         llx.TimeDataPtr(nullableTime(sa.UpdatedAt)),
		"archivedAt":        llx.TimeDataPtr(nullableTime(sa.ArchivedAt)),
		"createdByActorId":  llx.StringData(sa.CreatedByActorID),
		"updatedByActorId":  llx.StringDataPtr(nullableString(sa.UpdatedByActorID)),
		"archivedByActorId": llx.StringDataPtr(nullableString(sa.ArchivedByActorID)),
	}
}

// claude.organization.federationIssuer

func (r *mqlClaudeOrganization) federationIssuers() ([]any, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	pager := client.Beta.Organization.Federation.Issuers.ListAutoPaging(
		context.Background(), anthropic.BetaOrganizationFederationIssuerListParams{})

	var res []any
	for pager.Next() {
		iss := pager.Current()
		args, err := federationIssuerArgs(iss)
		if err != nil {
			return nil, err
		}
		mqlIssuer, err := CreateResource(r.MqlRuntime, "claude.organization.federationIssuer", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIssuer)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing federation issuers: %w", err)
	}
	return res, nil
}

// federationIssuerArgs maps a federation issuer onto resource arguments.
func federationIssuerArgs(iss anthropic.BetaFederationIssuer) (map[string]*llx.RawData, error) {
	pollStatus, err := rawJSONDict(iss.PollStatus.RawJSON())
	if err != nil {
		return nil, err
	}
	jwks, err := rawJSONDict(iss.JWKS.RawJSON())
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"__id":                  llx.StringData(iss.ID),
		"id":                    llx.StringData(iss.ID),
		"name":                  llx.StringData(iss.Name),
		"issuerUrl":             llx.StringData(iss.IssuerURL),
		"checkJti":              llx.BoolData(iss.CheckJTI),
		"maxJwtLifetimeSeconds": llx.IntData(iss.MaxJWTLifetimeSeconds),
		"jwksPollingDisabledAt": llx.TimeDataPtr(nullableTime(iss.JWKSPollingDisabledAt)),
		"pollStatus":            llx.DictData(pollStatus),
		"jwks":                  llx.DictData(jwks),
		"createdAt":             llx.TimeDataPtr(nullableTime(iss.CreatedAt)),
		"updatedAt":             llx.TimeDataPtr(nullableTime(iss.UpdatedAt)),
		"archivedAt":            llx.TimeDataPtr(nullableTime(iss.ArchivedAt)),
		"createdByActorId":      llx.StringData(iss.CreatedByActorID),
	}, nil
}

// rules lists the federation rules that accept tokens from this issuer.
//
// The rules are listed once for the organization and filtered here rather than
// fetched per issuer, so an organization with many issuers still costs one
// call.
func (r *mqlClaudeOrganizationFederationIssuer) rules() ([]any, error) {
	rules, err := organizationList(r.MqlRuntime, func(o *mqlClaudeOrganization) *plugin.TValue[[]any] {
		return o.GetFederationRules()
	})
	if err != nil {
		return nil, err
	}

	issuerID := r.Id.Data
	res := []any{}
	for _, item := range rules {
		rule, ok := item.(*mqlClaudeOrganizationFederationRule)
		if !ok {
			continue
		}
		if rule.cacheIssuerID == issuerID {
			res = append(res, rule)
		}
	}
	return res, nil
}

// claude.organization.federationRule

type mqlClaudeOrganizationFederationRuleInternal struct {
	cacheIssuerID         string
	cacheServiceAccountID string
	cacheWorkspaceIDs     []string
}

func (r *mqlClaudeOrganization) federationRules() ([]any, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	pager := client.Beta.Organization.Federation.Rules.ListAutoPaging(
		context.Background(), anthropic.BetaOrganizationFederationRuleListParams{})

	var res []any
	for pager.Next() {
		rule := pager.Current()
		args, err := federationRuleArgs(rule)
		if err != nil {
			return nil, err
		}
		mqlRule, err := CreateResource(r.MqlRuntime, "claude.organization.federationRule", args)
		if err != nil {
			return nil, err
		}

		ref := mqlRule.(*mqlClaudeOrganizationFederationRule)
		ref.cacheIssuerID = rule.IssuerID
		ref.cacheServiceAccountID = rule.Target.ServiceAccountID
		ref.cacheWorkspaceIDs = federationRuleWorkspaceIDs(rule)

		res = append(res, mqlRule)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing federation rules: %w", err)
	}
	return res, nil
}

// federationRuleWorkspaceIDs collects the workspaces a rule names.
//
// The API reports a single workspace on WorkspaceID and a list on
// WorkspaceIDs depending on how the rule was written. Reading only one of them
// under-reports the rule's reach, so both are merged and de-duplicated.
func federationRuleWorkspaceIDs(rule anthropic.BetaFederationRule) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range append([]string{rule.WorkspaceID}, rule.WorkspaceIDs...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// federationRuleArgs maps a federation rule onto resource arguments.
func federationRuleArgs(rule anthropic.BetaFederationRule) (map[string]*llx.RawData, error) {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(rule.ID),
		"id":                     llx.StringData(rule.ID),
		"name":                   llx.StringData(rule.Name),
		"description":            llx.StringData(rule.Description),
		"appliesToAllWorkspaces": llx.BoolData(rule.AppliesToAllWorkspaces),
		"matchAudience":          llx.StringDataPtr(nullableString(rule.Match.Audience)),
		"matchSubjectPrefix":     llx.StringDataPtr(nullableString(rule.Match.SubjectPrefix)),
		"matchClaims":            llx.MapData(toInterfaceMap(rule.Match.Claims), types.String),
		"matchCondition":         llx.StringDataPtr(nullableString(rule.Match.Condition)),
		"attributes":             llx.MapData(toInterfaceMap(rule.Attributes), types.String),
		"oauthScope":             llx.StringData(rule.OAuthScope),
		"tokenLifetimeSeconds":   llx.IntData(rule.TokenLifetimeSeconds),
		"createdAt":              llx.TimeDataPtr(nullableTime(rule.CreatedAt)),
		"updatedAt":              llx.TimeDataPtr(nullableTime(rule.UpdatedAt)),
		"archivedAt":             llx.TimeDataPtr(nullableTime(rule.ArchivedAt)),
		"createdByActorId":       llx.StringData(rule.CreatedByActorID),
	}, nil
}

func (r *mqlClaudeOrganizationFederationRule) issuer() (*mqlClaudeOrganizationFederationIssuer, error) {
	found, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationFederationIssuer](
		r.MqlRuntime, r.cacheIssuerID,
		func(o *mqlClaudeOrganization) *plugin.TValue[[]any] { return o.GetFederationIssuers() })
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Issuer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return found, nil
}

func (r *mqlClaudeOrganizationFederationRule) serviceAccount() (*mqlClaudeOrganizationServiceAccount, error) {
	found, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationServiceAccount](
		r.MqlRuntime, r.cacheServiceAccountID,
		func(o *mqlClaudeOrganization) *plugin.TValue[[]any] { return o.GetServiceAccounts() })
	if err != nil {
		return nil, err
	}
	if !ok {
		r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return found, nil
}

func (r *mqlClaudeOrganizationFederationRule) workspaces() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheWorkspaceIDs {
		found, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationWorkspace](
			r.MqlRuntime, id,
			func(o *mqlClaudeOrganization) *plugin.TValue[[]any] { return o.GetWorkspaces() })
		if err != nil {
			return nil, err
		}
		if ok {
			res = append(res, found)
		}
	}
	return res, nil
}
