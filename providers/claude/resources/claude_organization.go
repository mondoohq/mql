// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/claude/connection"
	"go.mondoo.com/mql/types"
)

// lookupWorkspace returns the organization workspace carrying the given id.
func lookupWorkspace(runtime *plugin.Runtime, id string) (*mqlClaudeOrganizationWorkspace, bool, error) {
	return lookupOrganizationChild[*mqlClaudeOrganizationWorkspace](runtime, id, (*mqlClaudeOrganization).GetWorkspaces)
}

// lookupMember returns the organization member carrying the given id.
func lookupMember(runtime *plugin.Runtime, id string) (*mqlClaudeOrganizationMember, bool, error) {
	return lookupOrganizationChild[*mqlClaudeOrganizationMember](runtime, id, (*mqlClaudeOrganization).GetMembers)
}

// claude.organization

// workspaceArgs maps an organization workspace onto resource arguments.
func workspaceArgs(w connection.AdminWorkspace) (map[string]*llx.RawData, error) {
	createdAt, err := parseTime(w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing workspace createdAt: %w", err)
	}

	// A live workspace has no archive date at all. Reporting the zero time
	// would date every active workspace to year 1 and make it read as the
	// oldest archived workspace in the organization.
	var archivedAt *time.Time
	if w.ArchivedAt != nil && *w.ArchivedAt != "" {
		parsed, err := parseTime(*w.ArchivedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing workspace archivedAt: %w", err)
		}
		archivedAt = &parsed
	}

	var workspaceGeo, defaultInferenceGeo string
	var allowedInferenceGeos []interface{}
	if w.DataResidency != nil {
		workspaceGeo = w.DataResidency.WorkspaceGeo
		defaultInferenceGeo = w.DataResidency.DefaultInferenceGeo
		allowedInferenceGeos = toInterfaceSlice(w.DataResidency.AllowedInferenceGeos)
	}
	if allowedInferenceGeos == nil {
		allowedInferenceGeos = []interface{}{}
	}

	return map[string]*llx.RawData{
		"__id":         llx.StringData(w.ID),
		"id":           llx.StringData(w.ID),
		"name":         llx.StringData(w.Name),
		"displayColor": llx.StringData(w.DisplayColor),
		"createdAt":    llx.TimeData(createdAt),
		"archivedAt":   llx.TimeDataPtr(archivedAt),
		// A workspace on Anthropic-managed encryption has no key at all,
		// which has to read as null. An empty string would make
		// "every workspace has a customer-managed key" look satisfiable by
		// a workspace that has none.
		"externalKeyId":        llx.StringDataPtr(w.ExternalKeyID),
		"compartmentId":        llx.StringDataPtr(nullableString(w.CompartmentID)),
		"tags":                 llx.MapData(toInterfaceMap(w.Tags), types.String),
		"workspaceGeo":         llx.StringData(workspaceGeo),
		"defaultInferenceGeo":  llx.StringData(defaultInferenceGeo),
		"allowedInferenceGeos": llx.ArrayData(allowedInferenceGeos, types.String),
	}, nil
}

func (r *mqlClaudeOrganization) workspaces() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	workspaces, err := admin.ListWorkspaces(context.Background())
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(workspaces))
	for _, w := range workspaces {
		args, err := workspaceArgs(w)
		if err != nil {
			return nil, err
		}

		mqlWs, err := CreateResource(r.MqlRuntime, "claude.organization.workspace", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlWs)
	}

	return res, nil
}

func (r *mqlClaudeOrganization) members() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	users, err := admin.ListUsers(context.Background())
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(users))
	for _, u := range users {
		addedAt, err := parseTime(u.AddedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing member addedAt: %w", err)
		}

		mqlMember, err := CreateResource(r.MqlRuntime, "claude.organization.member", map[string]*llx.RawData{
			"__id":    llx.StringData(u.ID),
			"id":      llx.StringData(u.ID),
			"name":    llx.StringData(u.Name),
			"email":   llx.StringData(u.Email),
			"role":    llx.StringData(u.Role),
			"addedAt": llx.TimeData(addedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlMember)
	}

	return res, nil
}

func (r *mqlClaudeOrganization) invites() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	invites, err := admin.ListInvites(context.Background())
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(invites))
	for _, inv := range invites {
		invitedAt, err := parseTime(inv.InvitedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing invite invitedAt: %w", err)
		}
		expiresAt, err := parseTime(inv.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("parsing invite expiresAt: %w", err)
		}

		mqlInvite, err := CreateResource(r.MqlRuntime, "claude.organization.invite", map[string]*llx.RawData{
			"__id":      llx.StringData(inv.ID),
			"id":        llx.StringData(inv.ID),
			"email":     llx.StringData(inv.Email),
			"role":      llx.StringData(inv.Role),
			"status":    llx.StringData(inv.Status),
			"invitedAt": llx.TimeData(invitedAt),
			"expiresAt": llx.TimeData(expiresAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInvite)
	}

	return res, nil
}

type mqlClaudeOrganizationApiKeyInternal struct {
	cacheWorkspaceID               *string
	cacheCreatedByID               string
	cachePrincipalUserID           string
	cachePrincipalServiceAccountID string
}

func (r *mqlClaudeOrganization) apiKeys() ([]interface{}, error) {
	client, err := adminSDKClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	pager := client.Beta.Organization.APIKeys.ListAutoPaging(
		context.Background(), anthropic.BetaOrganizationAPIKeyListParams{})

	var res []interface{}
	for pager.Next() {
		k := pager.Current()

		mqlKey, err := CreateResource(r.MqlRuntime, "claude.organization.apiKey", apiKeyArgs(k))
		if err != nil {
			return nil, err
		}

		apiKey := mqlKey.(*mqlClaudeOrganizationApiKey)
		apiKey.cacheWorkspaceID = nullableString(k.Scope.WorkspaceID)
		apiKey.cacheCreatedByID = k.CreatedBy.ID
		apiKey.cachePrincipalUserID = k.Principal.UserID
		apiKey.cachePrincipalServiceAccountID = k.Principal.ServiceAccountID

		res = append(res, mqlKey)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing api keys: %w", err)
	}

	return res, nil
}

// apiKeyArgs maps an organization API key onto resource arguments.
func apiKeyArgs(k anthropic.BetaAPIKey) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(k.ID),
		"id":        llx.StringData(k.ID),
		"name":      llx.StringData(k.Name),
		"status":    llx.StringData(string(k.Status)),
		"createdAt": llx.TimeDataPtr(nullableTime(k.CreatedAt)),
		// A key that never expires reports no expiry at all. The zero time
		// would date it to year 1, which an expiry check reads as long
		// expired.
		"expiresAt":      llx.TimeDataPtr(nullableTime(k.ExpiresAt)),
		"partialKeyHint": llx.StringData(k.PartialKeyHint),
		"principalType":  llx.StringDataPtr(nullableString(k.Principal.Type)),
		"scopeType":      llx.StringDataPtr(nullableString(k.Scope.Type)),
	}
}

func (r *mqlClaudeOrganizationApiKey) principalUser() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cachePrincipalUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.PrincipalUser.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

func (r *mqlClaudeOrganizationApiKey) principalServiceAccount() (*mqlClaudeOrganizationServiceAccount, error) {
	sa, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationServiceAccount](
		r.MqlRuntime, r.cachePrincipalServiceAccountID,
		(*mqlClaudeOrganization).GetServiceAccounts)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.PrincipalServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return sa, nil
}

func (r *mqlClaudeOrganizationApiKey) createdBy() (*mqlClaudeOrganizationMember, error) {
	member, ok, err := lookupMember(r.MqlRuntime, r.cacheCreatedByID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.CreatedBy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return member, nil
}

func (r *mqlClaudeOrganizationApiKey) workspace() (*mqlClaudeOrganizationWorkspace, error) {
	var workspaceID string
	if r.cacheWorkspaceID != nil {
		workspaceID = *r.cacheWorkspaceID
	}

	ws, ok, err := lookupWorkspace(r.MqlRuntime, workspaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Workspace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return ws, nil
}

// claude.organization.rateLimit

func (r *mqlClaudeOrganization) rateLimits() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	limits, err := admin.ListRateLimits(context.Background())
	if err != nil {
		return nil, err
	}

	return convertRateLimits(r.MqlRuntime, limits, "org")
}

func convertRateLimits(runtime *plugin.Runtime, limits []connection.AdminRateLimit, prefix string) ([]interface{}, error) {
	res := make([]interface{}, 0, len(limits))
	for _, l := range limits {
		models := make([]interface{}, len(l.Models))
		for j, m := range l.Models {
			models[j] = m
		}

		mqlLimit, err := CreateResource(runtime, "claude.organization.rateLimit", map[string]*llx.RawData{
			"__id":                  llx.StringData(prefix + "/ratelimit/" + l.GroupType),
			"groupType":             llx.StringData(l.GroupType),
			"models":                llx.ArrayData(models, types.String),
			"requestsPerMinute":     llx.IntData(l.LimitValue("requests_per_minute")),
			"inputTokensPerMinute":  llx.IntData(l.LimitValue("input_tokens_per_minute_cache_aware")),
			"outputTokensPerMinute": llx.IntData(l.LimitValue("output_tokens_per_minute")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLimit)
	}
	return res, nil
}

// claude.organization.workspace members and rate limits

type mqlClaudeOrganizationWorkspaceInternal struct{}

type mqlClaudeOrganizationWorkspaceMemberInternal struct {
	cacheUserID      string
	cacheWorkspaceID string
}

func (r *mqlClaudeOrganizationWorkspaceMember) user() (*mqlClaudeOrganizationMember, error) {
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

func (r *mqlClaudeOrganizationWorkspaceMember) workspace() (*mqlClaudeOrganizationWorkspace, error) {
	ws, ok, err := lookupWorkspace(r.MqlRuntime, r.cacheWorkspaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Workspace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return ws, nil
}

func (r *mqlClaudeOrganizationWorkspace) members() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	wsID := r.GetId().Data
	members, err := admin.ListWorkspaceMembers(context.Background(), wsID)
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(members))
	for _, m := range members {
		mqlMember, err := CreateResource(r.MqlRuntime, "claude.organization.workspace.member", map[string]*llx.RawData{
			"__id":          llx.StringData(m.WorkspaceID + "/" + m.UserID),
			"workspaceRole": llx.StringData(m.WorkspaceRole),
		})
		if err != nil {
			return nil, err
		}

		wsMember := mqlMember.(*mqlClaudeOrganizationWorkspaceMember)
		wsMember.cacheUserID = m.UserID
		wsMember.cacheWorkspaceID = m.WorkspaceID

		res = append(res, mqlMember)
	}

	return res, nil
}

func (r *mqlClaudeOrganizationWorkspace) rateLimits() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	wsID := r.GetId().Data
	limits, err := admin.ListWorkspaceRateLimits(context.Background(), wsID)
	if err != nil {
		return nil, err
	}

	return convertRateLimits(r.MqlRuntime, limits, "ws/"+wsID)
}

// claude.organization.usageEntry

type mqlClaudeOrganizationUsageEntryInternal struct {
	cacheWorkspaceID string
}

func (r *mqlClaudeOrganizationUsageEntry) workspace() (*mqlClaudeOrganizationWorkspace, error) {
	ws, ok, err := lookupWorkspace(r.MqlRuntime, r.cacheWorkspaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Workspace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return ws, nil
}

func (r *mqlClaudeOrganization) usageReport() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	buckets, err := admin.ListUsageReport(context.Background())
	if err != nil {
		return nil, err
	}

	var res []interface{}
	for _, b := range buckets {
		startingAt, err := parseTime(b.StartingAt)
		if err != nil {
			return nil, fmt.Errorf("parsing usage startingAt: %w", err)
		}
		endingAt, err := parseTime(b.EndingAt)
		if err != nil {
			return nil, fmt.Errorf("parsing usage endingAt: %w", err)
		}

		for _, result := range b.Results {
			mqlEntry, err := CreateResource(r.MqlRuntime, "claude.organization.usageEntry", map[string]*llx.RawData{
				"__id":                 llx.StringData("usage/" + b.StartingAt + "/" + result.Model + "/" + result.WorkspaceID + "/" + result.ServiceTier),
				"startingAt":           llx.TimeData(startingAt),
				"endingAt":             llx.TimeData(endingAt),
				"model":                llx.StringData(result.Model),
				"serviceTier":          llx.StringData(result.ServiceTier),
				"uncachedInputTokens":  llx.IntData(result.UncachedInputTokens),
				"cacheReadInputTokens": llx.IntData(result.CacheReadInputTokens),
				"outputTokens":         llx.IntData(result.OutputTokens),
			})
			if err != nil {
				return nil, err
			}

			mqlEntry.(*mqlClaudeOrganizationUsageEntry).cacheWorkspaceID = result.WorkspaceID

			res = append(res, mqlEntry)
		}
	}

	return res, nil
}

// claude.organization.costEntry

type mqlClaudeOrganizationCostEntryInternal struct {
	cacheWorkspaceID string
}

func (r *mqlClaudeOrganizationCostEntry) workspace() (*mqlClaudeOrganizationWorkspace, error) {
	ws, ok, err := lookupWorkspace(r.MqlRuntime, r.cacheWorkspaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Workspace.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return ws, nil
}

func (r *mqlClaudeOrganization) costReport() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	buckets, err := admin.ListCostReport(context.Background())
	if err != nil {
		return nil, err
	}

	var res []interface{}
	for _, b := range buckets {
		startingAt, err := parseTime(b.StartingAt)
		if err != nil {
			return nil, fmt.Errorf("parsing cost startingAt: %w", err)
		}
		endingAt, err := parseTime(b.EndingAt)
		if err != nil {
			return nil, fmt.Errorf("parsing cost endingAt: %w", err)
		}

		for _, result := range b.Results {
			mqlEntry, err := CreateResource(r.MqlRuntime, "claude.organization.costEntry", map[string]*llx.RawData{
				"__id":       llx.StringData("cost/" + b.StartingAt + "/" + result.CostType + "/" + result.Model + "/" + result.WorkspaceID),
				"startingAt": llx.TimeData(startingAt),
				"endingAt":   llx.TimeData(endingAt),
				"amount":     llx.StringData(result.Amount),
				"currency":   llx.StringData(result.Currency),
				"costType":   llx.StringData(result.CostType),
				"model":      llx.StringData(result.Model),
			})
			if err != nil {
				return nil, err
			}

			mqlEntry.(*mqlClaudeOrganizationCostEntry).cacheWorkspaceID = result.WorkspaceID

			res = append(res, mqlEntry)
		}
	}

	return res, nil
}

// claude.organization.activity

func (r *mqlClaudeOrganization) activities() ([]interface{}, error) {
	admin, err := requireAdmin(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	activities, err := admin.ListActivities(context.Background())
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(activities))
	for _, a := range activities {
		args, err := activityArgs(a)
		if err != nil {
			return nil, err
		}

		mqlActivity, err := CreateResource(r.MqlRuntime, "claude.organization.activity", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlActivity)
	}

	return res, nil
}

// activityArgs maps a compliance activity onto resource arguments. Each actor
// variant defines a different subset of the union, so a value the variant does
// not carry reads as null rather than as the empty string: an api_actor has no
// email address, and reporting "" there would be a measurement it never made.
func activityArgs(a connection.AdminActivity) (map[string]*llx.RawData, error) {
	createdAt, err := parseTime(a.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing activity createdAt: %w", err)
	}

	return map[string]*llx.RawData{
		"__id":                 llx.StringData(a.ID),
		"id":                   llx.StringData(a.ID),
		"type":                 llx.StringData(a.Type),
		"actorType":            llx.StringDataPtr(nullableString(a.Actor.Type)),
		"actorEmail":           llx.StringDataPtr(nullableString(a.Actor.Email)),
		"actorId":              llx.StringDataPtr(nullableString(a.Actor.ID)),
		"unauthenticatedEmail": llx.StringDataPtr(nullableString(a.Actor.UnauthenticatedEmail)),
		"ipAddress":            llx.StringDataPtr(nullableString(a.Actor.IPAddress)),
		"userAgent":            llx.StringDataPtr(nullableString(a.Actor.UserAgent)),
		"apiKeyId":             llx.StringDataPtr(nullableString(a.Actor.APIKeyID)),
		"adminApiKeyId":        llx.StringDataPtr(nullableString(a.Actor.AdminAPIKeyID)),
		"directoryId":          llx.StringDataPtr(nullableString(a.Actor.DirectoryID)),
		"idpConnectionType":    llx.StringDataPtr(nullableString(a.Actor.IdpConnectionType)),
		"workosEventId":        llx.StringDataPtr(nullableString(a.Actor.WorkosEventID)),
		"createdAt":            llx.TimeData(createdAt),
	}, nil
}

// apiKey resolves the organization API key behind an api_actor activity. The
// feed is retained far longer than the keys it names, so a key that has since
// been deleted resolves to nothing and leaves apiKeyId as the only record of
// which credential acted.
func (r *mqlClaudeOrganizationActivity) apiKey() (*mqlClaudeOrganizationApiKey, error) {
	key, ok, err := lookupOrganizationChild[*mqlClaudeOrganizationApiKey](
		r.MqlRuntime, r.ApiKeyId.Data, (*mqlClaudeOrganization).GetApiKeys)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.ApiKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return key, nil
}
