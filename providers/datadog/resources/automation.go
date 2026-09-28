// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/datadog/connection"
	"go.mondoo.com/mql/types"
)

// pagedListMaxPages bounds every page-number walk in this file. Both endpoints
// page by number, so a server that ignored the parameter would otherwise hand
// back the same page forever.
const pagedListMaxPages = 100

// walkPagedList drives a page-number walk over fetch.
//
// fetch returns the records on one page, the total Datadog reports for the
// whole list (0 when it reports none), and the HTTP response. idOf names a
// record; an empty name marks a record the SDK could not decode, which is
// skipped rather than reported as an entry every field of which is empty.
//
// The walk ends on an empty page, on a page carrying no record it has not
// already seen (the endpoint ignored the page number), and once the reported
// total has been collected. Without a total it also ends on a short page. A
// reported total is preferred over the short-page rule because the server may
// cap the page size below what was asked for, and a short-page rule would then
// stop after the first page.
func walkPagedList[T any](what string, pageSize int64, idOf func(T) string, fetch func(page int64) ([]T, int64, *http.Response, error)) ([]T, *http.Response, error) {
	var all []T
	seen := map[string]struct{}{}

	for page := int64(0); page < pagedListMaxPages; page++ {
		data, total, httpResp, err := fetch(page)
		if err != nil {
			return nil, httpResp, err
		}
		if len(data) == 0 {
			return all, httpResp, nil
		}

		fresh, unreadable := 0, 0
		for _, item := range data {
			id := idOf(item)
			if id == "" {
				unreadable++
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			fresh++
			all = append(all, item)
		}
		if unreadable > 0 {
			log.Warn().Int("count", unreadable).Int64("page", page).Str("list", what).Msg("datadog> skipped records that could not be read")
		}
		if fresh == 0 && unreadable == 0 {
			log.Warn().Int64("page", page).Str("list", what).Msg("datadog> paging repeated a page, stopping the walk")
			return all, httpResp, nil
		}

		if total > 0 {
			if int64(len(all)) >= total {
				return all, httpResp, nil
			}
			continue
		}
		if int64(len(data)) < pageSize {
			return all, httpResp, nil
		}
	}

	log.Warn().Int("pages", pagedListMaxPages).Str("list", what).Msg("datadog> stopped listing at the page cap")
	return all, nil, nil
}

// --- Workflows ---

const workflowPageSize = int64(50)

// workflowLister is the part of WorkflowAutomationApi the walk needs, so the
// pagination can be exercised against a test server.
type workflowLister interface {
	ListWorkflows(ctx context.Context, o ...datadogV2.ListWorkflowsOptionalParameters) (datadogV2.ListWorkflowsResponse, *http.Response, error)
}

// listWorkflows walks every page of workflows, unpublished ones included. The
// API leaves drafts out unless asked, and a draft that runs as its owner is as
// much a standing grant as a published one: anyone who can start it by hand
// borrows that identity.
func listWorkflows(ctx context.Context, api workflowLister) ([]datadogV2.WorkflowListItem, *http.Response, error) {
	return walkPagedList("workflows", workflowPageSize,
		func(w datadogV2.WorkflowListItem) string { return w.GetId() },
		func(page int64) ([]datadogV2.WorkflowListItem, int64, *http.Response, error) {
			resp, httpResp, err := api.ListWorkflows(ctx,
				*datadogV2.NewListWorkflowsOptionalParameters().
					WithLimit(workflowPageSize).
					WithPage(page).
					WithFilterIncludeUnpublished(true))
			if err != nil {
				return nil, 0, httpResp, err
			}
			var total int64
			if meta, ok := resp.GetMetaOk(); ok && meta != nil {
				if p, ok := meta.GetPageOk(); ok && p != nil {
					// The filtered count is the size of the list this query
					// asked for. The unfiltered count is only a fallback.
					total = p.GetTotalFilteredCount()
					if total == 0 {
						total = p.GetTotalCount()
					}
				}
			}
			return resp.GetData(), total, httpResp, nil
		})
}

// workflowUserRefs reads the owner, creator and run-as user IDs off a
// workflow's relationships. Each is empty when the relationship is absent.
func workflowUserRefs(w datadogV2.WorkflowListItem) (owner, creator, runAs string) {
	rels, ok := w.GetRelationshipsOk()
	if !ok || rels == nil {
		return "", "", ""
	}
	id := func(rel *datadogV2.WorkflowUserRelationship) string {
		if rel == nil {
			return ""
		}
		data, ok := rel.GetDataOk()
		if !ok || data == nil {
			return ""
		}
		return data.GetId()
	}
	return id(rels.Owner), id(rels.Creator), id(rels.RunAs)
}

func workflowArgs(w datadogV2.WorkflowListItem) map[string]*llx.RawData {
	attrs := w.GetAttributes()
	var runAsMode *string
	if attrs.RunAsUserMode != nil {
		s := string(*attrs.RunAsUserMode)
		runAsMode = &s
	}
	return map[string]*llx.RawData{
		"id":                  llx.StringData(w.GetId()),
		"name":                llx.StringData(attrs.GetName()),
		"description":         llx.StringDataPtr(attrs.Description),
		"published":           llx.BoolDataPtr(attrs.Published),
		"tags":                llx.ArrayData(toAnyStrings(attrs.GetTags()), types.String),
		"sensitivePrivileges": llx.BoolDataPtr(attrs.SensitivePrivileges),
		"runAsUserMode":       llx.StringDataPtr(runAsMode),
		"createdAt":           llx.TimeDataPtr(attrs.CreatedAt),
		"updatedAt":           llx.TimeDataPtr(attrs.UpdatedAt),
	}
}

func (r *mqlDatadog) workflows() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewWorkflowAutomationApi(conn.ApiClient())

	items, httpResp, err := listWorkflows(conn.AuthCtx(), api)
	if err != nil {
		if isForbidden(httpResp) {
			return nil, llx.Forbidden(err, llx.WithPermissions("workflows_read"))
		}
		return nil, err
	}

	all := make([]interface{}, 0, len(items))
	for _, w := range items {
		res, err := CreateResource(r.MqlRuntime, "datadog.workflow", workflowArgs(w))
		if err != nil {
			return nil, err
		}
		mqlWorkflow := res.(*mqlDatadogWorkflow)
		mqlWorkflow.cacheOwnerId, mqlWorkflow.cacheCreatorId, mqlWorkflow.cacheRunAsId = workflowUserRefs(w)
		all = append(all, mqlWorkflow)
	}
	return all, nil
}

type mqlDatadogWorkflowInternal struct {
	cacheOwnerId   string
	cacheCreatorId string
	cacheRunAsId   string
}

func (r *mqlDatadogWorkflow) id() (string, error) {
	return "datadog.workflow/" + r.Id.Data, nil
}

func (r *mqlDatadogWorkflow) owner() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheOwnerId, &r.Owner)
}

func (r *mqlDatadogWorkflow) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreatorId, &r.CreatedBy)
}

func (r *mqlDatadogWorkflow) runAsUser() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheRunAsId, &r.RunAsUser)
}

// --- Security Inbox rules ---

const securityInboxRulePageSize = int64(100)

// securityInboxRule is the common shape of a default and a custom inbox rule.
// The API returns the two through distinct types that carry the same
// attributes, so both are read into this before becoming resources.
type securityInboxRule struct {
	id           string
	isDefault    bool
	name         string
	enabled      bool
	description  *string
	findingTypes []string
	query        *string
	createdAt    int64
	modifiedAt   int64
	createdBy    string
	modifiedBy   string
}

// inboxRuleActor returns the user ID behind an actor, or empty when Datadog
// itself is the actor. System actors carry identifiers that are not user IDs,
// and matching one against the user list could only ever miss or mislead.
func inboxRuleActor(actorType datadogV2.AutomationRuleActorType, id string) string {
	if actorType != datadogV2.AUTOMATIONRULEACTORTYPE_USER {
		return ""
	}
	return id
}

func findingTypeStrings(in []datadogV2.SecurityFindingType) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

func customInboxRule(d datadogV2.InboxRuleDataResponse) securityInboxRule {
	// An undecodable record leaves the ID at its zero value, which is reported
	// as empty so the walk skips it rather than inventing a rule with that ID.
	id := ""
	if d.UnparsedObject == nil && [16]byte(d.Id) != [16]byte{} {
		id = d.Id.String()
	}
	attrs := d.Attributes
	return securityInboxRule{
		id:           id,
		name:         attrs.Name,
		enabled:      attrs.Enabled,
		description:  attrs.Action.Description,
		findingTypes: findingTypeStrings(attrs.Rule.FindingTypes),
		query:        attrs.Rule.Query,
		createdAt:    attrs.CreatedAt,
		modifiedAt:   attrs.ModifiedAt,
		createdBy:    inboxRuleActor(attrs.CreatedBy.Type, attrs.CreatedBy.Id),
		modifiedBy:   inboxRuleActor(attrs.ModifiedBy.Type, attrs.ModifiedBy.Id),
	}
}

func defaultInboxRule(d datadogV2.DefaultInboxRuleDataResponse) securityInboxRule {
	id := ""
	if d.UnparsedObject == nil {
		id = d.Id
	}
	attrs := d.Attributes
	return securityInboxRule{
		id:           id,
		isDefault:    true,
		name:         attrs.Name,
		enabled:      attrs.Enabled,
		description:  attrs.Action.Description,
		findingTypes: findingTypeStrings(attrs.Rule.FindingTypes),
		query:        attrs.Rule.Query,
		createdAt:    attrs.CreatedAt,
		modifiedAt:   attrs.ModifiedAt,
		createdBy:    inboxRuleActor(attrs.CreatedBy.Type, attrs.CreatedBy.Id),
		modifiedBy:   inboxRuleActor(attrs.ModifiedBy.Type, attrs.ModifiedBy.Id),
	}
}

// unixMillis converts a millisecond timestamp. Zero means Datadog did not
// report one, and reads as null rather than as the Unix epoch.
func unixMillis(ms int64) *time.Time {
	if ms == 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}

// securityInboxRuleLister is the part of SecurityMonitoringApi the inbox rule
// listing needs.
type securityInboxRuleLister interface {
	ListSecurityFindingsAutomationInboxRules(ctx context.Context, o ...datadogV2.ListSecurityFindingsAutomationInboxRulesOptionalParameters) (datadogV2.InboxRulesResponse, *http.Response, error)
	ListSecurityFindingsAutomationDefaultInboxRules(ctx context.Context) (datadogV2.DefaultInboxRulesResponse, *http.Response, error)
}

// listSecurityInboxRules returns the default rules followed by every page of
// the organization's own rules.
func listSecurityInboxRules(ctx context.Context, api securityInboxRuleLister) ([]securityInboxRule, *http.Response, error) {
	defaults, httpResp, err := api.ListSecurityFindingsAutomationDefaultInboxRules(ctx)
	if err != nil {
		return nil, httpResp, err
	}

	var all []securityInboxRule
	skipped := 0
	for _, d := range defaults.GetData() {
		rule := defaultInboxRule(d)
		if rule.id == "" {
			skipped++
			continue
		}
		all = append(all, rule)
	}
	if skipped > 0 {
		log.Warn().Int("count", skipped).Msg("datadog> skipped default inbox rules that could not be read")
	}

	custom, httpResp, err := walkPagedList("security inbox rules", securityInboxRulePageSize,
		func(r securityInboxRule) string { return r.id },
		func(page int64) ([]securityInboxRule, int64, *http.Response, error) {
			resp, httpResp, err := api.ListSecurityFindingsAutomationInboxRules(ctx,
				*datadogV2.NewListSecurityFindingsAutomationInboxRulesOptionalParameters().
					WithPageSize(securityInboxRulePageSize).
					WithPageNumber(page))
			if err != nil {
				return nil, 0, httpResp, err
			}
			data := resp.GetData()
			out := make([]securityInboxRule, 0, len(data))
			for _, d := range data {
				out = append(out, customInboxRule(d))
			}
			return out, resp.Meta.Page.TotalFilteredCount, httpResp, nil
		})
	if err != nil {
		return nil, httpResp, err
	}
	return append(all, custom...), httpResp, nil
}

func securityInboxRuleArgs(rule securityInboxRule) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":           llx.StringData(rule.id),
		"name":         llx.StringData(rule.name),
		"isDefault":    llx.BoolData(rule.isDefault),
		"enabled":      llx.BoolData(rule.enabled),
		"description":  llx.StringDataPtr(rule.description),
		"findingTypes": llx.ArrayData(toAnyStrings(rule.findingTypes), types.String),
		"query":        llx.StringDataPtr(rule.query),
		"createdAt":    llx.TimeDataPtr(unixMillis(rule.createdAt)),
		"modifiedAt":   llx.TimeDataPtr(unixMillis(rule.modifiedAt)),
	}
}

func (r *mqlDatadog) securityInboxRules() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewSecurityMonitoringApi(conn.ApiClient())

	rules, httpResp, err := listSecurityInboxRules(conn.AuthCtx(), api)
	if err != nil {
		if isForbidden(httpResp) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}

	all := make([]interface{}, 0, len(rules))
	for _, rule := range rules {
		res, err := CreateResource(r.MqlRuntime, "datadog.securityInboxRule", securityInboxRuleArgs(rule))
		if err != nil {
			return nil, err
		}
		mqlRule := res.(*mqlDatadogSecurityInboxRule)
		mqlRule.cacheCreatedById = rule.createdBy
		mqlRule.cacheModifiedById = rule.modifiedBy
		all = append(all, mqlRule)
	}
	return all, nil
}

type mqlDatadogSecurityInboxRuleInternal struct {
	cacheCreatedById  string
	cacheModifiedById string
}

func (r *mqlDatadogSecurityInboxRule) id() (string, error) {
	// Default rule IDs are fixed names and custom rule IDs are UUIDs, so the
	// two never collide, but the prefix keeps the kinds apart regardless.
	kind := "custom"
	if r.IsDefault.Data {
		kind = "default"
	}
	return "datadog.securityInboxRule/" + kind + "/" + r.Id.Data, nil
}

func (r *mqlDatadogSecurityInboxRule) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreatedById, &r.CreatedBy)
}

func (r *mqlDatadogSecurityInboxRule) modifiedBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheModifiedById, &r.ModifiedBy)
}
