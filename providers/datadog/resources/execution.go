// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/datadog/connection"
	"go.mondoo.com/mql/types"
)

// Scope discriminators reported through datadog.executionPolicy.scopeRestriction.
const (
	// executionScopeNone is reported when the policy carries no scope object at
	// all, or an empty one. Datadog documents an empty object as "no scope
	// restriction", so this is the widest reading a policy can have.
	executionScopeNone = "none"
	// executionScopeKubernetes, executionScopeScripts and
	// executionScopeRemoteActionRshell each name the single member Datadog
	// populated.
	executionScopeKubernetes         = "kubernetes"
	executionScopeScripts            = "scripts"
	executionScopeRemoteActionRshell = "remoteActionRshell"
	// executionScopeUnknown is reported when Datadog returned a scope that sets
	// no member this provider models, or that sets more than one at once. Both
	// break the documented "at most one member" contract, so the restriction is
	// reported as unmodeled rather than silently as none.
	executionScopeUnknown = "unknown"
)

const (
	executionPolicyPageSize = int32(100)
	// executionPolicyMaxPages bounds the walk. Datadog pages execution policies
	// by page[number], so a server that ignores the parameter would otherwise
	// hand back the same page forever.
	executionPolicyMaxPages = 100
)

// executionPolicyLister is the part of ExecutionPolicyApi the walk needs. It
// exists so the pagination logic can be exercised against a stub as well as
// against a real client.
type executionPolicyLister interface {
	ListExecutionPolicies(ctx context.Context, o ...datadogV2.ListExecutionPoliciesOptionalParameters) (datadogV2.ExecutionPolicyListResponse, *http.Response, error)
}

// listExecutionPolicies walks every page of execution policies.
//
// Termination is deliberately over-determined, because a single condition is
// not enough: a short page ends the walk, an empty page ends it, reaching the
// reported total ends it, and a page carrying no policy ID the walk has not
// already seen ends it too. That last one is what stops a server which ignores
// page[number] from multiplying the first page up to the cap.
func listExecutionPolicies(ctx context.Context, api executionPolicyLister) ([]datadogV2.ExecutionPolicyResponseData, *http.Response, error) {
	var all []datadogV2.ExecutionPolicyResponseData
	seen := map[string]struct{}{}

	for page := range int32(executionPolicyMaxPages) {
		resp, httpResp, err := api.ListExecutionPolicies(ctx,
			*datadogV2.NewListExecutionPoliciesOptionalParameters().
				WithPageSize(executionPolicyPageSize).
				WithPageNumber(page))
		if err != nil {
			return nil, httpResp, err
		}

		data := resp.GetData()
		if len(data) == 0 {
			return all, httpResp, nil
		}

		fresh, unreadable := 0, 0
		for _, policy := range data {
			id := policy.GetId()
			if id == "" {
				// A record the SDK could not decode carries no readable field,
				// so reporting it would add a policy whose effect and targets
				// are empty and which no assertion can match. It is also
				// indistinguishable from every other undecodable record, which
				// would collapse them all into one under the repeat guard
				// below. Skip it and count it instead.
				unreadable++
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			fresh++
			all = append(all, policy)
		}
		if unreadable > 0 {
			log.Warn().Int("count", unreadable).Int32("page", page).Msg("datadog> skipped execution policies that could not be read")
		}

		// A page carrying nothing new means the endpoint ignored page[number].
		// A page of records none of which could be read is a different problem
		// and must not end the walk, or one bad page would truncate the rest.
		if fresh == 0 && unreadable == 0 {
			log.Warn().Int32("page", page).Msg("datadog> execution policy paging repeated a page, stopping the walk")
			return all, httpResp, nil
		}
		if int32(len(data)) < executionPolicyPageSize {
			return all, httpResp, nil
		}
		meta := resp.GetMeta()
		if total := meta.Page.GetTotal(); total > 0 && int32(len(all)) >= total {
			return all, httpResp, nil
		}
	}

	log.Warn().Int("pages", executionPolicyMaxPages).Msg("datadog> stopped listing execution policies at the page cap")
	return all, nil, nil
}

func (r *mqlDatadog) executionPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewExecutionPolicyApi(conn.ApiClient())

	policies, httpResp, err := listExecutionPolicies(conn.AuthCtx(), api)
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> execution policies not available (403 Forbidden). Your Datadog plan may not include the actions product, or the application key may lack the permission to read them")
			return nil, nil
		}
		return nil, err
	}

	all := make([]any, 0, len(policies))
	for _, policy := range policies {
		args, err := executionPolicyArgs(r.MqlRuntime, policy)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "datadog.executionPolicy", args)
		if err != nil {
			return nil, err
		}
		mqlPolicy := res.(*mqlDatadogExecutionPolicy)
		attrs := policy.GetAttributes()
		mqlPolicy.cacheCreatedById = attrs.GetCreatedBy()
		mqlPolicy.cacheUpdatedById = attrs.GetUpdatedBy()
		all = append(all, mqlPolicy)
	}
	return all, nil
}

func initDatadogExecutionPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewExecutionPolicyApi(conn.ApiClient())

	resp, _, err := api.GetExecutionPolicy(conn.AuthCtx(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("datadog.executionPolicy %q not found: %w", id, err)
	}

	// The resource is built here rather than handed back as arguments, because
	// createdBy and updatedBy resolve out of cached IDs that only exist on the
	// resource itself. Returning arguments alone would leave both reading null.
	policy := resp.GetData()
	newArgs, err := executionPolicyArgs(runtime, policy)
	if err != nil {
		return nil, nil, err
	}
	res, err := CreateResource(runtime, "datadog.executionPolicy", newArgs)
	if err != nil {
		return nil, nil, err
	}
	mqlPolicy := res.(*mqlDatadogExecutionPolicy)
	attrs := policy.GetAttributes()
	mqlPolicy.cacheCreatedById = attrs.GetCreatedBy()
	mqlPolicy.cacheUpdatedById = attrs.GetUpdatedBy()
	return nil, mqlPolicy, nil
}

// executionPolicyArgs converts one API record into resource arguments. The
// scope and the targets are built here rather than lazily, because both come
// out of the record that has already been read and neither needs a further
// call.
func executionPolicyArgs(runtime *plugin.Runtime, policy datadogV2.ExecutionPolicyResponseData) (map[string]*llx.RawData, error) {
	id := policy.GetId()
	attrs := policy.GetAttributes()
	pattern := attrs.GetActionPattern()

	scope, err := createExecutionPolicyScope(runtime, id, attrs.Scope)
	if err != nil {
		return nil, err
	}

	targets, err := createExecutionPolicyTargets(runtime, id, attrs.GetTargets())
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"id":          llx.StringData(id),
		"name":        llx.StringData(attrs.GetName()),
		"effect":      llx.StringData(string(attrs.GetEffect())),
		"integration": llx.StringData(string(pattern.GetIntegration())),
		"actionFqns":  llx.ArrayData(toAnyStrings(pattern.GetActionFqns()), types.String),
		"scope":       llx.ResourceData(scope, "datadog.executionPolicy.scopeRestriction"),
		"targets":     llx.ArrayData(targets, types.Resource("datadog.executionPolicy.target")),
		"version":     llx.IntData(int64(attrs.GetVersion())),
		"createdAt":   llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
		"updatedAt":   llx.TimeDataPtr(timePtr(attrs.GetUpdatedAt())),
	}, nil
}

// executionScopeType picks the member of the scope union Datadog populated.
//
// The API documents at most one of kubernetes, scripts and remote_action_rshell
// as set. Anything else is reported as unknown so a scope this provider cannot
// read is never mistaken for a policy that carries no restriction.
func executionScopeType(scope *datadogV2.ExecutionPolicyScope) string {
	if scope == nil {
		return executionScopeNone
	}

	found := ""
	count := 0
	if scope.Kubernetes != nil {
		found = executionScopeKubernetes
		count++
	}
	if scope.Scripts != nil {
		found = executionScopeScripts
		count++
	}
	if scope.RemoteActionRshell != nil {
		found = executionScopeRemoteActionRshell
		count++
	}

	switch {
	case count == 1:
		return found
	case count > 1:
		return executionScopeUnknown
	case len(scope.AdditionalProperties) > 0 || scope.UnparsedObject != nil:
		// A member the SDK does not model lands in AdditionalProperties, and a
		// scope that failed to decode lands in UnparsedObject. Either way
		// something restricts the policy that cannot be reported here.
		return executionScopeUnknown
	default:
		return executionScopeNone
	}
}

// executionScopeKubernetesNamespaces flattens the namespaces across every
// Kubernetes rule. The rules carry a single list each, so the union is the
// whole of what the scope permits and preserving the grouping would add
// nothing to query.
func executionScopeKubernetesNamespaces(scope *datadogV2.ExecutionPolicyScope) []string {
	if scope == nil || scope.Kubernetes == nil {
		return nil
	}
	var out []string
	for _, rule := range scope.Kubernetes.GetRules() {
		out = append(out, rule.GetTargetNamespaces()...)
	}
	return out
}

// executionScopeScriptNames flattens the script names across every script rule,
// for the same reason as executionScopeKubernetesNamespaces.
func executionScopeScriptNames(scope *datadogV2.ExecutionPolicyScope) []string {
	if scope == nil || scope.Scripts == nil {
		return nil
	}
	var out []string
	for _, rule := range scope.Scripts.GetRules() {
		out = append(out, rule.GetTargetScriptNames()...)
	}
	return out
}

func createExecutionPolicyScope(runtime *plugin.Runtime, policyID string, scope *datadogV2.ExecutionPolicyScope) (*mqlDatadogExecutionPolicyScopeRestriction, error) {
	rules, err := createExecutionPolicyRemoteShellRules(runtime, policyID, scope)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "datadog.executionPolicy.scopeRestriction", map[string]*llx.RawData{
		"__id":                 llx.StringData(policyID + "/scopeRestriction"),
		"scopeType":            llx.StringData(executionScopeType(scope)),
		"kubernetesNamespaces": llx.ArrayData(toAnyStrings(executionScopeKubernetesNamespaces(scope)), types.String),
		"scriptNames":          llx.ArrayData(toAnyStrings(executionScopeScriptNames(scope)), types.String),
		"remoteShellRules":     llx.ArrayData(rules, types.Resource("datadog.executionPolicy.remoteShellRule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogExecutionPolicyScopeRestriction), nil
}

func createExecutionPolicyRemoteShellRules(runtime *plugin.Runtime, policyID string, scope *datadogV2.ExecutionPolicyScope) ([]any, error) {
	if scope == nil || scope.RemoteActionRshell == nil {
		return []any{}, nil
	}

	rules := scope.RemoteActionRshell.GetRules()
	out := make([]any, 0, len(rules))
	for i, rule := range rules {
		res, err := CreateResource(runtime, "datadog.executionPolicy.remoteShellRule", map[string]*llx.RawData{
			// The rules carry no identifier of their own, so position within
			// the policy is what separates one from the next.
			"__id":        llx.StringData(fmt.Sprintf("%s/remoteShellRule/%d", policyID, i)),
			"access":      llx.StringData(string(rule.GetAccess())),
			"targetPaths": llx.ArrayData(toAnyStrings(rule.GetTargetPaths()), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func createExecutionPolicyTargets(runtime *plugin.Runtime, policyID string, targets []datadogV2.ExecutionPolicyTarget) ([]any, error) {
	out := make([]any, 0, len(targets))
	for i, target := range targets {
		res, err := CreateResource(runtime, "datadog.executionPolicy.target", map[string]*llx.RawData{
			// Targets carry no identifier of their own either, and two targets
			// may legitimately name the same tags under different labels, so
			// position is the only dimension that separates them.
			"__id": llx.StringData(fmt.Sprintf("%s/target/%d", policyID, i)),
			// Name is nullable on the wire. Keeping it a pointer reports an
			// unnamed target as null rather than as an empty label.
			"name":      llx.StringDataPtr(target.Name.Get()),
			"agentTags": llx.ArrayData(toAnyStrings(target.GetAgentTags()), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

type mqlDatadogExecutionPolicyInternal struct {
	cacheCreatedById string
	cacheUpdatedById string
}

func (r *mqlDatadogExecutionPolicy) id() (string, error) {
	return "datadog.executionPolicy/" + r.Id.Data, nil
}

func (r *mqlDatadogExecutionPolicy) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreatedById, &r.CreatedBy)
}

func (r *mqlDatadogExecutionPolicy) updatedBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheUpdatedById, &r.UpdatedBy)
}
