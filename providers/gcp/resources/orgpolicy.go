// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	orgpolicy "cloud.google.com/go/orgpolicy/apiv2"
	"cloud.google.com/go/orgpolicy/apiv2/orgpolicypb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpOrgPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// dryRunOnly reports whether the policy has a dry-run spec set but no enforced
// live spec, meaning it is evaluated for testing only and does not actually
// enforce.
func (g *mqlGcpOrgPolicy) dryRunOnly() (bool, error) {
	if g.Spec.Error != nil {
		return false, g.Spec.Error
	}
	if g.DryRunSpec.Error != nil {
		return false, g.DryRunSpec.Error
	}
	return g.DryRunSpec.Data != nil && g.Spec.Data == nil, nil
}

// policySpecSummary is the decoded view of an org policy spec: the scalar
// predicates derived from the spec's unconditional rules, plus the conditional
// rules kept verbatim.
type policySpecSummary struct {
	enforced          bool
	allowAll          bool
	denyAll           bool
	inheritFromParent bool
	allowedValues     []any
	deniedValues      []any
	// hasConditionalRules reports whether the spec carries at least one rule
	// gated by a CEL condition.
	hasConditionalRules bool
	// conditionalRules holds one dict per condition-gated rule.
	conditionalRules []any
}

// conditionalRuleDict renders a condition-gated rule as a dict, keeping both the
// condition and the effect it would have. Only JSON-native values are emitted,
// since anything else is dropped on the way through llx.DictData.
func conditionalRuleDict(rule *orgpolicypb.PolicySpec_PolicyRule) map[string]any {
	allowedValues := []any{}
	deniedValues := []any{}
	if vals := rule.GetValues(); vals != nil {
		for _, v := range vals.GetAllowedValues() {
			allowedValues = append(allowedValues, v)
		}
		for _, v := range vals.GetDeniedValues() {
			deniedValues = append(deniedValues, v)
		}
	}
	cond := rule.GetCondition()
	return map[string]any{
		"condition":            cond.GetExpression(),
		"conditionTitle":       cond.GetTitle(),
		"conditionDescription": cond.GetDescription(),
		"enforce":              rule.GetEnforce(),
		"allowAll":             rule.GetAllowAll(),
		"denyAll":              rule.GetDenyAll(),
		"allowedValues":        allowedValues,
		"deniedValues":         deniedValues,
	}
}

// interpretPolicySpec decodes an org policy's live spec.
//
// The scalar predicates (enforced, allowAll, denyAll, allowedValues,
// deniedValues) are derived from unconditional rules only, since a rule gated
// by a CEL condition applies to a subset of resources and its effect cannot be
// decided without evaluating the condition against a specific one. Those rules
// are not discarded: they are reported through hasConditionalRules and
// conditionalRules, so that a constraint enforced only by a tag-scoped rule is
// distinguishable from a constraint with no policy at all. Both cases used to
// render as an all-false summary, which made the false negative invisible.
//
// The result reflects only this resource's directly-set spec, not policy
// inherited from a parent.
func interpretPolicySpec(spec *orgpolicypb.PolicySpec) policySpecSummary {
	summary := policySpecSummary{
		allowedValues:    []any{},
		deniedValues:     []any{},
		conditionalRules: []any{},
	}
	if spec == nil {
		return summary
	}
	summary.inheritFromParent = spec.GetInheritFromParent()
	for _, rule := range spec.GetRules() {
		if rule.GetCondition() != nil {
			summary.hasConditionalRules = true
			summary.conditionalRules = append(summary.conditionalRules, conditionalRuleDict(rule))
			continue
		}
		if rule.GetEnforce() {
			summary.enforced = true
		}
		if rule.GetAllowAll() {
			summary.allowAll = true
		}
		if rule.GetDenyAll() {
			summary.denyAll = true
		}
		if vals := rule.GetValues(); vals != nil {
			for _, v := range vals.GetAllowedValues() {
				summary.allowedValues = append(summary.allowedValues, v)
			}
			for _, v := range vals.GetDeniedValues() {
				summary.deniedValues = append(summary.deniedValues, v)
			}
		}
	}
	return summary
}

// listOrgPolicies fetches org policies for a given parent resource.
// parentResourceName should be "organizations/{id}" or "projects/{id}".
func listOrgPolicies(runtime *plugin.Runtime, conn *connection.GcpConnection, parentResourceName string) ([]any, error) {
	creds, err := conn.Credentials(orgpolicy.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := orgpolicy.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListPolicies(ctx, &orgpolicypb.ListPoliciesRequest{
		Parent: parentResourceName,
	})

	var res []any
	for {
		policy, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		spec, err := protoToDict(policy.Spec)
		if err != nil {
			return nil, err
		}
		dryRunSpec, err := protoToDict(policy.DryRunSpec)
		if err != nil {
			return nil, err
		}

		constraintName := extractConstraintName(policy.Name)

		var updatedAt *llx.RawData
		if policy.Spec != nil && policy.Spec.UpdateTime != nil {
			updatedAt = llx.TimeData(policy.Spec.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		summary := interpretPolicySpec(policy.Spec)

		mqlPolicy, err := CreateResource(runtime, "gcp.orgPolicy", map[string]*llx.RawData{
			"id":                  llx.StringData(policy.Name),
			"name":                llx.StringData(policy.Name),
			"constraintName":      llx.StringData(constraintName),
			"spec":                llx.DictData(spec),
			"dryRunSpec":          llx.DictData(dryRunSpec),
			"etag":                llx.StringData(policy.Etag),
			"updatedAt":           updatedAt,
			"enforced":            llx.BoolData(summary.enforced),
			"allowedValues":       llx.ArrayData(summary.allowedValues, types.String),
			"deniedValues":        llx.ArrayData(summary.deniedValues, types.String),
			"allowAll":            llx.BoolData(summary.allowAll),
			"denyAll":             llx.BoolData(summary.denyAll),
			"inheritFromParent":   llx.BoolData(summary.inheritFromParent),
			"hasConditionalRules": llx.BoolData(summary.hasConditionalRules),
			"conditionalRules":    llx.ArrayData(summary.conditionalRules, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}

	return res, nil
}

func (g *mqlGcpOrganization) orgPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	orgId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	// orgId is already in "organizations/{id}" format from initGcpOrganization
	return listOrgPolicies(g.MqlRuntime, conn, orgId)
}

// extractConstraintName extracts the constraint name from a full org policy resource path.
// Format: {parent}/policies/{constraintName}
// Returns the full name unchanged if the "/policies/" segment is not found.
func extractConstraintName(policyName string) string {
	if _, after, ok := strings.CutLast(policyName, "/policies/"); ok {
		return after
	}
	return policyName
}

func (g *mqlGcpProject) orgPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	return listOrgPolicies(g.MqlRuntime, conn, "projects/"+projectId)
}

func (g *mqlGcpFolder) orgPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	folderId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	return listOrgPolicies(g.MqlRuntime, conn, "folders/"+folderId)
}

func (g *mqlGcpOrgPolicyConstraint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProject) orgPolicyConstraints() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(orgpolicy.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := orgpolicy.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var res []any
	it := client.ListConstraints(ctx, &orgpolicypb.ListConstraintsRequest{
		Parent: "projects/" + projectId,
	})
	for {
		c, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		listConstraint, err := protoToDict(c.GetListConstraint())
		if err != nil {
			return nil, err
		}
		booleanConstraint, err := protoToDict(c.GetBooleanConstraint())
		if err != nil {
			return nil, err
		}

		mqlConstraint, err := CreateResource(g.MqlRuntime, "gcp.orgPolicy.constraint", map[string]*llx.RawData{
			"name":              llx.StringData(c.Name),
			"displayName":       llx.StringData(c.DisplayName),
			"description":       llx.StringData(c.Description),
			"constraintDefault": llx.StringData(c.ConstraintDefault.String()),
			"listConstraint":    llx.DictData(listConstraint),
			"booleanConstraint": llx.DictData(booleanConstraint),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConstraint)
	}
	return res, nil
}

func (g *mqlGcpOrgPolicyCustomConstraint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganization) customConstraints() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// orgId is already in "organizations/{id}" format from initGcpOrganization
	orgId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(orgpolicy.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := orgpolicy.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var res []any
	it := client.ListCustomConstraints(ctx, &orgpolicypb.ListCustomConstraintsRequest{
		Parent: orgId,
	})
	for {
		c, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		methodTypes := make([]any, 0, len(c.MethodTypes))
		for _, m := range c.MethodTypes {
			methodTypes = append(methodTypes, m.String())
		}

		mqlConstraint, err := CreateResource(g.MqlRuntime, "gcp.orgPolicy.customConstraint", map[string]*llx.RawData{
			"name":          llx.StringData(c.Name),
			"displayName":   llx.StringData(c.DisplayName),
			"description":   llx.StringData(c.Description),
			"resourceTypes": llx.ArrayData(convert.SliceAnyToInterface(c.ResourceTypes), types.String),
			"methodTypes":   llx.ArrayData(methodTypes, types.String),
			"condition":     llx.StringData(c.Condition),
			"actionType":    llx.StringData(c.ActionType.String()),
			"updated":       llx.TimeDataPtr(timestampAsTimePtr(c.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConstraint)
	}
	return res, nil
}
