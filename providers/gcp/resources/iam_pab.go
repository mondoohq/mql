// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	iamv3 "cloud.google.com/go/iam/apiv3"
	"cloud.google.com/go/iam/apiv3/iampb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpOrganizationPrincipalAccessBoundaryPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganizationPolicyBinding) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpOrganizationPolicyBindingInternal struct {
	// organizationId is the organization the binding was listed under, needed to
	// reach the boundary policy list when resolving policy().
	organizationId string
}

// policy resolves the boundary policy this binding attaches, so a binding leads
// straight to the resource sets it admits.
//
// Resolution goes through the organization's boundary policy list rather than a
// per-binding Get: the list is fetched once and cached on the organization
// resource, so N bindings cost one call rather than N.
func (g *mqlGcpOrganizationPolicyBinding) policy() (*mqlGcpOrganizationPrincipalAccessBoundaryPolicy, error) {
	if g.PolicyName.Error != nil {
		return nil, g.PolicyName.Error
	}
	policyName := g.PolicyName.Data
	if policyName == "" || g.organizationId == "" {
		g.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	org, err := NewResource(g.MqlRuntime, "gcp.organization", map[string]*llx.RawData{
		"id": llx.StringData(g.organizationId),
	})
	if err != nil {
		return nil, err
	}

	policies := org.(*mqlGcpOrganization).GetPrincipalAccessBoundaryPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, raw := range policies.Data {
		p, ok := raw.(*mqlGcpOrganizationPrincipalAccessBoundaryPolicy)
		if !ok || p == nil {
			continue
		}
		if p.Name.Error == nil && p.Name.Data == policyName {
			return p, nil
		}
	}

	// A binding can reference a policy in another organization, which the
	// organization-scoped list does not contain.
	g.Policy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// principalAccessBoundaryPolicies lists the organization's boundary policies.
// Boundary policies are defined only under locations/global.
func (g *mqlGcpOrganization) principalAccessBoundaryPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// Id is already in "organizations/{id}" form from initGcpOrganization.
	orgId := g.Id.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil
	}
	creds, err := conn.Credentials(iamv3.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iamv3.NewPrincipalAccessBoundaryPoliciesClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListPrincipalAccessBoundaryPolicies(ctx, &iampb.ListPrincipalAccessBoundaryPoliciesRequest{
		Parent: orgId + "/locations/global",
	})

	res := []any{}
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: an error partway through pagination
				// should not throw away the policies the API already returned.
				log.Warn().Err(err).Msg("could not list all principal access boundary policies")
				break
			}
			return nil, err
		}

		rules := make([]any, 0, len(p.GetDetails().GetRules()))
		for _, rule := range p.GetDetails().GetRules() {
			rules = append(rules, map[string]any{
				"description": rule.GetDescription(),
				"resources":   convert.SliceAnyToInterface(rule.GetResources()),
				"effect":      rule.GetEffect().String(),
			})
		}

		mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.organization.principalAccessBoundaryPolicy", map[string]*llx.RawData{
			"name":               llx.StringData(p.GetName()),
			"uid":                llx.StringData(p.GetUid()),
			"displayName":        llx.StringData(p.GetDisplayName()),
			"annotations":        llx.MapData(convert.MapToInterfaceMap(p.GetAnnotations()), types.String),
			"etag":               llx.StringData(p.GetEtag()),
			"enforcementVersion": llx.StringData(p.GetDetails().GetEnforcementVersion()),
			"rules":              llx.ArrayData(rules, types.Dict),
			"createTime":         llx.TimeDataPtr(timestampAsTimePtr(p.GetCreateTime())),
			"updateTime":         llx.TimeDataPtr(timestampAsTimePtr(p.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}

	return res, nil
}

// policyBindings lists the organization's policy bindings, the attachments that
// put a boundary policy into effect. A boundary policy with no binding
// constrains nothing, so the two collections are only meaningful together.
func (g *mqlGcpOrganization) policyBindings() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	orgId := g.Id.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil
	}
	creds, err := conn.Credentials(iamv3.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iamv3.NewPolicyBindingsClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListPolicyBindings(ctx, &iampb.ListPolicyBindingsRequest{
		Parent: orgId + "/locations/global",
	})

	res := []any{}
	for {
		b, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: keep the bindings already returned.
				log.Warn().Err(err).Msg("could not list all policy bindings")
				break
			}
			return nil, err
		}

		var target map[string]any
		if t := b.GetTarget(); t != nil {
			target = map[string]any{"principalSet": t.GetPrincipalSet()}
		}

		var condition map[string]any
		if c := b.GetCondition(); c != nil {
			condition = map[string]any{
				"expression":  c.GetExpression(),
				"title":       c.GetTitle(),
				"description": c.GetDescription(),
				"location":    c.GetLocation(),
			}
		}

		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.organization.policyBinding", map[string]*llx.RawData{
			"name":        llx.StringData(b.GetName()),
			"uid":         llx.StringData(b.GetUid()),
			"displayName": llx.StringData(b.GetDisplayName()),
			"target":      llx.DictData(target),
			"policyKind":  llx.StringData(b.GetPolicyKind().String()),
			"policyName":  llx.StringData(b.GetPolicy()),
			"condition":   llx.DictData(condition),
			"annotations": llx.MapData(convert.MapToInterfaceMap(b.GetAnnotations()), types.String),
			"etag":        llx.StringData(b.GetEtag()),
			"createTime":  llx.TimeDataPtr(timestampAsTimePtr(b.GetCreateTime())),
			"updateTime":  llx.TimeDataPtr(timestampAsTimePtr(b.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		mqlBinding.(*mqlGcpOrganizationPolicyBinding).organizationId = orgId
		res = append(res, mqlBinding)
	}

	return res, nil
}
