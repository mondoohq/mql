// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type mqlGcpHierarchicalFirewallPolicyInternal struct {
	// cacheRules holds the rules from the list response, so reading rules costs no
	// second call. The list endpoint returns them inline.
	cacheRules []*compute.FirewallPolicyRule
}

func (g *mqlGcpHierarchicalFirewallPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// listHierarchicalFirewallPolicies lists the firewall policies defined on a
// resource-manager node.
//
// parent must be "organizations/{id}" or "folders/{id}". These are a different
// object from the network firewall policies attached inside a project: their
// rules are evaluated first and cannot be overridden from below, so a project
// scoped firewall review cannot see them.
func listHierarchicalFirewallPolicies(runtime *plugin.Runtime, parent string) ([]any, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	call := computeSvc.FirewallPolicies.List().ParentId(parent)
	if err := call.Pages(ctx, func(page *compute.FirewallPolicyList) error {
		for _, p := range page.Items {
			if p == nil {
				continue
			}

			associations := hierarchicalFirewallPolicyAssociations(p.Associations)

			mqlPolicy, err := CreateResource(runtime, "gcp.hierarchicalFirewallPolicy", map[string]*llx.RawData{
				"name":           llx.StringData(p.Name),
				"shortName":      llx.StringData(p.ShortName),
				"description":    llx.StringData(p.Description),
				"parent":         llx.StringData(p.Parent),
				"selfLink":       llx.StringData(p.SelfLink),
				"ruleTupleCount": llx.IntData(p.RuleTupleCount),
				"fingerprint":    llx.StringData(p.Fingerprint),
				"created":        llx.TimeDataPtr(parseTime(p.CreationTimestamp)),
				"associations":   llx.ArrayData(associations, types.Dict),
			})
			if err != nil {
				return err
			}
			mqlPolicy.(*mqlGcpHierarchicalFirewallPolicy).cacheRules = p.Rules
			res = append(res, mqlPolicy)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("parent", parent).Msg("could not list hierarchical firewall policies")
			return nil, nil
		}
		return nil, err
	}

	return res, nil
}

// hierarchicalFirewallPolicyAssociations maps a policy's associations to
// dicts. Priority is null when the API reports none: 0 is not a valid
// priority (1 is the highest).
func hierarchicalFirewallPolicyAssociations(in []*compute.FirewallPolicyAssociation) []any {
	res := make([]any, 0, len(in))
	for _, a := range in {
		if a == nil {
			continue
		}
		var priority any
		if a.Priority != 0 {
			priority = a.Priority
		}
		res = append(res, map[string]any{
			"name":             a.Name,
			"attachmentTarget": a.AttachmentTarget,
			"firewallPolicyId": a.FirewallPolicyId,
			"shortName":        a.ShortName,
			"displayName":      a.DisplayName,
			"priority":         priority,
		})
	}
	return res
}

// rules maps the policy's rules, reusing the mapping that serves network
// firewall policies since both carry the same rule type.
func (g *mqlGcpHierarchicalFirewallPolicy) rules() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	return mqlFirewallPolicyRules(g.MqlRuntime, g.Name.Data, g.cacheRules)
}

func (g *mqlGcpOrganization) firewallPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// Id is already in "organizations/{id}" form from initGcpOrganization.
	return listHierarchicalFirewallPolicies(g.MqlRuntime, g.Id.Data)
}

func (g *mqlGcpFolder) firewallPolicies() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listHierarchicalFirewallPolicies(g.MqlRuntime, "folders/"+g.Id.Data)
}
