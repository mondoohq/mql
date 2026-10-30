// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/rbacpolicies"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackNetworkRbacPolicyInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackNetworkRbacPolicy) id() (string, error) {
	return "openstack.network.rbacPolicy/" + r.Id.Data, nil
}

func (o *mqlOpenstack) rbacPolicies() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := rbacpolicies.List(client, rbacpolicies.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := rbacpolicies.ExtractRBACPolicies(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := newMqlOpenstackRbacPolicy(o.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackRbacPolicy(runtime *plugin.Runtime, p *rbacpolicies.RBACPolicy) (*mqlOpenstackNetworkRbacPolicy, error) {
	res, err := CreateResource(runtime, "openstack.network.rbacPolicy", map[string]*llx.RawData{
		"__id":            llx.StringData("openstack.network.rbacPolicy/" + p.ID),
		"id":              llx.StringData(p.ID),
		"action":          llx.StringData(string(p.Action)),
		"objectType":      llx.StringData(p.ObjectType),
		"objectId":        llx.StringData(p.ObjectID),
		"targetProjectId": llx.StringData(p.TargetTenant),
	})
	if err != nil {
		return nil, err
	}
	mqlP := res.(*mqlOpenstackNetworkRbacPolicy)
	// ProjectID is the owner; fall back to the legacy TenantID alias.
	owner := p.ProjectID
	if owner == "" {
		owner = p.TenantID
	}
	mqlP.cacheProjectID = owner
	return mqlP, nil
}

func initOpenstackNetworkRbacPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		initSyntheticID("openstack.network.rbacPolicy", "id", args)
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	client, err := conn(runtime).NetworkClient()
	if err != nil {
		return nil, nil, err
	}
	p, err := rbacpolicies.Get(ctx(), client, id).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return args, nil, nil
		}
		return nil, nil, err
	}
	res, err := newMqlOpenstackRbacPolicy(runtime, p)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// normalizeRBACObjectType folds a Neutron RBAC object_type into a single
// spelling. Neutron reports the multi-word types with either a hyphen or an
// underscore depending on release ("qos-policy" and "qos_policy" are the same
// type), so matching on one literal silently drops the other spelling and the
// policy resolves to nothing.
func normalizeRBACObjectType(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
}

// rbacObjectTypeIs reports whether the policy targets the given object type,
// tolerating either spelling.
func rbacObjectTypeIs(actual, want string) bool {
	return normalizeRBACObjectType(actual) == normalizeRBACObjectType(want)
}

func (r *mqlOpenstackNetworkRbacPolicy) network() (*mqlOpenstackNetwork, error) {
	if !rbacObjectTypeIs(r.ObjectType.Data, "network") || r.ObjectId.Data == "" {
		r.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network", map[string]*llx.RawData{
		"id": llx.StringData(r.ObjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetwork), nil
}

func (r *mqlOpenstackNetworkRbacPolicy) qosPolicy() (*mqlOpenstackQosPolicy, error) {
	if !rbacObjectTypeIs(r.ObjectType.Data, "qos-policy") || r.ObjectId.Data == "" {
		r.QosPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.qosPolicy", map[string]*llx.RawData{
		"id": llx.StringData(r.ObjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackQosPolicy), nil
}

func (r *mqlOpenstackNetworkRbacPolicy) securityGroup() (*mqlOpenstackSecurityGroup, error) {
	if !rbacObjectTypeIs(r.ObjectType.Data, "security_group") || r.ObjectId.Data == "" {
		r.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.securityGroup", map[string]*llx.RawData{
		"id": llx.StringData(r.ObjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSecurityGroup), nil
}

func (r *mqlOpenstackNetworkRbacPolicy) subnetPool() (*mqlOpenstackSubnetPool, error) {
	if !rbacObjectTypeIs(r.ObjectType.Data, "subnetpool") || r.ObjectId.Data == "" {
		r.SubnetPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnetPool", map[string]*llx.RawData{
		"id": llx.StringData(r.ObjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnetPool), nil
}

func (r *mqlOpenstackNetworkRbacPolicy) addressScope() (*mqlOpenstackNetworkAddressScope, error) {
	if !rbacObjectTypeIs(r.ObjectType.Data, "address_scope") || r.ObjectId.Data == "" {
		r.AddressScope.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network.addressScope", map[string]*llx.RawData{
		"id": llx.StringData(r.ObjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetworkAddressScope), nil
}

func (r *mqlOpenstackNetworkRbacPolicy) addressGroup() (*mqlOpenstackNetworkAddressGroup, error) {
	if !rbacObjectTypeIs(r.ObjectType.Data, "address_group") || r.ObjectId.Data == "" {
		r.AddressGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network.addressGroup", map[string]*llx.RawData{
		"id": llx.StringData(r.ObjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetworkAddressGroup), nil
}

func (r *mqlOpenstackNetworkRbacPolicy) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
