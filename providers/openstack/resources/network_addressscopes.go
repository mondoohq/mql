// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/addressscopes"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackNetworkAddressScopeInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackNetworkAddressScope) id() (string, error) {
	return "openstack.network.addressScope/" + r.Id.Data, nil
}

func (o *mqlOpenstack) addressScopes() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := addressscopes.List(client, addressscopes.ListOpts{}).AllPages(ctx())
	if err != nil {
		// A cloud without the address-scope extension (or a token without access
		// to it) has no address scopes rather than a failed query.
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := addressscopes.ExtractAddressScopes(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		res, err := newMqlOpenstackAddressScope(o.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackAddressScope(runtime *plugin.Runtime, s *addressscopes.AddressScope) (*mqlOpenstackNetworkAddressScope, error) {
	res, err := CreateResource(runtime, "openstack.network.addressScope", map[string]*llx.RawData{
		"__id":      llx.StringData("openstack.network.addressScope/" + s.ID),
		"id":        llx.StringData(s.ID),
		"name":      llx.StringData(s.Name),
		"ipVersion": llx.IntData(int64(s.IPVersion)),
		"shared":    llx.BoolData(s.Shared),
	})
	if err != nil {
		return nil, err
	}
	mqlS := res.(*mqlOpenstackNetworkAddressScope)
	// ProjectID is the owner; fall back to the legacy TenantID alias.
	owner := s.ProjectID
	if owner == "" {
		owner = s.TenantID
	}
	mqlS.cacheProjectID = owner
	return mqlS, nil
}

// initOpenstackNetworkAddressScope resolves a scope out of the cached list
// rather than fetching it by id. Every subnet pool bound to a scope and every
// RBAC policy sharing one resolves through here, so a per-id fetch would issue
// one call per pool and per policy; the list is a single call shared by all.
func initOpenstackNetworkAddressScope(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		initSyntheticID("openstack.network.addressScope", "id", args)
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetAddressScopes()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s, ok := raw.(*mqlOpenstackNetworkAddressScope)
		if ok && s.Id.Data == id {
			return args, s, nil
		}
	}
	// A blank scope would report shared as false, which is the reading this
	// resource exists to make trustworthy, so report the miss instead.
	return nil, nil, fmt.Errorf("openstack.network.addressScope with id %q not found", id)
}

func (r *mqlOpenstackNetworkAddressScope) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
