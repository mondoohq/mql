// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/addressgroups"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackNetworkAddressGroupInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackNetworkAddressGroup) id() (string, error) {
	return "openstack.network.addressGroup/" + r.Id.Data, nil
}

func (o *mqlOpenstack) addressGroups() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := addressgroups.List(client, addressgroups.ListOpts{}).AllPages(ctx())
	if err != nil {
		// A cloud without the address-groups extension (or without access to it)
		// simply has no address groups rather than failing the query.
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := addressgroups.ExtractGroups(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		res, err := newMqlOpenstackAddressGroup(o.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackAddressGroup(runtime *plugin.Runtime, g *addressgroups.AddressGroup) (*mqlOpenstackNetworkAddressGroup, error) {
	res, err := CreateResource(runtime, "openstack.network.addressGroup", map[string]*llx.RawData{
		"__id":        llx.StringData("openstack.network.addressGroup/" + g.ID),
		"id":          llx.StringData(g.ID),
		"name":        llx.StringData(g.Name),
		"description": llx.StringData(g.Description),
		"addresses":   stringSliceData(g.Addresses),
	})
	if err != nil {
		return nil, err
	}
	mqlG := res.(*mqlOpenstackNetworkAddressGroup)
	mqlG.cacheProjectID = g.ProjectID
	return mqlG, nil
}

// initOpenstackNetworkAddressGroup resolves a group out of the project's cached
// list rather than fetching it by id. Every security-group rule that matches an
// address group resolves through here, so a per-id fetch would issue one call
// per rule; the list is a single call shared by all of them.
func initOpenstackNetworkAddressGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		initSyntheticID("openstack.network.addressGroup", "id", args)
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
	list := root.(*mqlOpenstack).GetAddressGroups()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		g, ok := raw.(*mqlOpenstackNetworkAddressGroup)
		if ok && g.Id.Data == id {
			return args, g, nil
		}
	}
	// Reporting the miss matters more here than elsewhere: a blank group would
	// answer containsPublicAddress with false, which is the false negative this
	// resource exists to remove.
	return nil, nil, fmt.Errorf("openstack.network.addressGroup with id %q not found", id)
}

// containsPublicAddress reports whether any member address opens a broad slice
// of the public internet. Security-group rules that match this group inherit
// that reach, so widening the group widens every rule referencing it.
func (r *mqlOpenstackNetworkAddressGroup) containsPublicAddress() (bool, error) {
	addresses := r.GetAddresses()
	if addresses.Error != nil {
		return false, addresses.Error
	}
	for _, raw := range addresses.Data {
		if s, ok := raw.(string); ok && addressIsPublic(s) {
			return true, nil
		}
	}
	return false, nil
}

func (r *mqlOpenstackNetworkAddressGroup) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
