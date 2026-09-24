// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerPlacementGroupInternal struct {
	cacheServerIDs []int64
}

func (r *mqlHetznerPlacementGroup) id() (string, error) {
	return fmt.Sprintf("hetzner.placementGroup/%d", r.Id.Data), nil
}

func (h *mqlHetzner) placementGroups() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.PlacementGroup, *hcloud.Response, error) {
		return c.Client().PlacementGroup.List(ctx(), hcloud.PlacementGroupListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, pg := range items {
		res, err := newMqlHetznerPlacementGroup(h.MqlRuntime, pg)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerPlacementGroup(runtime *plugin.Runtime, pg *hcloud.PlacementGroup) (*mqlHetznerPlacementGroup, error) {
	res, err := CreateResource(runtime, "hetzner.placementGroup", map[string]*llx.RawData{
		"__id":    llx.StringData(fmt.Sprintf("hetzner.placementGroup/%d", pg.ID)),
		"id":      llx.IntData(pg.ID),
		"name":    llx.StringData(pg.Name),
		"type":    llx.StringData(string(pg.Type)),
		"created": llx.TimeDataPtr(timePtr(pg.Created)),
		"labels":  labelData(pg.Labels),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerPlacementGroup)
	m.cacheServerIDs = pg.Servers
	return m, nil
}

func initHetznerPlacementGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "placementGroup")
	if err != nil {
		return nil, nil, err
	}
	pg, _, err := conn(runtime).Client().PlacementGroup.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if pg == nil {
		return nil, nil, notFoundErr("placementGroup", id)
	}
	res, err := newMqlHetznerPlacementGroup(runtime, pg)
	return args, res, err
}

func (m *mqlHetznerPlacementGroup) servers() ([]any, error) {
	out := make([]any, 0, len(m.cacheServerIDs))
	for _, id := range m.cacheServerIDs {
		ref, err := NewResource(m.MqlRuntime, "hetzner.server", map[string]*llx.RawData{
			"id": llx.IntData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}
