// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"github.com/gophercloud/gophercloud/v2/openstack/placement/v1/resourceproviders"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.placement.resourceProvider ----

type mqlOpenstackPlacementResourceProviderInternal struct {
	cacheParentUUID string
	cacheRootUUID   string
}

func (r *mqlOpenstackPlacementResourceProvider) id() (string, error) {
	return "openstack.placement.resourceProvider/" + r.Id.Data, nil
}

func initOpenstackPlacementResourceProvider(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetResourceProviders()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		rp := raw.(*mqlOpenstackPlacementResourceProvider)
		if rp.Id.Data == id {
			return args, rp, nil
		}
	}
	initSyntheticID("openstack.placement.resourceProvider", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) resourceProviders() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.PlacementClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := resourceproviders.List(client, resourceproviders.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := resourceproviders.ExtractResourceProviders(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		rp := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.placement.resourceProvider", map[string]*llx.RawData{
			"__id":       llx.StringData("openstack.placement.resourceProvider/" + rp.UUID),
			"id":         llx.StringData(rp.UUID),
			"name":       llx.StringData(rp.Name),
			"generation": llx.IntData(int64(rp.Generation)),
		})
		if err != nil {
			return nil, err
		}
		mqlRP := res.(*mqlOpenstackPlacementResourceProvider)
		mqlRP.cacheParentUUID = rp.ParentProviderUUID
		mqlRP.cacheRootUUID = rp.RootProviderUUID
		out = append(out, mqlRP)
	}
	return out, nil
}

func (r *mqlOpenstackPlacementResourceProvider) traits() ([]any, error) {
	client, err := conn(r.MqlRuntime).PlacementClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	res, err := resourceproviders.GetTraits(ctx(), client, r.Id.Data).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	return stringSlice(res.Traits), nil
}

// inventories returns one dict per resource class, joining the configured
// inventory (total/reserved/limits) with current usage so callers can compute
// free capacity per class (e.g. VGPU total vs used) in a single query.
func (r *mqlOpenstackPlacementResourceProvider) inventories() ([]any, error) {
	client, err := conn(r.MqlRuntime).PlacementClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	inv, err := resourceproviders.GetInventories(ctx(), client, r.Id.Data).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}

	// Usage is a best-effort enrichment; if it can't be read, report 0 used
	// rather than failing the inventory query.
	used := map[string]int{}
	if usage, uerr := resourceproviders.GetUsages(ctx(), client, r.Id.Data).Extract(); uerr == nil {
		used = usage.Usages
	}

	classes := make([]string, 0, len(inv.Inventories))
	for class := range inv.Inventories {
		classes = append(classes, class)
	}
	sort.Strings(classes)

	out := make([]any, 0, len(classes))
	for _, class := range classes {
		item := inv.Inventories[class]
		out = append(out, map[string]any{
			"resource_class":   class,
			"total":            item.Total,
			"reserved":         item.Reserved,
			"allocation_ratio": float64(item.AllocationRatio),
			"min_unit":         item.MinUnit,
			"max_unit":         item.MaxUnit,
			"step_size":        item.StepSize,
			"used":             used[class],
		})
	}
	return out, nil
}

func (r *mqlOpenstackPlacementResourceProvider) aggregates() ([]any, error) {
	client, err := conn(r.MqlRuntime).PlacementClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	res, err := resourceproviders.GetAggregates(ctx(), client, r.Id.Data).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	return stringSlice(res.Aggregates), nil
}

func (r *mqlOpenstackPlacementResourceProvider) parent() (*mqlOpenstackPlacementResourceProvider, error) {
	if r.cacheParentUUID == "" {
		r.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.placement.resourceProvider", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheParentUUID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackPlacementResourceProvider), nil
}

func (r *mqlOpenstackPlacementResourceProvider) root() (*mqlOpenstackPlacementResourceProvider, error) {
	if r.cacheRootUUID == "" {
		r.Root.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.placement.resourceProvider", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheRootUUID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackPlacementResourceProvider), nil
}
