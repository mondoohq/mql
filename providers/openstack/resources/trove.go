// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/db/v1/databases"
	"github.com/gophercloud/gophercloud/v2/openstack/db/v1/instances"
	"github.com/gophercloud/gophercloud/v2/openstack/db/v1/users"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.db.instance ----

type mqlOpenstackDbInstanceInternal struct {
	cacheFlavorID string
}

func (r *mqlOpenstackDbInstance) id() (string, error) {
	return "openstack.db.instance/" + r.Id.Data, nil
}

func initOpenstackDbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetDatabaseInstances()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		inst := raw.(*mqlOpenstackDbInstance)
		if inst.Id.Data == id {
			return args, inst, nil
		}
	}
	initSyntheticID("openstack.db.instance", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) databaseInstances() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.DatabaseClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := instances.List(client).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := instances.ExtractInstances(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		inst := &items[i]
		addresses := make([]any, 0, len(inst.Addresses))
		for _, a := range inst.Addresses {
			addresses = append(addresses, map[string]any{
				"type":    a.Type,
				"address": a.Address,
			})
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.db.instance", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.db.instance/" + inst.ID),
			"id":               llx.StringData(inst.ID),
			"name":             llx.StringData(inst.Name),
			"status":           llx.StringData(inst.Status),
			"hostname":         llx.StringData(inst.Hostname),
			"datastoreType":    llx.StringData(inst.Datastore.Type),
			"datastoreVersion": llx.StringData(inst.Datastore.Version),
			"volumeSize":       llx.IntData(int64(inst.Volume.Size)),
			"created":          llx.TimeDataPtr(timePtr(inst.Created)),
			"addresses":        dictSliceData(addresses),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance := res.(*mqlOpenstackDbInstance)
		mqlInstance.cacheFlavorID = inst.Flavor.ID
		out = append(out, mqlInstance)
	}
	return out, nil
}

func (r *mqlOpenstackDbInstance) flavor() (*mqlOpenstackComputeFlavor, error) {
	if r.cacheFlavorID == "" {
		r.Flavor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.compute.flavor", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheFlavorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeFlavor), nil
}

func (r *mqlOpenstackDbInstance) databases() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.DatabaseClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := databases.List(client, r.Id.Data).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := databases.ExtractDBs(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, db := range items {
		out = append(out, map[string]any{
			"name":    db.Name,
			"charset": db.CharSet,
			"collate": db.Collate,
		})
	}
	return out, nil
}

func (r *mqlOpenstackDbInstance) users() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.DatabaseClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := users.List(client, r.Id.Data).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := users.ExtractUsers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, u := range items {
		dbNames := make([]any, 0, len(u.Databases))
		for _, db := range u.Databases {
			dbNames = append(dbNames, db.Name)
		}
		// The user password (u.Password) is credential material and is not exposed.
		out = append(out, map[string]any{
			"name":      u.Name,
			"databases": dbNames,
		})
	}
	return out, nil
}
