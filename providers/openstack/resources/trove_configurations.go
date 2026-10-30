// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/db/v1/configurations"
	"github.com/gophercloud/gophercloud/v2/openstack/db/v1/instances"
	"go.mondoo.com/mql/llx"
)

func (r *mqlOpenstackDbConfiguration) id() (string, error) {
	return "openstack.db.configuration/" + r.Id.Data, nil
}

func (o *mqlOpenstack) databaseConfigurations() ([]any, error) {
	client, err := conn(o.MqlRuntime).DatabaseClient()
	if err != nil {
		return nil, err
	}
	pages, err := configurations.List(client).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := configurations.ExtractConfigs(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, c := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.db.configuration", map[string]*llx.RawData{
			"__id":                 llx.StringData("openstack.db.configuration/" + c.ID),
			"id":                   llx.StringData(c.ID),
			"name":                 llx.StringData(c.Name),
			"description":          llx.StringData(c.Description),
			"datastoreName":        llx.StringData(c.DatastoreName),
			"datastoreVersionName": llx.StringData(c.DatastoreVersionName),
			"values":               llx.DictData(toDict(c.Values)),
			"createdAt":            llx.TimeDataPtr(timePtr(c.Created)),
			"updatedAt":            llx.TimeDataPtr(timePtr(c.Updated)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// instances reads the database instances this configuration group is attached
// to. Trove only exposes the association from the group, so this is one call
// per group and it stays lazy until the field is asked for.
func (r *mqlOpenstackDbConfiguration) instances() ([]any, error) {
	client, err := conn(r.MqlRuntime).DatabaseClient()
	if err != nil {
		return nil, err
	}
	pages, err := configurations.ListInstances(client, r.Id.Data).AllPages(ctx())
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
	for _, inst := range items {
		res, err := NewResource(r.MqlRuntime, "openstack.db.instance", map[string]*llx.RawData{
			"id": llx.StringData(inst.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
