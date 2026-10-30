// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlHetznerStorageBoxType) id() (string, error) {
	return fmt.Sprintf("hetzner.storageBoxType/%d", r.Id.Data), nil
}

func (h *mqlHetzner) storageBoxTypes() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.StorageBoxType, *hcloud.Response, error) {
		return c.Client().StorageBoxType.List(ctx(), hcloud.StorageBoxTypeListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, t := range items {
		res, err := newMqlHetznerStorageBoxType(h.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerStorageBoxType(runtime *plugin.Runtime, t *hcloud.StorageBoxType) (*mqlHetznerStorageBoxType, error) {
	res, err := CreateResource(runtime, "hetzner.storageBoxType", map[string]*llx.RawData{
		"__id":                   llx.StringData(fmt.Sprintf("hetzner.storageBoxType/%d", t.ID)),
		"id":                     llx.IntData(t.ID),
		"name":                   llx.StringData(t.Name),
		"description":            llx.StringData(t.Description),
		"snapshotLimit":          llx.IntDataDefault(t.SnapshotLimit, 0),
		"automaticSnapshotLimit": llx.IntDataDefault(t.AutomaticSnapshotLimit, 0),
		"subaccountsLimit":       llx.IntData(int64(t.SubaccountsLimit)),
		"size":                   llx.IntData(t.Size),
		"deprecated":             llx.TimeDataPtr(timePtrUnix0(t.UnavailableAfter())),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerStorageBoxType), nil
}

func initHetznerStorageBoxType(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "storageBoxType")
	if err != nil {
		return nil, nil, err
	}
	t, _, err := conn(runtime).Client().StorageBoxType.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if t == nil {
		return nil, nil, notFoundErr("storageBoxType", id)
	}
	res, err := newMqlHetznerStorageBoxType(runtime, t)
	return args, res, err
}
