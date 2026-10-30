// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/qos"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlOpenstackBlockstorageQosSpec) id() (string, error) {
	return "openstack.blockstorage.qosSpec/" + r.Id.Data, nil
}

func (o *mqlOpenstack) blockStorageQosSpecs() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BlockStorageClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := qos.List(client, qos.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := qos.ExtractQoS(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		res, err := newMqlOpenstackQosSpec(o.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackQosSpec(runtime *plugin.Runtime, q *qos.QoS) (*mqlOpenstackBlockstorageQosSpec, error) {
	res, err := CreateResource(runtime, "openstack.blockstorage.qosSpec", map[string]*llx.RawData{
		"__id":     llx.StringData("openstack.blockstorage.qosSpec/" + q.ID),
		"id":       llx.StringData(q.ID),
		"name":     llx.StringData(q.Name),
		"consumer": llx.StringData(q.Consumer),
		"specs":    stringMapData(q.Specs),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageQosSpec), nil
}

func initOpenstackBlockstorageQosSpec(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		initSyntheticID("openstack.blockstorage.qosSpec", "id", args)
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	client, err := conn(runtime).BlockStorageClient()
	if err != nil {
		if serviceMissing(err) {
			return args, nil, nil
		}
		return nil, nil, err
	}
	q, err := qos.Get(ctx(), client, id).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return args, nil, nil
		}
		return nil, nil, err
	}
	res, err := newMqlOpenstackQosSpec(runtime, q)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (r *mqlOpenstackBlockstorageVolumeType) qosSpec() (*mqlOpenstackBlockstorageQosSpec, error) {
	if r.cacheQosSpecID == "" {
		r.QosSpec.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.qosSpec", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheQosSpecID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageQosSpec), nil
}
