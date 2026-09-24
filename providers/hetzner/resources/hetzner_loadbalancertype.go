// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlHetznerLoadBalancerType) id() (string, error) {
	return fmt.Sprintf("hetzner.loadBalancerType/%d", r.Id.Data), nil
}

func (h *mqlHetzner) loadBalancerTypes() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.LoadBalancerType, *hcloud.Response, error) {
		return c.Client().LoadBalancerType.List(ctx(), hcloud.LoadBalancerTypeListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, t := range items {
		res, err := newMqlHetznerLoadBalancerType(h.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerLoadBalancerType(runtime *plugin.Runtime, t *hcloud.LoadBalancerType) (*mqlHetznerLoadBalancerType, error) {
	res, err := CreateResource(runtime, "hetzner.loadBalancerType", map[string]*llx.RawData{
		"__id":                    llx.StringData(fmt.Sprintf("hetzner.loadBalancerType/%d", t.ID)),
		"id":                      llx.IntData(t.ID),
		"name":                    llx.StringData(t.Name),
		"description":             llx.StringData(t.Description),
		"maxConnections":          llx.IntData(int64(t.MaxConnections)),
		"maxServices":             llx.IntData(int64(t.MaxServices)),
		"maxTargets":              llx.IntData(int64(t.MaxTargets)),
		"maxAssignedCertificates": llx.IntData(int64(t.MaxAssignedCertificates)),
		"deprecation":             llx.DictData(deprecationDict(t.Deprecation)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerLoadBalancerType), nil
}

func initHetznerLoadBalancerType(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "loadBalancerType")
	if err != nil {
		return nil, nil, err
	}
	t, _, err := conn(runtime).Client().LoadBalancerType.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if t == nil {
		return nil, nil, notFoundErr("loadBalancerType", id)
	}
	res, err := newMqlHetznerLoadBalancerType(runtime, t)
	return args, res, err
}
