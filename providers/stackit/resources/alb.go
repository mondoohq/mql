// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	alb "github.com/stackitcloud/stackit-sdk-go/services/alb/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackit) albLoadBalancers() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ALB()
	if err != nil {
		return nil, err
	}
	out := []any{}
	pageId := ""
	for {
		req := client.DefaultAPI.ListLoadBalancers(bgctx(), c.ProjectID(), c.Region())
		if pageId != "" {
			req = req.PageId(pageId)
		}
		resp, err := req.Execute()
		if err != nil {
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		items, _ := resp.GetLoadBalancersOk()
		for i := range items {
			res, err := buildAlbLoadBalancer(r.MqlRuntime, &items[i], c.Region())
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		next, ok := resp.GetNextPageIdOk()
		if !ok || next == nil || *next == "" {
			break
		}
		pageId = *next
	}
	return out, nil
}

// mqlStackitAlbLoadBalancerInternal caches the raw listener and target-pool
// slices so the certificate, plaintext-port, and TLS-bridging accessors read
// typed SDK structs rather than the listeners/targetPools dicts, and the
// managed security-group ids so the typed refs resolve against the project's
// group list once per connection.
type mqlStackitAlbLoadBalancerInternal struct {
	rawListeners   []alb.Listener
	rawTargetPools []alb.TargetPool

	cacheLoadBalancerSecurityGroupId string
	cacheTargetSecurityGroupId       string
}

func initStackitAlbLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, ok := idArg(args, "name")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ALB()
	if err != nil {
		return nil, nil, err
	}
	lb, err := client.DefaultAPI.GetLoadBalancer(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	if lb == nil {
		return nil, nil, fmt.Errorf("stackit.alb.loadBalancer with name %q not found", name)
	}
	res, err := buildAlbLoadBalancer(runtime, lb, c.Region())
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func buildAlbLoadBalancer(runtime *plugin.Runtime, lb *alb.LoadBalancer, region string) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"name":                                 llx.StringData(lb.GetName()),
		"externalAddress":                      llx.StringData(lb.GetExternalAddress()),
		"privateAddress":                       llx.StringData(lb.GetPrivateAddress()),
		"planId":                               llx.StringData(lb.GetPlanId()),
		"status":                               llx.StringData(string(lb.GetStatus())),
		"region":                               llx.StringData(region),
		"listeners":                            llx.ArrayData(anySliceToDict(lb.GetListeners()), types.Dict),
		"networks":                             llx.ArrayData(anySliceToDict(lb.GetNetworks()), types.Dict),
		"targetPools":                          llx.ArrayData(anySliceToDict(lb.GetTargetPools()), types.Dict),
		"options":                              llx.DictData(toDict(lb.GetOptions())),
		"errors":                               llx.ArrayData(anySliceToDict(lb.GetErrors()), types.Dict),
		"loadBalancerSecurityGroup":            llx.DictData(toDict(lb.GetLoadBalancerSecurityGroup())),
		"targetSecurityGroup":                  llx.DictData(toDict(lb.GetTargetSecurityGroup())),
		"disableTargetSecurityGroupAssignment": llx.BoolDataPtr(lbDisableTargetSecurityGroupAssignment(lb)),
		"labels":                               labelData(lb.GetLabels()),
	}
	res, err := CreateResource(runtime, "stackit.alb.loadBalancer", args)
	if err != nil {
		return nil, err
	}
	mlb := res.(*mqlStackitAlbLoadBalancer)
	mlb.rawListeners = lb.GetListeners()
	mlb.rawTargetPools = lb.GetTargetPools()
	if sg, ok := lb.GetLoadBalancerSecurityGroupOk(); ok && sg != nil {
		mlb.cacheLoadBalancerSecurityGroupId = sg.GetId()
	}
	if sg, ok := lb.GetTargetSecurityGroupOk(); ok && sg != nil {
		mlb.cacheTargetSecurityGroupId = sg.GetId()
	}
	return res, nil
}

func (r *mqlStackitAlbLoadBalancer) id() (string, error) {
	return "stackit.alb.loadBalancer/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}
