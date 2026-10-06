// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
)

type mqlExoscaleNlbInternal struct {
	cacheServices []v3.LoadBalancerService
}

func (r *mqlExoscaleNlb) id() (string, error) {
	return "exoscale.nlb/" + r.Id.Data, nil
}

func (r *mqlExoscale) nlbs() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-load-balancers", func(c *v3.Client) ([]v3.LoadBalancer, error) {
		res, err := c.ListLoadBalancers(ctx())
		if err != nil {
			return nil, err
		}
		return res.LoadBalancers, nil
	})
	if err != nil {
		return nil, err
	}
	filters := conn(r.MqlRuntime).Filters
	out := make([]any, 0, len(items))
	for _, it := range items {
		lb := it.item
		if filters.IsFilteredOut(lb.Labels) {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.nlb", map[string]*llx.RawData{
			"__id":          llx.StringData("exoscale.nlb/" + string(lb.ID)),
			"id":            llx.StringData(string(lb.ID)),
			"zone":          llx.StringData(it.zone),
			"name":          llx.StringData(lb.Name),
			"description":   llx.StringData(lb.Description),
			"ip":            llx.StringData(ipString(lb.IP)),
			"addressFamily": llx.StringData(string(lb.Addressfamily)),
			"state":         llx.StringData(string(lb.State)),
			"created":       timeData(lb.CreatedAT),
			"labels":        labelData(lb.Labels),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlExoscaleNlb).cacheServices = lb.Services
		out = append(out, res)
	}
	return out, nil
}

func initExoscaleNlb(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	if id == "" {
		id = connection.AssetOption(conn(runtime).Conf, connection.OptionNlb)
	}
	if id == "" {
		return nil, nil, fmt.Errorf("exoscale.nlb requires an id, for example exoscale.nlb(id: \"<uuid>\")")
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, nil, err
	}
	list := ns.GetNlbs()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	if lb, ok := pickOneByID(list.Data, id, func(l *mqlExoscaleNlb) string { return l.Id.Data }); ok {
		return args, lb, nil
	}
	return nil, nil, fmt.Errorf("exoscale.nlb with id %q not found", id)
}

type mqlExoscaleNlbServiceInternal struct {
	cacheInstancePoolID string
}

func (r *mqlExoscaleNlb) services() ([]any, error) {
	out := make([]any, 0, len(r.cacheServices))
	for _, s := range r.cacheServices {
		args := map[string]*llx.RawData{
			"__id":                llx.StringData("exoscale.nlb.service/" + r.Id.Data + "/" + string(s.ID)),
			"id":                  llx.StringData(string(s.ID)),
			"name":                llx.StringData(s.Name),
			"description":         llx.StringData(s.Description),
			"port":                llx.IntData(s.Port),
			"targetPort":          llx.IntData(s.TargetPort),
			"protocol":            llx.StringData(string(s.Protocol)),
			"strategy":            llx.StringData(string(s.Strategy)),
			"state":               llx.StringData(string(s.State)),
			"healthcheckMode":     llx.StringData(""),
			"healthcheckPort":     llx.NilData,
			"healthcheckUri":      llx.StringData(""),
			"healthcheckInterval": llx.NilData,
			"healthcheckTimeout":  llx.NilData,
			"healthcheckRetries":  llx.NilData,
			"healthcheckTlsSni":   llx.StringData(""),
		}
		if h := s.Healthcheck; h != nil {
			args["healthcheckMode"] = llx.StringData(string(h.Mode))
			args["healthcheckPort"] = llx.IntData(h.Port)
			args["healthcheckUri"] = llx.StringData(h.URI)
			args["healthcheckInterval"] = llx.IntData(h.Interval)
			args["healthcheckTimeout"] = llx.IntData(h.Timeout)
			args["healthcheckRetries"] = llx.IntData(h.Retries)
			args["healthcheckTlsSni"] = llx.StringData(h.TlsSNI)
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.nlb.service", args)
		if err != nil {
			return nil, err
		}
		if s.InstancePool != nil {
			res.(*mqlExoscaleNlbService).cacheInstancePoolID = string(s.InstancePool.ID)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlExoscaleNlbService) instancePool() (*mqlExoscaleComputeInstancePool, error) {
	return instancePoolByID(r.MqlRuntime, r.cacheInstancePoolID, &r.InstancePool)
}
