// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// mqlDigitaloceanVpcSubnetInternal keeps the id of the VPC a subnet belongs
// to, which the subnet routes endpoint is keyed by and vpc() resolves.
type mqlDigitaloceanVpcSubnetInternal struct {
	cacheVpcID string
}

// vpcSubnetArgs maps a subnet to its MQL fields. Subnet ids are UUIDs, so the
// id alone keys the cache.
func vpcSubnetArgs(s *godo.VPCSubnet) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.vpc.subnet", s.ID)
	if err != nil {
		return nil, err
	}
	return map[string]*llx.RawData{
		"__id":    llx.StringData(id),
		"id":      llx.StringData(s.ID),
		"name":    llx.StringData(s.Name),
		"ipRange": llx.StringData(s.IPRange),
		"type":    llx.StringData(s.Type),
		"region":  llx.StringData(s.Region),
		"default": llx.BoolData(s.Default),
		"urn":     llx.StringData(s.URN),
		// An absent creation time stays null rather than becoming the zero
		// time, which would report 1 January year 1 as a real date.
		"createdAt": llx.TimeDataPtr(timePtr(s.CreatedAt)),
	}, nil
}

// subnets lists the subnets the VPC's address range is divided into.
func (r *mqlDigitaloceanVpc) subnets() ([]any, error) {
	vpcID := r.Id.Data
	if vpcID == "" {
		return nil, errors.New("cannot list VPC subnets without a VPC id")
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	subnets, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.VPCSubnet, *godo.Response, error) {
		return client.VPCs.ListSubnets(c, vpcID, o)
	})
	if err != nil {
		// A VPC removed between the listing and this call answers 404, which
		// is genuinely no subnets. Denied and transient reads propagate.
		if isDoNotFound(err) {
			return []any{}, nil
		}
		return nil, classifyDoError(err)
	}

	out := make([]any, 0, len(subnets))
	for _, s := range subnets {
		// godo hands back a slice of pointers; a nil entry would panic the
		// provider and take the whole scan with it.
		if s == nil || s.ID == "" {
			continue
		}
		args, err := vpcSubnetArgs(s)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vpc.subnet", args)
		if err != nil {
			return nil, err
		}
		res.(*mqlDigitaloceanVpcSubnet).cacheVpcID = vpcID
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanVpcSubnet) id() (string, error) {
	return resourceID("digitalocean.vpc.subnet", r.Id.Data)
}

func (r *mqlDigitaloceanVpcSubnet) vpc() (*mqlDigitaloceanVpc, error) {
	return resolveVpcRef(r.MqlRuntime, &r.Vpc, r.cacheVpcID)
}

// routes lists the routes in effect for the subnet. The endpoint includes
// the VPC-scoped routes propagated into the subnet, which resolve to the same
// resources the VPC's own routes() returns.
func (r *mqlDigitaloceanVpcSubnet) routes() ([]any, error) {
	vpcID, subnetID := r.cacheVpcID, r.Id.Data
	if vpcID == "" || subnetID == "" {
		return nil, errors.New("cannot list subnet routes without a VPC id and a subnet id")
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	routes, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.Route, *godo.Response, error) {
		return client.Routes.ListSubnetRoutes(c, vpcID, subnetID, o)
	})
	if err != nil {
		// A subnet removed between the listing and this call answers 404,
		// which is genuinely an empty route table.
		if isDoNotFound(err) {
			return []any{}, nil
		}
		return nil, classifyDoError(err)
	}

	out := make([]any, 0, len(routes))
	for _, rt := range routes {
		if rt == nil || rt.ID == "" {
			continue
		}
		args, err := vpcRouteArgs(vpcID, rt)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vpc.route", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// subnetByID resolves a subnet from the subnet lists of every VPC, read once
// per scan. It returns nil when no VPC lists the subnet.
func (r *mqlDigitalocean) subnetByID(id string) (*mqlDigitaloceanVpcSubnet, error) {
	r.subnetIndexOnce.Do(func() {
		vpcs := r.GetVpcs()
		if vpcs.Error != nil {
			r.subnetIndexErr = vpcs.Error
			return
		}
		idx := map[string]*mqlDigitaloceanVpcSubnet{}
		for _, v := range vpcs.Data {
			subnets := v.(*mqlDigitaloceanVpc).GetSubnets()
			if subnets.Error != nil {
				r.subnetIndexErr = subnets.Error
				return
			}
			for _, s := range subnets.Data {
				ms := s.(*mqlDigitaloceanVpcSubnet)
				idx[ms.Id.Data] = ms
			}
		}
		r.subnetIndex = idx
	})
	if r.subnetIndexErr != nil {
		return nil, r.subnetIndexErr
	}
	return r.subnetIndex[id], nil
}

// resolveSubnetRef resolves a subnet by id for a typed accessor, marking the
// field null when the id is unset or no VPC lists the subnet.
func resolveSubnetRef(runtime *plugin.Runtime, target *plugin.TValue[*mqlDigitaloceanVpcSubnet], subnetID string) (*mqlDigitaloceanVpcSubnet, error) {
	if strings.TrimSpace(subnetID) == "" {
		target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(runtime)
	if err != nil {
		return nil, err
	}
	subnet, err := parent.subnetByID(subnetID)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return subnet, nil
}

func (r *mqlDigitaloceanDroplet) subnet() (*mqlDigitaloceanVpcSubnet, error) {
	return resolveSubnetRef(r.MqlRuntime, &r.Subnet, r.cacheSubnetUUID)
}

func (r *mqlDigitaloceanLoadBalancer) subnet() (*mqlDigitaloceanVpcSubnet, error) {
	return resolveSubnetRef(r.MqlRuntime, &r.Subnet, r.cacheSubnetUUID)
}

func (r *mqlDigitaloceanKubernetesCluster) workerSubnet() (*mqlDigitaloceanVpcSubnet, error) {
	return resolveSubnetRef(r.MqlRuntime, &r.WorkerSubnet, r.WorkerSubnetUuid.Data)
}
