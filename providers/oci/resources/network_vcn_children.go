// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// vcnChildren filters one of the tenancy-wide network lists down to the members
// of this VCN.
//
// OCI's list APIs are compartment-scoped, not VCN-scoped, so there is no call
// that returns "the subnets of this VCN" directly. Every child type already
// caches the OCID of the VCN it belongs to (the same value its own vcn()
// accessor resolves against), so the reverse edge is a filter over the list the
// oci.network singleton already holds. That singleton is runtime-cached, so a
// query walking several VCNs pays for the listing once rather than once per VCN.
func vcnChildren[T any](o *mqlOciNetworkVcn, list func(*mqlOciNetwork) *plugin.TValue[[]any], vcnIDOf func(T) string) ([]any, error) {
	networkResource, err := CreateResource(o.MqlRuntime, "oci.network", nil)
	if err != nil {
		return nil, err
	}

	all := list(networkResource.(*mqlOciNetwork))
	if all.Error != nil {
		return nil, all.Error
	}

	vcnID := o.Id.Data
	res := []any{}
	for _, entry := range all.Data {
		child, ok := entry.(T)
		if !ok {
			continue
		}
		if vcnIDOf(child) == vcnID {
			res = append(res, entry)
		}
	}
	return res, nil
}

func (o *mqlOciNetworkVcn) subnets() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetSubnets() },
		func(s *mqlOciNetworkSubnet) string { return s.cacheVcnID })
}

func (o *mqlOciNetworkVcn) routeTables() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetRouteTables() },
		func(r *mqlOciNetworkRouteTable) string { return r.cacheVcnID })
}

func (o *mqlOciNetworkVcn) securityLists() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetSecurityLists() },
		func(s *mqlOciNetworkSecurityList) string { return s.cacheVcnID })
}

func (o *mqlOciNetworkVcn) networkSecurityGroups() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetNetworkSecurityGroups() },
		func(g *mqlOciNetworkNetworkSecurityGroup) string { return g.cacheVcnID })
}

func (o *mqlOciNetworkVcn) internetGateways() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetInternetGateways() },
		func(g *mqlOciNetworkInternetGateway) string { return g.cacheVcnID })
}

func (o *mqlOciNetworkVcn) natGateways() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetNatGateways() },
		func(g *mqlOciNetworkNatGateway) string { return g.cacheVcnID })
}

// defaultRouteTable is the route table OCI applies to subnets that name none of
// their own. Resolved by OCID rather than filtered out of routeTables() so the
// lookup stays a single Get when that is all the query asks for.
func (o *mqlOciNetworkVcn) defaultRouteTable() (*mqlOciNetworkRouteTable, error) {
	id := o.DefaultRouteTableId.Data
	if id == "" || !isOcid(id) {
		o.DefaultRouteTable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.network.routeTable", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciNetworkRouteTable), nil
}

// defaultSecurityList is the security list OCI applies to subnets that name
// none of their own.
func (o *mqlOciNetworkVcn) defaultSecurityList() (*mqlOciNetworkSecurityList, error) {
	id := o.DefaultSecurityListId.Data
	if id == "" || !isOcid(id) {
		o.DefaultSecurityList.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.network.securityList", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciNetworkSecurityList), nil
}

type mqlOciNetworkVcnInternal struct {
	ociCompartmentRef
}
