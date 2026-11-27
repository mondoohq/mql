// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// subnetRoutes serves one VPC holding two subnets, and the routes of the
// first.
func subnetRoutes() map[string]route {
	return map[string]route{
		"/v2/vpcs": {200, `{"vpcs":[{"id":"vpc-1","name":"prod","region":"nyc3"}],"links":{},"meta":{"total":1}}`},
		"/v2/vpcs/vpc-1/subnets": {200, `{"vpc_subnets":[
			{"id":"sn-1","vpc_id":"vpc-1","name":"workers","ip_range":"10.10.0.0/24","default":false,"type":"PRIVATE","urn":"do:vpcsubnet:sn-1","region":"nyc3","created_at":"2026-10-01T10:00:00Z"},
			{"id":"sn-2","vpc_id":"vpc-1","name":"default","ip_range":"10.10.1.0/24","default":true,"region":"nyc3"}
		],"links":{},"meta":{"total":2}}`},
		"/v2/vpcs/vpc-1/subnets/sn-1/routes": {200, `{"routes":[
			{"id":"rt-vpc","type":"DYNAMIC","destination_cidr":"0.0.0.0/0","target_urns":["do:natgateway:n1"],"modifiable":false},
			{"id":"rt-sub","type":"STATIC","destination_cidr":"192.168.0.0/16","target_urns":["do:droplet:7"],"modifiable":true}
		],"links":{},"meta":{"total":2}}`},
	}
}

// Synthetic: a subnet in the shape of godo's VPCSubnet JSON, decoded through its struct tags; no live account was checked.
func TestVpcSubnetArgs(t *testing.T) {
	var s godo.VPCSubnet
	require.NoError(t, json.Unmarshal([]byte(`{"id":"sn-1","vpc_id":"vpc-1","name":"workers","ip_range":"10.10.0.0/24","default":true,"type":"PRIVATE","urn":"do:vpcsubnet:sn-1","region":"nyc3"}`), &s))
	args, err := vpcSubnetArgs(&s)
	require.NoError(t, err)
	assert.Equal(t, "10.10.0.0/24", args["ipRange"].Value)
	assert.Equal(t, true, args["default"].Value)
	assert.Equal(t, "PRIVATE", args["type"].Value)
	assert.Equal(t, "do:vpcsubnet:sn-1", args["urn"].Value)
	assert.Nil(t, args["createdAt"].Value, "an absent creation time is null, not year 1")

	_, err = vpcSubnetArgs(&godo.VPCSubnet{})
	assert.Error(t, err, "a subnet without an id cannot be keyed")
}

// Synthetic: a droplet's subnet resolves from the VPCs' subnet lists; no live account was checked.
func TestDropletSubnetResolvesFromIndex(t *testing.T) {
	rt := statusRuntime(t, subnetRoutes())

	d := &mqlDigitaloceanDroplet{MqlRuntime: rt}
	d.cacheSubnetUUID = "sn-2"
	s, err := d.subnet()
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "default", s.Name.Data)

	v, err := s.vpc()
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, "vpc-1", v.Id.Data)

	lb := &mqlDigitaloceanLoadBalancer{MqlRuntime: rt}
	lb.cacheSubnetUUID = "sn-gone"
	missing, err := lb.subnet()
	require.NoError(t, err)
	assert.Nil(t, missing)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, lb.Subnet.State, "a subnet no VPC lists is null")
}

// Synthetic: a resource placed in no subnet is null and costs no API call; no live account was checked.
func TestSubnetRefEmptyIsNullWithoutCalls(t *testing.T) {
	rt := routedRuntime(t, map[string]string{})
	k := &mqlDigitaloceanKubernetesCluster{MqlRuntime: rt, WorkerSubnetUuid: plugin.TValue[string]{Data: "", State: plugin.StateIsSet}}
	s, err := k.workerSubnet()
	require.NoError(t, err)
	assert.Nil(t, s)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, k.WorkerSubnet.State)
}

// Synthetic: a subnet's routes include the VPC-wide ones and are keyed by VPC like the VPC's own routes; no live account was checked.
func TestVpcSubnetRoutes(t *testing.T) {
	rt := statusRuntime(t, subnetRoutes())
	k := &mqlDigitaloceanKubernetesCluster{MqlRuntime: rt, WorkerSubnetUuid: plugin.TValue[string]{Data: "sn-1", State: plugin.StateIsSet}}
	s, err := k.workerSubnet()
	require.NoError(t, err)
	require.NotNil(t, s)

	routes, err := s.routes()
	require.NoError(t, err)
	require.Len(t, routes, 2)
	ids := []string{routes[0].(*mqlDigitaloceanVpcRoute).Id.Data, routes[1].(*mqlDigitaloceanVpcRoute).Id.Data}
	assert.Equal(t, []string{"rt-vpc", "rt-sub"}, ids)
	key, err := resourceID("digitalocean.vpc.route", "vpc-1", "rt-sub")
	require.NoError(t, err)
	assert.Equal(t, key, routes[1].(*mqlDigitaloceanVpcRoute).__id)
}
