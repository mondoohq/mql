// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVpcRouteArgs(t *testing.T) {
	created := time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)
	args, err := vpcRouteArgs("vpc-1", &godo.Route{
		ID:              "route-1",
		Type:            godo.RouteTypeStatic,
		DestinationCIDR: "10.20.0.0/16",
		TargetURNs:      []string{"do:droplet:12345", "do:load_balancer:abcde"},
		Modifiable:      true,
		CreatedAt:       created,
	})
	require.NoError(t, err)

	assert.Equal(t, "route-1", args["id"].Value)
	assert.Equal(t, "STATIC", args["type"].Value)
	assert.Equal(t, "10.20.0.0/16", args["destinationCidr"].Value)
	assert.Equal(t, []any{"do:droplet:12345", "do:load_balancer:abcde"}, args["targetUrns"].Value,
		"every target must survive the mapping: a route's egress is the whole target set, not the first one")
	assert.Equal(t, true, args["modifiable"].Value)
	assert.Equal(t, created, *args["createdAt"].Value.(*time.Time))
}

// A route ID is only unique within its VPC, so two VPCs carrying the same
// route ID must not collide in the resource cache. Dropping the VPC from the
// key makes the second VPC's route resolve to the first one's.
func TestVpcRouteArgsScopesTheCacheKeyToTheVpc(t *testing.T) {
	a, err := vpcRouteArgs("vpc-1", &godo.Route{ID: "route-1"})
	require.NoError(t, err)
	b, err := vpcRouteArgs("vpc-2", &godo.Route{ID: "route-1"})
	require.NoError(t, err)

	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
}

// A route the API reports without a creation time must read as null. The zero
// time would report 1 January year 1 as a real date, which an age check would
// then treat as an extremely old route.
func TestVpcRouteArgsCreatedAtIsNullWhenAbsent(t *testing.T) {
	args, err := vpcRouteArgs("vpc-1", &godo.Route{ID: "route-1", DestinationCIDR: "0.0.0.0/0"})
	require.NoError(t, err)
	assert.Nil(t, args["createdAt"].Value)
}

// A route with no targets must map to an empty list, not to null, so a policy
// counting targets sees zero rather than an unread field.
func TestVpcRouteArgsEmptyTargetsAreAnEmptyList(t *testing.T) {
	args, err := vpcRouteArgs("vpc-1", &godo.Route{ID: "route-1"})
	require.NoError(t, err)
	assert.Equal(t, []any{}, args["targetUrns"].Value)
}
