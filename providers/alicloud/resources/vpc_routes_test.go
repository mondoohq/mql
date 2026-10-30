// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"github.com/stretchr/testify/assert"
)

// TestRouteEntryNextHop covers the next-hop extraction that decides where a
// route leads. Returning an empty hop for a populated route would make a
// default route look like it goes nowhere, so the nil-element and empty-list
// cases carry the weight here.
func TestRouteEntryNextHop(t *testing.T) {
	hop := func(hopType, hopID string) *vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntryNextHops {
		return &vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntryNextHops{
			NextHop: []*vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntryNextHopsNextHop{
				{NextHopType: new(hopType), NextHopId: new(hopID)},
			},
		}
	}

	t.Run("nil entry", func(t *testing.T) {
		hopType, hopID := routeEntryNextHop(nil)
		assert.Equal(t, "", hopType)
		assert.Equal(t, "", hopID)
	})
	t.Run("entry with no next hops struct", func(t *testing.T) {
		hopType, hopID := routeEntryNextHop(&vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry{})
		assert.Equal(t, "", hopType)
		assert.Equal(t, "", hopID)
	})
	t.Run("empty next hop list", func(t *testing.T) {
		entry := &vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry{
			NextHops: &vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntryNextHops{},
		}
		hopType, hopID := routeEntryNextHop(entry)
		assert.Equal(t, "", hopType)
		assert.Equal(t, "", hopID)
	})
	t.Run("a nat gateway hop", func(t *testing.T) {
		entry := &vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry{
			NextHops: hop("NatGateway", "ngw-bp1uewa15k4abc"),
		}
		hopType, hopID := routeEntryNextHop(entry)
		assert.Equal(t, "NatGateway", hopType)
		assert.Equal(t, "ngw-bp1uewa15k4abc", hopID)
	})
	t.Run("a nil element is skipped rather than returned empty", func(t *testing.T) {
		entry := &vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntry{
			NextHops: &vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntryNextHops{
				NextHop: []*vpcclient.DescribeRouteEntryListResponseBodyRouteEntrysRouteEntryNextHopsNextHop{
					nil,
					{NextHopType: new("Instance"), NextHopId: new("i-abc")},
				},
			},
		}
		hopType, hopID := routeEntryNextHop(entry)
		assert.Equal(t, "Instance", hopType)
		assert.Equal(t, "i-abc", hopID)
	})
}

// TestVpcNetworkAclEntryKey covers the rule cache key. The id-less fallback is
// the case that matters: keying every such rule the same way would collapse a
// whole ACL's rules onto a single resource and hide all but one of them.
func TestVpcNetworkAclEntryKey(t *testing.T) {
	t.Run("the rule id is used when present", func(t *testing.T) {
		key := vpcNetworkAclEntryKey("ingress", vpcNetworkAclEntryArgs{
			entryID:  new("nae-bp1abc"),
			protocol: new("tcp"),
		})
		assert.Equal(t, "nae-bp1abc", key)
	})

	t.Run("id-less rules stay distinct from each other", func(t *testing.T) {
		ssh := vpcNetworkAclEntryKey("ingress", vpcNetworkAclEntryArgs{
			protocol:     new("tcp"),
			port:         new("22/22"),
			sourceCidrIp: new("0.0.0.0/0"),
		})
		https := vpcNetworkAclEntryKey("ingress", vpcNetworkAclEntryArgs{
			protocol:     new("tcp"),
			port:         new("443/443"),
			sourceCidrIp: new("0.0.0.0/0"),
		})
		assert.NotEqual(t, ssh, https)
	})

	t.Run("direction separates an otherwise identical rule", func(t *testing.T) {
		in := vpcNetworkAclEntryKey("ingress", vpcNetworkAclEntryArgs{
			protocol: new("all"), port: new("-1/-1"),
		})
		out := vpcNetworkAclEntryKey("egress", vpcNetworkAclEntryArgs{
			protocol: new("all"), port: new("-1/-1"),
		})
		assert.NotEqual(t, in, out)
	})

	t.Run("source and destination share one slot in the key", func(t *testing.T) {
		src := vpcNetworkAclEntryKey("ingress", vpcNetworkAclEntryArgs{
			protocol: new("tcp"), port: new("22/22"),
			sourceCidrIp: new("10.0.0.0/8"),
		})
		dst := vpcNetworkAclEntryKey("ingress", vpcNetworkAclEntryArgs{
			protocol: new("tcp"), port: new("22/22"),
			destinationCidrIp: new("10.0.0.0/8"),
		})
		assert.Equal(t, src, dst,
			"source and destination are never both set on one rule, so they share the slot")
	})
}
