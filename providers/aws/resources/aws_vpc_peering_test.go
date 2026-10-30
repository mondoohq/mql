// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The accepter and the requester of one peering connection must not share a
// cache key. They used to: the key was built from the region and the VPC id,
// and the VPC id is empty while the generated constructor runs, so every side
// of every connection in a region collapsed onto one entry and whichever side
// was built second returned the first one's CIDRs.
func TestPeeringVpcCacheKeySeparatesTheTwoSides(t *testing.T) {
	accepter := peeringVpcCacheKey("pcx-06c03109ac23954e0", "accepter")
	requester := peeringVpcCacheKey("pcx-06c03109ac23954e0", "requester")

	require.NotEqual(t, accepter, requester,
		"the two sides of one peering connection must have distinct cache keys")
	assert.Equal(t, "aws.vpc.peeringConnection.peeringVpc/pcx-06c03109ac23954e0/accepter", accepter)
	assert.Equal(t, "aws.vpc.peeringConnection.peeringVpc/pcx-06c03109ac23954e0/requester", requester)
}

// A hub VPC peered to several spokes appears once per connection. Keying on the
// VPC id would have merged those too, so the same side of two connections has
// to stay distinct.
func TestPeeringVpcCacheKeySeparatesConnections(t *testing.T) {
	first := peeringVpcCacheKey("pcx-1111111111111111a", "requester")
	second := peeringVpcCacheKey("pcx-2222222222222222b", "requester")

	assert.NotEqual(t, first, second,
		"the same side of two peering connections must have distinct cache keys")
}

// The old key was region + VPC id, and the VPC id is "" at construction time.
// Pin the shape that made every side collide so a regression cannot reintroduce
// a key that ignores the connection id.
func TestPeeringVpcCacheKeyDoesNotCollapseOnAnEmptyVpcId(t *testing.T) {
	const region = "us-west-2"
	oldKey := func(vpcID string) string {
		return "aws.vpc.peeringConnection.peeringVpc/" + region + "/" + vpcID
	}

	// what the old key produced for both sides, since cacheVpcId was unset
	assert.Equal(t, oldKey(""), oldKey(""),
		"sanity: the old key was identical for both sides")

	// the new key never depends on a value that is empty at construction
	keys := map[string]bool{}
	for _, side := range []string{"accepter", "requester"} {
		for _, pcx := range []string{"pcx-aaa", "pcx-bbb"} {
			k := peeringVpcCacheKey(pcx, side)
			require.False(t, keys[k], "duplicate cache key %q", k)
			keys[k] = true
		}
	}
	assert.Len(t, keys, 4)
}
