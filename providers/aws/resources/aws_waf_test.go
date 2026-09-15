// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// TestElbWebAclNullForNonApplicationLB verifies that webAcl() short-circuits to a
// set-null value for every load balancer type that cannot carry a WAFv2 web ACL
// (Network, Gateway, Classic, or an unset type), without reaching the WAFv2 API.
func TestElbWebAclNullForNonApplicationLB(t *testing.T) {
	for _, elbType := range []string{"network", "gateway", "classic", ""} {
		t.Run("elbType="+elbType, func(t *testing.T) {
			lb := &mqlAwsElbLoadbalancer{}
			lb.ElbType = plugin.TValue[string]{Data: elbType, State: plugin.StateIsSet}
			result, err := lb.webAcl()
			require.NoError(t, err)
			require.Nil(t, result)
			assert.True(t, lb.WebAcl.IsNull())
			assert.True(t, lb.WebAcl.IsSet())
		})
	}
}

// TestWafAssociatedLoadBalancersEmptyForCloudFront verifies that a
// CloudFront-scoped web ACL returns an empty association list (CloudFront ACLs
// attach through distributions, not the regional ListResourcesForWebACL API),
// without reaching the WAFv2 API.
func TestWafAssociatedLoadBalancersEmptyForCloudFront(t *testing.T) {
	acl := &mqlAwsWafAcl{}
	acl.Scope = plugin.TValue[string]{Data: "CLOUDFRONT", State: plugin.StateIsSet}
	result, err := acl.associatedLoadBalancers()
	require.NoError(t, err)
	assert.Empty(t, result)
}

// TestWafScopesFor pins which scopes a query covers. CLOUDFRONT and REGIONAL
// are separate estates: CloudFront web ACLs live only in us-east-1, regional
// ones are per-region, and neither on its own describes an account's WAF
// posture. So no scope has to mean both, not a default of one.
func TestWafScopesFor(t *testing.T) {
	assert.Equal(t, []string{"CLOUDFRONT"}, wafScopesFor("CLOUDFRONT"))
	assert.Equal(t, []string{"REGIONAL"}, wafScopesFor("REGIONAL"))

	both := []string{"CLOUDFRONT", "REGIONAL"}
	assert.Equal(t, both, wafScopesFor(""), "no scope covers both")

	// An unrecognized scope is not silently treated as one of the two, since
	// picking either would report a partial estate as the whole one.
	assert.Equal(t, both, wafScopesFor("Regional"))
	assert.Equal(t, both, wafScopesFor("global"))
}

// TestWafRegionsFor pins where each scope is queried. CLOUDFRONT is pinned to
// us-east-1, which is where WAF keeps those ACLs regardless of where the
// distribution serves from; REGIONAL takes the connection's whole region list,
// because querying only the default region reported an empty estate for every
// account whose ACLs live anywhere else.
func TestWafRegionsFor(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1", "ap-southeast-2")

	cloudfront, err := wafRegionsFor(conn, "CLOUDFRONT")
	require.NoError(t, err)
	assert.Equal(t, []string{"us-east-1"}, cloudfront)

	regional, err := wafRegionsFor(conn, "REGIONAL")
	require.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "eu-west-1", "ap-southeast-2"}, regional,
		"regional resources exist per region, so every region is queried")
}
