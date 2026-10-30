// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

func TestParseWafv2WebAclArn(t *testing.T) {
	// Synthetic: regional web ACL ARN in the documented format.
	region, scope, name, id, err := parseWafv2WebAclArn("arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/my-acl/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111")
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", region)
	assert.Equal(t, wafScopeRegional, scope)
	assert.Equal(t, "my-acl", name)
	assert.Equal(t, "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111", id)

	// Synthetic: a global ARN is a CLOUDFRONT-scoped ACL.
	region, scope, _, _, err = parseWafv2WebAclArn("arn:aws:wafv2:us-east-1:123456789012:global/webacl/edge/abc")
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", region)
	assert.Equal(t, wafScopeCloudfront, scope)

	// Synthetic: malformed and non-web-ACL ARNs are rejected.
	for _, bad := range []string{
		"",
		"not-an-arn",
		"arn:aws:waf::123456789012:webacl/abc",
		"arn:aws:wafv2:eu-west-1:123456789012:regional/ipset/my-set/abc",
		"arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/my-acl",
		"arn:aws:wafv2:eu-west-1:123456789012:other/webacl/my-acl/abc",
	} {
		_, _, _, _, err := parseWafv2WebAclArn(bad)
		assert.Error(t, err, bad)
	}
}
