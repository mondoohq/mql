// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

const testVpcArn = "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abc123"

func cacheRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// A resource an earlier reference already materialized comes back without an
// API call. NewResource consults the cache only after the init returns, so
// without this the same VPC is fetched once per referring resource -- four EC2
// instances in one VPC measured four DescribeVpcs calls for the one VPC.
func TestCachedByArn_ReturnsTheCachedResource(t *testing.T) {
	runtime := cacheRuntime()

	vpc, err := CreateResource(runtime, ResourceAwsVpc, map[string]*llx.RawData{
		"arn": llx.StringData(testVpcArn),
	})
	require.NoError(t, err)

	got := cachedByArn(runtime, ResourceAwsVpc, testVpcArn)
	assert.Same(t, vpc, got)
}

// A miss returns nil so the caller stays on its existing fetch path.
func TestCachedByArn_MissFallsThrough(t *testing.T) {
	runtime := cacheRuntime()

	assert.Nil(t, cachedByArn(runtime, ResourceAwsVpc, testVpcArn))
	assert.Nil(t, cachedByArn(runtime, ResourceAwsVpc, ""))
	assert.Nil(t, cachedByArn(nil, ResourceAwsVpc, testVpcArn))
}

// The lookup must not cross resource types: two resources can share an ARN
// shape only by accident, and returning the wrong type would panic the caller's
// assertion.
func TestCachedByArn_ScopedToTheResourceType(t *testing.T) {
	runtime := cacheRuntime()

	_, err := CreateResource(runtime, ResourceAwsVpc, map[string]*llx.RawData{
		"arn": llx.StringData(testVpcArn),
	})
	require.NoError(t, err)

	assert.Nil(t, cachedByArn(runtime, ResourceAwsIamRole, testVpcArn),
		"a vpc must not answer a lookup for an iam role")
}

func TestCachedArgByArn(t *testing.T) {
	runtime := cacheRuntime()
	vpc, err := CreateResource(runtime, ResourceAwsVpc, map[string]*llx.RawData{
		"arn": llx.StringData(testVpcArn),
	})
	require.NoError(t, err)

	t.Run("reads the arn out of args", func(t *testing.T) {
		got := cachedArgByArn(runtime, ResourceAwsVpc, map[string]*llx.RawData{
			"arn": llx.StringData(testVpcArn),
		})
		assert.Same(t, vpc, got)
	})

	// Referrers that pass only an id keep their existing path: the cache key is
	// the ARN, so there is nothing to look up.
	t.Run("no arn argument is a miss", func(t *testing.T) {
		assert.Nil(t, cachedArgByArn(runtime, ResourceAwsVpc, map[string]*llx.RawData{
			"id": llx.StringData("vpc-abc123"),
		}))
		assert.Nil(t, cachedArgByArn(runtime, ResourceAwsVpc, map[string]*llx.RawData{}))
	})

	t.Run("a non-string arn is a miss, not a panic", func(t *testing.T) {
		assert.Nil(t, cachedArgByArn(runtime, ResourceAwsVpc, map[string]*llx.RawData{
			"arn": llx.IntData(42),
		}))
	})
}

// The init keeps its fast path: a caller that supplied everything must not be
// diverted, and a cache miss must leave the existing lookup untouched.
func TestInitAwsVpc_UsesTheCacheThenFallsThrough(t *testing.T) {
	runtime := cacheRuntime()
	vpc, err := CreateResource(runtime, ResourceAwsVpc, map[string]*llx.RawData{
		"arn": llx.StringData(testVpcArn),
	})
	require.NoError(t, err)

	args, res, err := initAwsVpc(runtime, map[string]*llx.RawData{
		"arn": llx.StringData(testVpcArn),
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Same(t, vpc, res, "must return the cached vpc rather than calling DescribeVpcs")
	assert.NotNil(t, args)
}
