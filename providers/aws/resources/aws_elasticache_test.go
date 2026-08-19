// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	elasticache_types "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestElasticacheClusterKmsKey covers the early-return null-state paths of
// kmsKey(), which resolve before any connection or API call. A cluster without
// a replication group (the KMS key only ever comes from the replication group)
// must report a set-but-null field rather than returning a bare nil, which would
// panic the runtime. The populated path requires a live API and is covered by
// interactive testing.
func TestElasticacheClusterKmsKey(t *testing.T) {
	t.Run("nil replication group ID sets null state", func(t *testing.T) {
		c := &mqlAwsElasticacheCluster{}
		result, err := c.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, c.KmsKey.IsNull())
		assert.True(t, c.KmsKey.IsSet())
	})

	t.Run("empty replication group ID sets null state", func(t *testing.T) {
		c := &mqlAwsElasticacheCluster{}
		empty := ""
		c.cacheReplicationGroupId = &empty
		result, err := c.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, c.KmsKey.IsNull())
		assert.True(t, c.KmsKey.IsSet())
	})
}

// TestElasticacheSecurityGroupArns covers the branch that skips a security
// group membership the API reports without an id. That branch logs the cluster
// id, which is itself optional, and it is the path a partially populated
// cluster record is most likely to take. jobpool runs the lister with no panic
// recovery, so a deref here kills the provider process rather than one query.
func TestElasticacheSecurityGroupArns(t *testing.T) {
	const (
		region    = "us-east-1"
		accountID = "000000000000"
	)

	sgID := func(id string) elasticache_types.SecurityGroupMembership {
		return elasticache_types.SecurityGroupMembership{SecurityGroupId: &id}
	}

	tests := []struct {
		name     string
		cluster  elasticache_types.CacheCluster
		expected []string
	}{
		{
			name:     "no security groups",
			cluster:  elasticache_types.CacheCluster{},
			expected: []string{},
		},
		{
			name: "all memberships carry an id",
			cluster: elasticache_types.CacheCluster{
				CacheClusterId: aws.String("my-cluster"),
				SecurityGroups: []elasticache_types.SecurityGroupMembership{
					sgID("sg-0123456789abcdef0"),
					sgID("sg-0fedcba9876543210"),
				},
			},
			expected: []string{
				"arn:aws:ec2:us-east-1:000000000000:security-group/sg-0123456789abcdef0",
				"arn:aws:ec2:us-east-1:000000000000:security-group/sg-0fedcba9876543210",
			},
		},
		{
			name: "membership without an id is skipped",
			cluster: elasticache_types.CacheCluster{
				CacheClusterId: aws.String("my-cluster"),
				SecurityGroups: []elasticache_types.SecurityGroupMembership{
					{},
					sgID("sg-0123456789abcdef0"),
				},
			},
			expected: []string{"arn:aws:ec2:us-east-1:000000000000:security-group/sg-0123456789abcdef0"},
		},
		{
			// The skip path logs the cluster id, so an absent one must not be
			// dereferenced to report the skip.
			name: "membership without an id on a cluster without an id",
			cluster: elasticache_types.CacheCluster{
				SecurityGroups: []elasticache_types.SecurityGroupMembership{{}},
			},
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected,
				elasticacheSecurityGroupArns(region, accountID, test.cluster))
		})
	}
}
