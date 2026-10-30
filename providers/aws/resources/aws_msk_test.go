// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafka_types "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ===== null-state tests =====

func TestMskClusterBrokerNodeGroupNullOnServerless(t *testing.T) {
	c := &mqlAwsMskCluster{}
	// provisioned is nil (serverless-only)
	got, err := c.brokerNodeGroup()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, c.BrokerNodeGroup.IsNull())
	assert.True(t, c.BrokerNodeGroup.IsSet())
}

func TestMskClusterServerlessConfigNullOnProvisioned(t *testing.T) {
	c := &mqlAwsMskCluster{}
	// serverless is nil (provisioned-only)
	got, err := c.serverlessConfig()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, c.ServerlessConfig.IsNull())
	assert.True(t, c.ServerlessConfig.IsSet())
}

func TestMskClusterStorageModeNullOnServerless(t *testing.T) {
	c := &mqlAwsMskCluster{}
	// provisioned nil → storageMode returns "" with null state
	got, err := c.storageMode()
	require.NoError(t, err)
	assert.Equal(t, "", got)
	assert.True(t, c.StorageMode.IsNull())
	assert.True(t, c.StorageMode.IsSet())
}

func TestMskClusterEbsVolumeSizeGiBNullOnServerless(t *testing.T) {
	c := &mqlAwsMskCluster{}
	got, err := c.ebsVolumeSizeGiB()
	require.NoError(t, err)
	assert.Equal(t, int64(0), got)
	assert.True(t, c.EbsVolumeSizeGiB.IsNull())
	assert.True(t, c.EbsVolumeSizeGiB.IsSet())
}

func TestMskClusterNetworkType(t *testing.T) {
	t.Run("null when provisioned has no connectivity info", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			BrokerNodeGroupInfo: &kafka_types.BrokerNodeGroupInfo{
				// ConnectivityInfo is nil
			},
		}
		got, err := c.networkType()
		require.NoError(t, err)
		assert.Equal(t, "", got)
		assert.True(t, c.NetworkType.IsNull())
		assert.True(t, c.NetworkType.IsSet())
	})

	t.Run("null on empty cluster (no provisioned, no serverless)", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		got, err := c.networkType()
		require.NoError(t, err)
		assert.Equal(t, "", got)
		assert.True(t, c.NetworkType.IsNull())
	})

	t.Run("returns value for provisioned with connectivity", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			BrokerNodeGroupInfo: &kafka_types.BrokerNodeGroupInfo{
				ConnectivityInfo: &kafka_types.ConnectivityInfo{
					NetworkType: kafka_types.NetworkTypeIpv4,
				},
			},
		}
		got, err := c.networkType()
		require.NoError(t, err)
		assert.Equal(t, "IPV4", got)
	})

	t.Run("returns value for serverless", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.serverless = &kafka_types.Serverless{
			ConnectivityInfo: &kafka_types.ServerlessConnectivityInfo{
				NetworkType: kafka_types.NetworkTypeDual,
			},
		}
		got, err := c.networkType()
		require.NoError(t, err)
		assert.Equal(t, "DUAL", got)
	})
}

func TestMskClusterPublicAccess(t *testing.T) {
	t.Run("null on serverless", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		got, err := c.publicAccess()
		require.NoError(t, err)
		assert.False(t, got)
		assert.True(t, c.PublicAccess.IsNull())
	})

	t.Run("false when type DISABLED", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			BrokerNodeGroupInfo: &kafka_types.BrokerNodeGroupInfo{
				ConnectivityInfo: &kafka_types.ConnectivityInfo{
					PublicAccess: &kafka_types.PublicAccess{Type: aws.String("DISABLED")},
				},
			},
		}
		got, err := c.publicAccess()
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("true when type SERVICE_PROVIDED_EIPS", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			BrokerNodeGroupInfo: &kafka_types.BrokerNodeGroupInfo{
				ConnectivityInfo: &kafka_types.ConnectivityInfo{
					PublicAccess: &kafka_types.PublicAccess{Type: aws.String("SERVICE_PROVIDED_EIPS")},
				},
			},
		}
		got, err := c.publicAccess()
		require.NoError(t, err)
		assert.True(t, got)
	})
}

// ===== anyAuthEnabled / clientAuth semantics =====

func TestMskClusterAnyAuthEnabled(t *testing.T) {
	t.Run("unauthenticated-only does not count as auth", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			ClientAuthentication: &kafka_types.ClientAuthentication{
				Unauthenticated: &kafka_types.Unauthenticated{Enabled: aws.Bool(true)},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.False(t, got, "unauthenticated traffic alone must not report anyAuthEnabled=true")
	})

	t.Run("IAM enabled is auth", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			ClientAuthentication: &kafka_types.ClientAuthentication{
				Sasl: &kafka_types.Sasl{
					Iam: &kafka_types.Iam{Enabled: aws.Bool(true)},
				},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("SCRAM enabled is auth", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			ClientAuthentication: &kafka_types.ClientAuthentication{
				Sasl: &kafka_types.Sasl{
					Scram: &kafka_types.Scram{Enabled: aws.Bool(true)},
				},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("mTLS enabled is auth", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			ClientAuthentication: &kafka_types.ClientAuthentication{
				Tls: &kafka_types.Tls{Enabled: aws.Bool(true)},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("IAM + unauthenticated still counts as auth", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			ClientAuthentication: &kafka_types.ClientAuthentication{
				Sasl: &kafka_types.Sasl{
					Iam: &kafka_types.Iam{Enabled: aws.Bool(true)},
				},
				Unauthenticated: &kafka_types.Unauthenticated{Enabled: aws.Bool(true)},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("everything off returns false", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.provisioned = &kafka_types.Provisioned{
			ClientAuthentication: &kafka_types.ClientAuthentication{
				Sasl: &kafka_types.Sasl{
					Iam:   &kafka_types.Iam{Enabled: aws.Bool(false)},
					Scram: &kafka_types.Scram{Enabled: aws.Bool(false)},
				},
				Tls:             &kafka_types.Tls{Enabled: aws.Bool(false)},
				Unauthenticated: &kafka_types.Unauthenticated{Enabled: aws.Bool(false)},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("serverless IAM enabled", func(t *testing.T) {
		c := &mqlAwsMskCluster{}
		c.serverless = &kafka_types.Serverless{
			ClientAuthentication: &kafka_types.ServerlessClientAuthentication{
				Sasl: &kafka_types.ServerlessSasl{
					Iam: &kafka_types.Iam{Enabled: aws.Bool(true)},
				},
			},
		}
		got, err := c.anyAuthEnabled()
		require.NoError(t, err)
		assert.True(t, got)
	})
}

// ===== replicator cross-region/account + lazy-describe null-state =====

func TestMskReplicatorDescription(t *testing.T) {
	t.Run("null when describe returns nil", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {}) // mark as done, leaves describeResp nil
		got, err := r.description()
		require.NoError(t, err)
		assert.Equal(t, "", got)
		assert.True(t, r.Description.IsNull())
		assert.True(t, r.Description.IsSet())
	})

	t.Run("returns value from describe", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {})
		r.describeResp = &kafka.DescribeReplicatorOutput{
			ReplicatorDescription: aws.String("test description"),
		}
		got, err := r.description()
		require.NoError(t, err)
		assert.Equal(t, "test description", got)
	})
}

func TestMskReplicatorStateCodeAndMessage(t *testing.T) {
	t.Run("stateCode null when StateInfo nil", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {})
		r.describeResp = &kafka.DescribeReplicatorOutput{}
		got, err := r.stateCode()
		require.NoError(t, err)
		assert.Equal(t, "", got)
		assert.True(t, r.StateCode.IsNull())
	})

	t.Run("stateMessage null when StateInfo nil", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {})
		r.describeResp = &kafka.DescribeReplicatorOutput{}
		got, err := r.stateMessage()
		require.NoError(t, err)
		assert.Equal(t, "", got)
		assert.True(t, r.StateMessage.IsNull())
	})

	t.Run("stateCode populated from StateInfo", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {})
		r.describeResp = &kafka.DescribeReplicatorOutput{
			StateInfo: &kafka_types.ReplicationStateInfo{
				Code:    aws.String("RUNNING"),
				Message: aws.String("all good"),
			},
		}
		code, err := r.stateCode()
		require.NoError(t, err)
		assert.Equal(t, "RUNNING", code)
		msg, err := r.stateMessage()
		require.NoError(t, err)
		assert.Equal(t, "all good", msg)
	})
}

func TestMskReplicatorServiceExecutionRoleNull(t *testing.T) {
	t.Run("null when role arn missing", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {})
		r.describeResp = &kafka.DescribeReplicatorOutput{} // no ServiceExecutionRoleArn
		got, err := r.serviceExecutionRole()
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.True(t, r.ServiceExecutionRole.IsNull())
		assert.True(t, r.ServiceExecutionRole.IsSet())
	})
}

func TestMskReplicatorIsCrossRegion(t *testing.T) {
	t.Run("false for single region", func(t *testing.T) {
		r := buildReplicatorWithClusters(
			"arn:aws:kafka:us-east-1:111111111111:cluster/a/11111111-1111-1111-1111-111111111111-1",
			"arn:aws:kafka:us-east-1:111111111111:cluster/b/22222222-2222-2222-2222-222222222222-2",
		)
		got, err := r.isCrossRegion()
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("true when regions differ", func(t *testing.T) {
		r := buildReplicatorWithClusters(
			"arn:aws:kafka:us-east-1:111111111111:cluster/a/11111111-1111-1111-1111-111111111111-1",
			"arn:aws:kafka:us-west-2:111111111111:cluster/b/22222222-2222-2222-2222-222222222222-2",
		)
		got, err := r.isCrossRegion()
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("false when describe response is nil", func(t *testing.T) {
		r := &mqlAwsMskReplicator{}
		r.describeOnce.Do(func() {})
		got, err := r.isCrossRegion()
		require.NoError(t, err)
		assert.False(t, got)
	})
}

func TestMskReplicatorIsCrossAccount(t *testing.T) {
	t.Run("false for same account", func(t *testing.T) {
		r := buildReplicatorWithClusters(
			"arn:aws:kafka:us-east-1:111111111111:cluster/a/11111111-1111-1111-1111-111111111111-1",
			"arn:aws:kafka:us-east-1:111111111111:cluster/b/22222222-2222-2222-2222-222222222222-2",
		)
		got, err := r.isCrossAccount()
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("true when accounts differ", func(t *testing.T) {
		r := buildReplicatorWithClusters(
			"arn:aws:kafka:us-east-1:111111111111:cluster/a/11111111-1111-1111-1111-111111111111-1",
			"arn:aws:kafka:us-east-1:222222222222:cluster/b/22222222-2222-2222-2222-222222222222-2",
		)
		got, err := r.isCrossAccount()
		require.NoError(t, err)
		assert.True(t, got)
	})
}

func buildReplicatorWithClusters(arns ...string) *mqlAwsMskReplicator {
	clusters := make([]kafka_types.KafkaClusterDescription, 0, len(arns))
	for _, a := range arns {
		clusters = append(clusters, kafka_types.KafkaClusterDescription{
			AmazonMskCluster: &kafka_types.AmazonMskCluster{MskClusterArn: &a},
		})
	}
	r := &mqlAwsMskReplicator{}
	r.describeOnce.Do(func() {})
	r.describeResp = &kafka.DescribeReplicatorOutput{KafkaClusters: clusters}
	return r
}

// ===== compile-time guard that State helpers exist on the generated resources =====

var (
	_ interface {
		IsSet() bool
		IsNull() bool
	} = &plugin.TValue[string]{}
)
