// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func newTestSecret(resp *secretsmanager.DescribeSecretOutput) *mqlAwsSecretsmanagerSecret {
	s := &mqlAwsSecretsmanagerSecret{MqlRuntime: testRuntime()}
	s.Arn = plugin.TValue[string]{Data: "arn:aws:secretsmanager:us-east-1:111111111111:secret:db-AbCdEf", State: plugin.StateIsSet}
	s.describeResp = resp
	return s
}

func TestSecretCrossAccountReplicas(t *testing.T) {
	// Synthetic: no live account pair with cross-account replication was available.
	s := newTestSecret(&secretsmanager.DescribeSecretOutput{
		CrossAccountReplicas: []secretstypes.CrossAccountReplicaEntry{
			{
				ReplicaSecretARN:   aws.String("arn:aws:secretsmanager:us-east-1:222222222222:secret:db-copy-XyZ"),
				ReplicationRoleARN: aws.String("arn:aws:iam::111111111111:role/replicator"),
				ReplicationStatus:  secretstypes.StatusTypeInSync,
			},
			{
				ReplicaSecretARN:  aws.String("arn:aws:secretsmanager:eu-west-1:333333333333:secret:db-copy-QrS"),
				ReplicationStatus: secretstypes.StatusTypeFailed,
				StatusMessage:     aws.String("access denied"),
			},
			{ReplicationStatus: secretstypes.StatusTypeInSync},
		},
	})

	res, err := s.crossAccountReplicas()
	require.NoError(t, err)
	require.Len(t, res, 2, "an entry without a replica ARN is dropped")

	first := res[0].(*mqlAwsSecretsmanagerSecretCrossAccountReplica)
	assert.Equal(t, "arn:aws:secretsmanager:us-east-1:222222222222:secret:db-copy-XyZ", first.Arn.Data)
	assert.Equal(t, "InSync", first.Status.Data)
	assert.Equal(t, "arn:aws:iam::111111111111:role/replicator", *first.cacheRoleArn)

	second := res[1].(*mqlAwsSecretsmanagerSecretCrossAccountReplica)
	assert.Equal(t, "access denied", second.StatusMessage.Data)
	assert.NotEqual(t, first.__id, second.__id)

	role, err := second.replicationRole()
	require.NoError(t, err)
	assert.Nil(t, role)
	assert.True(t, second.ReplicationRole.IsNull())

	_, err = s.crossAccountPrimaryArn()
	require.NoError(t, err)
	assert.True(t, s.CrossAccountPrimaryArn.IsNull(), "a primary secret has no cross-account primary")
}

func TestSecretCrossAccountPrimary(t *testing.T) {
	// Synthetic: the replica side of a cross-account pair.
	s := newTestSecret(&secretsmanager.DescribeSecretOutput{
		CrossAccountPrimary: &secretstypes.CrossAccountPrimaryType{
			PrimarySecretARN:  aws.String("arn:aws:secretsmanager:us-east-1:999999999999:secret:origin-AbC"),
			ReplicationStatus: secretstypes.StatusTypeDetached,
		},
	})

	arn, err := s.crossAccountPrimaryArn()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:secretsmanager:us-east-1:999999999999:secret:origin-AbC", arn)

	status, err := s.crossAccountPrimaryStatus()
	require.NoError(t, err)
	assert.Equal(t, "Detached", status)

	_, err = s.crossAccountPrimaryStatusMessage()
	require.NoError(t, err)
	assert.True(t, s.CrossAccountPrimaryStatusMessage.IsNull())

	replicas, err := s.crossAccountReplicas()
	require.NoError(t, err)
	assert.Empty(t, replicas)
}
