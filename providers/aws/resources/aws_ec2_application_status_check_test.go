// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== status typed-ref null-state =====

func TestApplicationStatusInstanceNullWhenNoInstanceId(t *testing.T) {
	s := &mqlAwsEc2ApplicationStatusCheckStatus{}
	s.cacheInstanceId = ""
	got, err := s.instance()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, s.Instance.IsNull())
	assert.True(t, s.Instance.IsSet())
}

// ===== instance arn is built, not returned by the API =====

// The status only carries an instance id, and initAwsEc2Instance resolves by
// arn, so the arn is assembled from the region and account. A drift in the
// pattern would resolve to nothing rather than fail loudly.
func TestEc2InstanceArnPattern(t *testing.T) {
	got := fmt.Sprintf(ec2InstanceArnPattern, "us-east-1", "123456789012", "i-1234567890abcdef0")
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0", got)
}

// ===== deletion visibility =====

// The lister passes IncludeAll, so the response mixes live checks with ones
// deleted recently enough to still be inside their grace period. These pin that
// the two are distinguishable: a live check reports deleted false and leaves
// deletedAt null, rather than reporting a zero time that reads as a real date.
func TestApplicationStatusCheckDeletionFields(t *testing.T) {
	deletedAt := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	t.Run("live check", func(t *testing.T) {
		res, err := newMqlAwsEc2ApplicationStatusCheck(testRuntime(), "us-east-1",
			ec2types.ApplicationStatusCheckResponseObject{
				ApplicationStatusCheckId: aws.String("asc-0123456789abcdef0"),
			})
		require.NoError(t, err)

		check := res.(*mqlAwsEc2ApplicationStatusCheck)
		assert.False(t, check.Deleted.Data)
		assert.True(t, check.DeletedAt.IsNull(), "a live check has no deletion time")
	})

	t.Run("deleted check inside its grace period", func(t *testing.T) {
		res, err := newMqlAwsEc2ApplicationStatusCheck(testRuntime(), "us-east-1",
			ec2types.ApplicationStatusCheckResponseObject{
				ApplicationStatusCheckId: aws.String("asc-0fedcba9876543210"),
				DeletionTime:             &deletedAt,
			})
		require.NoError(t, err)

		check := res.(*mqlAwsEc2ApplicationStatusCheck)
		assert.True(t, check.Deleted.Data)
		assert.False(t, check.DeletedAt.IsNull())
		require.NotNil(t, check.DeletedAt.Data)
		assert.Equal(t, deletedAt, *check.DeletedAt.Data)
	})
}
