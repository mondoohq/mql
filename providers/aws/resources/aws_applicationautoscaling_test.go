// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	aatypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/stretchr/testify/assert"
)

// TestScalableTargetArn pins the identity of a scalable target. A target is
// keyed by its resource AND its dimension: a DynamoDB table with both read and
// write autoscaling has two targets sharing one resourceId, and an ARN built
// without the dimension collapsed them onto one cache row.
func TestScalableTargetArn(t *testing.T) {
	const (
		region  = "us-east-1"
		account = "000000000000"
	)

	target := func(resourceID string, dimension aatypes.ScalableDimension) aatypes.ScalableTarget {
		return aatypes.ScalableTarget{
			ServiceNamespace:  aatypes.ServiceNamespaceDynamodb,
			ResourceId:        aws.String(resourceID),
			ScalableDimension: dimension,
		}
	}

	t.Run("the reported arn is preferred", func(t *testing.T) {
		reported := "arn:aws:application-autoscaling:us-east-1:000000000000:scalable-target/0123456789abcdef"
		tgt := target("table/my-table", aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits)
		tgt.ScalableTargetARN = aws.String(reported)

		assert.Equal(t, reported, scalableTargetArn(tgt, region, account))
	})

	t.Run("read and write targets on one table do not collide", func(t *testing.T) {
		read := scalableTargetArn(
			target("table/my-table", aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits), region, account)
		write := scalableTargetArn(
			target("table/my-table", aatypes.ScalableDimensionDynamoDBTableWriteCapacityUnits), region, account)

		assert.NotEqual(t, read, write,
			"one table's read and write autoscaling are two targets, not one")
	})

	t.Run("different resources do not collide", func(t *testing.T) {
		first := scalableTargetArn(
			target("table/my-table", aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits), region, account)
		second := scalableTargetArn(
			target("table/other-table", aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits), region, account)

		assert.NotEqual(t, first, second)
	})

	t.Run("regions do not collide", func(t *testing.T) {
		tgt := target("table/my-table", aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits)
		assert.NotEqual(t,
			scalableTargetArn(tgt, "us-east-1", account),
			scalableTargetArn(tgt, "us-west-2", account))
	})

	t.Run("an empty reported arn falls back rather than emptying the key", func(t *testing.T) {
		tgt := target("table/my-table", aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits)
		tgt.ScalableTargetARN = aws.String("")

		assert.NotEmpty(t, scalableTargetArn(tgt, region, account))
	})
}
