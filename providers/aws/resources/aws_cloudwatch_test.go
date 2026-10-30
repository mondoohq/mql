// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestParseLogGroupArn(t *testing.T) {
	tests := []struct {
		name         string
		arn          string
		expectRegion string
		expectGroup  string
	}{
		{
			"standard log group",
			"arn:aws:logs:us-east-1:123456789012:log-group:/my/log/group:*",
			"us-east-1",
			"/my/log/group",
		},
		{
			"log group name with colons",
			"arn:aws:logs:eu-west-1:123456789012:log-group:my:group:with:colons:*",
			"eu-west-1",
			"my:group:with:colons",
		},
		{
			"simple name",
			"arn:aws:logs:ap-southeast-1:999999999999:log-group:simple:*",
			"ap-southeast-1",
			"simple",
		},
		{
			"govcloud partition",
			"arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/gov/logs:*",
			"us-gov-west-1",
			"/gov/logs",
		},
		{
			"china partition",
			"arn:aws-cn:logs:cn-north-1:123456789012:log-group:/cn/app:*",
			"cn-north-1",
			"/cn/app",
		},
		{
			"malformed ARN - too few parts",
			"arn:aws:logs",
			"",
			"",
		},
		{
			"empty string",
			"",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, groupName := parseLogGroupArn(tt.arn)
			assert.Equal(t, tt.expectRegion, region)
			assert.Equal(t, tt.expectGroup, groupName)
		})
	}
}

// TestBuildLogGroupResourceRetention pins how a log group reports its
// retention. CloudWatch signals "never expire" by returning no retention at
// all, so defaulting that to 0 put the strongest retention at the bottom of
// any numeric comparison: `retentionInDays >= 365` excluded exactly the groups
// that keep their logs forever.
func TestBuildLogGroupResourceRetention(t *testing.T) {
	t.Run("a group with a retention reports it", func(t *testing.T) {
		lg, err := buildLogGroupResource(testRuntime(), "us-east-1", cloudwatchlogstypes.LogGroup{
			Arn:             aws.String("arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/fn:*"),
			LogGroupName:    aws.String("/aws/lambda/fn"),
			RetentionInDays: aws.Int32(365),
		})
		require.NoError(t, err)

		assert.False(t, lg.RetentionInDays.IsNull())
		assert.Equal(t, int64(365), lg.RetentionInDays.Data)
		assert.False(t, lg.NeverExpires.Data)
	})

	t.Run("a group that never expires reports null, not zero", func(t *testing.T) {
		lg, err := buildLogGroupResource(testRuntime(), "us-east-1", cloudwatchlogstypes.LogGroup{
			Arn:          aws.String("arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/forever:*"),
			LogGroupName: aws.String("/aws/lambda/forever"),
		})
		require.NoError(t, err)

		assert.True(t, lg.RetentionInDays.IsNull(),
			"no retention means no expiry, which is not a retention of zero days")
		assert.True(t, lg.NeverExpires.Data)
	})
}

// dim builds a resolved metric dimension for the cache-key tests.
func dim(name, value string) *mqlAwsCloudwatchMetricdimension {
	d := &mqlAwsCloudwatchMetricdimension{}
	d.Name = plugin.TValue[string]{Data: name, State: plugin.StateIsSet}
	d.Value = plugin.TValue[string]{Data: value, State: plugin.StateIsSet}
	return d
}

// TestMetricStatisticsCacheKey pins the identity of a statistics series. A
// CloudWatch metric is identified by namespace, name AND dimensions: AWS/EC2
// CPUUtilization exists once per instance and is distinguished only by the
// InstanceId dimension, so a key without dimensions collapses every instance's
// series onto one cache entry and the first one fetched answers for all of them.
func TestMetricStatisticsCacheKey(t *testing.T) {
	const (
		ns     = "AWS/EC2"
		metric = "CPUUtilization"
		region = "us-east-1"
		label  = "CPUUtilization"
	)

	t.Run("two instances do not share a key", func(t *testing.T) {
		first := metricStatisticsCacheKey(ns, metric, region, label,
			[]any{dim("InstanceId", "i-aaaaaaaaaaaaaaaaa")})
		second := metricStatisticsCacheKey(ns, metric, region, label,
			[]any{dim("InstanceId", "i-bbbbbbbbbbbbbbbbb")})
		assert.NotEqual(t, first, second)
	})

	t.Run("dimension order does not change the key", func(t *testing.T) {
		forward := metricStatisticsCacheKey(ns, metric, region, label,
			[]any{dim("InstanceId", "i-aaaaaaaaaaaaaaaaa"), dim("AutoScalingGroupName", "asg-1")})
		reverse := metricStatisticsCacheKey(ns, metric, region, label,
			[]any{dim("AutoScalingGroupName", "asg-1"), dim("InstanceId", "i-aaaaaaaaaaaaaaaaa")})
		assert.Equal(t, forward, reverse,
			"the same series must key the same whatever order the API returned its dimensions in")
	})

	t.Run("the undimensioned aggregate keeps the plain key", func(t *testing.T) {
		assert.Equal(t, "AWS/EC2/CPUUtilization/us-east-1/CPUUtilization",
			metricStatisticsCacheKey(ns, metric, region, label, nil))
	})

	t.Run("a dimensioned series differs from the aggregate", func(t *testing.T) {
		aggregate := metricStatisticsCacheKey(ns, metric, region, label, nil)
		scoped := metricStatisticsCacheKey(ns, metric, region, label,
			[]any{dim("InstanceId", "i-aaaaaaaaaaaaaaaaa")})
		assert.NotEqual(t, aggregate, scoped)
	})

	t.Run("region and namespace still separate series", func(t *testing.T) {
		east := metricStatisticsCacheKey(ns, metric, "us-east-1", label, nil)
		west := metricStatisticsCacheKey(ns, metric, "us-west-2", label, nil)
		assert.NotEqual(t, east, west)
	})

	t.Run("a non-dimension element is skipped, not panicked on", func(t *testing.T) {
		assert.NotPanics(t, func() {
			metricStatisticsCacheKey(ns, metric, region, label, []any{"not a dimension", nil})
		})
	})
}

// TestDatapointCacheKey pins that a datapoint is identified within its series.
// formatDatapointId hashes only the datapoint's own values, so two instances
// idling at the same value in the same hour hash identically.
func TestDatapointCacheKey(t *testing.T) {
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	later := at.Add(time.Hour)

	idle := cloudwatchtypes.Datapoint{Timestamp: &at, Average: aws.Float64(0)}

	t.Run("same datapoint values in different series do not collide", func(t *testing.T) {
		first := datapointCacheKey("AWS/EC2/CPUUtilization/us-east-1/l/InstanceId=i-a", idle)
		second := datapointCacheKey("AWS/EC2/CPUUtilization/us-east-1/l/InstanceId=i-b", idle)
		assert.NotEqual(t, first, second)
	})

	t.Run("consecutive datapoints in one series do not collide", func(t *testing.T) {
		series := "AWS/EC2/CPUUtilization/us-east-1/l"
		first := datapointCacheKey(series, idle)
		second := datapointCacheKey(series, cloudwatchtypes.Datapoint{Timestamp: &later, Average: aws.Float64(0)})
		assert.NotEqual(t, first, second)
	})

	t.Run("a datapoint with no timestamp does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			datapointCacheKey("series", cloudwatchtypes.Datapoint{Average: aws.Float64(1)})
		})
	})
}
