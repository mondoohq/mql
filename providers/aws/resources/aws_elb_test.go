// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTargetGroupBackendTypeShortCircuit verifies that lambdaTargets and
// ipTargets return an empty list (without calling DescribeTargetHealth) for
// target groups whose target type doesn't match, so an instance-type target
// group reports no Lambda or IP backends.
func TestTargetGroupBackendTypeShortCircuit(t *testing.T) {
	t.Run("lambdaTargets empty for instance-type target group", func(t *testing.T) {
		tg := &mqlAwsElbTargetgroup{}
		tg.targetGroup = elbtypes.TargetGroup{TargetType: elbtypes.TargetTypeEnumInstance}
		result, err := tg.lambdaTargets()
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("ipTargets empty for instance-type target group", func(t *testing.T) {
		tg := &mqlAwsElbTargetgroup{}
		tg.targetGroup = elbtypes.TargetGroup{TargetType: elbtypes.TargetTypeEnumInstance}
		result, err := tg.ipTargets()
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("ipTargets empty for lambda-type target group", func(t *testing.T) {
		tg := &mqlAwsElbTargetgroup{}
		tg.targetGroup = elbtypes.TargetGroup{TargetType: elbtypes.TargetTypeEnumLambda}
		result, err := tg.ipTargets()
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// TestListenerForwardTargetGroupsNoForwardAction verifies that a listener whose
// default action does not forward (no target group ARNs) resolves to an empty
// list without touching the parent load balancer.
func TestListenerForwardTargetGroupsNoForwardAction(t *testing.T) {
	listener := &mqlAwsElbListener{}
	// defaultActionsCache is nil (e.g. a redirect or fixed-response default action)
	result, err := listener.forwardTargetGroups()
	require.NoError(t, err)
	assert.Empty(t, result)
}

// TestIsV1LoadBalancerArn guards the classic-vs-v2 dispatch. A substring match
// on "classic" also caught ALB/NLB ARNs whose *name* contains it, sending them
// to the v1 API: listeners() then returned an empty list and enforcesTls()
// passed vacuously on an unencrypted ALB.
func TestIsV1LoadBalancerArn(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want bool
	}{
		{"classic", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/classic/my-elb", true},
		{"alb named classic-migration", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/classic-migration-alb/50dc", false},
		{"alb named prod-classic-api", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/prod-classic-api/abc", false},
		{"nlb", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/my-nlb/abc", false},
		{"gwlb", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/gwy/my-gwlb/abc", false},
		{"not an arn", "my-elb", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isV1LoadBalancerArn(tt.arn))
		})
	}
}

// TestCrossZoneEnabledFromV2Attrs verifies that the cross-zone attribute is
// read by exact key and only the literal "true" counts as enabled. The
// attribute is absent on load balancer types that do not carry the setting,
// which must read as disabled rather than as an error.
func TestCrossZoneEnabledFromV2Attrs(t *testing.T) {
	key := "load_balancing.cross_zone.enabled"
	other := "deletion_protection.enabled"

	t.Run("enabled", func(t *testing.T) {
		assert.True(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{
			{Key: &key, Value: aws.String("true")},
		}))
	})

	t.Run("disabled", func(t *testing.T) {
		assert.False(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{
			{Key: &key, Value: aws.String("false")},
		}))
	})

	t.Run("attribute absent reads as disabled", func(t *testing.T) {
		assert.False(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{
			{Key: &other, Value: aws.String("true")},
		}))
	})

	t.Run("does not match on a different key carrying true", func(t *testing.T) {
		prefixed := "routing." + key
		assert.False(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{
			{Key: &prefixed, Value: aws.String("true")},
		}))
	})

	t.Run("nil value reads as disabled", func(t *testing.T) {
		assert.False(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{
			{Key: &key, Value: nil},
		}))
	})

	t.Run("nil key is skipped, later match still wins", func(t *testing.T) {
		assert.True(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{
			{Key: nil, Value: aws.String("false")},
			{Key: &key, Value: aws.String("true")},
		}))
	})

	t.Run("empty and nil attribute lists read as disabled", func(t *testing.T) {
		assert.False(t, crossZoneEnabledFromV2Attrs([]elbtypes.LoadBalancerAttribute{}))
		assert.False(t, crossZoneEnabledFromV2Attrs(nil))
	})
}
