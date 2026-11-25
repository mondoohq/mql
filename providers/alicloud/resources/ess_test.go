// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	essclient "github.com/alibabacloud-go/ess-20220222/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/types"
)

// Synthetic: a group without a warm pool; no target showed this. The API may
// still report WarmPoolCapacity as 0, which must not read as a pool holding
// zero instances.
func TestEssWarmPoolArgsAbsentIsNull(t *testing.T) {
	args := essWarmPoolArgs(&essclient.DescribeScalingGroupsResponseBodyScalingGroups{
		WarmPoolCapacity: tea.Int32(0),
	})
	for _, k := range []string{
		"warmPoolCapacity", "warmPoolStatus", "warmPoolInstanceState",
		"warmPoolMinCapacity", "warmPoolPreparedCapacity", "warmPoolReuseOnScaleIn",
	} {
		assert.Equal(t, types.Nil, args[k].Type, k)
	}
}

// Synthetic: values taken from the SDK's documented examples; no target showed this.
func TestEssWarmPoolArgsMapsConfiguration(t *testing.T) {
	args := essWarmPoolArgs(&essclient.DescribeScalingGroupsResponseBodyScalingGroups{
		WarmPoolCapacity: tea.Int32(5),
		WarmPoolConfiguration: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsWarmPoolConfiguration{
			Status:    tea.String("Active"),
			PoolState: tea.String("Stopped"),
			CapacityOptions: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsWarmPoolConfigurationCapacityOptions{
				MinCapacity:                  tea.Int32(2),
				DesiredGroupPreparedCapacity: tea.Int32(8),
			},
			InstanceReusePolicy: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsWarmPoolConfigurationInstanceReusePolicy{
				ReuseOnScaleIn: tea.Bool(true),
			},
		},
	})
	assert.Equal(t, int64(5), args["warmPoolCapacity"].Value)
	assert.Equal(t, "Active", args["warmPoolStatus"].Value)
	assert.Equal(t, "Stopped", args["warmPoolInstanceState"].Value)
	assert.Equal(t, int64(2), args["warmPoolMinCapacity"].Value)
	assert.Equal(t, int64(8), args["warmPoolPreparedCapacity"].Value)
	assert.Equal(t, true, args["warmPoolReuseOnScaleIn"].Value)
}

// Synthetic: a warm pool reported without its capacity or reuse blocks; no
// target showed this. The unreported settings stay null.
func TestEssWarmPoolArgsPartialConfiguration(t *testing.T) {
	args := essWarmPoolArgs(&essclient.DescribeScalingGroupsResponseBodyScalingGroups{
		WarmPoolCapacity: tea.Int32(0),
		WarmPoolConfiguration: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsWarmPoolConfiguration{
			Status: tea.String("Deleting"),
		},
	})
	assert.Equal(t, int64(0), args["warmPoolCapacity"].Value)
	assert.Equal(t, "Deleting", args["warmPoolStatus"].Value)
	assert.Equal(t, types.Nil, args["warmPoolMinCapacity"].Type)
	assert.Equal(t, types.Nil, args["warmPoolPreparedCapacity"].Type)
	assert.Equal(t, types.Nil, args["warmPoolReuseOnScaleIn"].Type)
}

// Synthetic: a group without zone shift options; no target showed this.
func TestEssZoneShiftArgsAbsentIsNull(t *testing.T) {
	args := essZoneShiftArgs(&essclient.DescribeScalingGroupsResponseBodyScalingGroups{})
	for _, k := range []string{
		"zoneShiftImpairedZoneIds", "zoneShiftExpiresAt", "zoneShiftImpairedZoneHealthCheck",
		"zoneShiftScaleInBlockedRuleTypes", "zoneShiftScaleOutHealthyZonesOnly",
	} {
		assert.Equal(t, types.Nil, args[k].Type, k)
	}
}

// Synthetic: values taken from the SDK's documented examples, including its
// minute-precision expiry format; no target showed this.
func TestEssZoneShiftArgsMapsOptions(t *testing.T) {
	args := essZoneShiftArgs(&essclient.DescribeScalingGroupsResponseBodyScalingGroups{
		ZoneShiftOptions: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsZoneShiftOptions{
			ExpiryTime:      tea.String("2026-01-01T12:05Z"),
			ImpairedZoneIds: []*string{tea.String("cn-hangzhou-g"), nil},
			ZoneShiftPolicy: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsZoneShiftOptionsZoneShiftPolicy{
				ImpairedZoneHealthCheckBehavior: tea.String("IgnoreUnhealthy"),
				ScaleInBlockedRuleTypes:         []*string{tea.String("StepScalingRule")},
				ScaleOutInHealthyZonesOnly:      tea.Bool(true),
			},
		},
	})
	assert.Equal(t, []any{"cn-hangzhou-g"}, args["zoneShiftImpairedZoneIds"].Value)
	expires := args["zoneShiftExpiresAt"].Value.(*time.Time)
	assert.Equal(t, time.Date(2026, 1, 1, 12, 5, 0, 0, time.UTC), *expires)
	assert.Equal(t, "IgnoreUnhealthy", args["zoneShiftImpairedZoneHealthCheck"].Value)
	assert.Equal(t, []any{"StepScalingRule"}, args["zoneShiftScaleInBlockedRuleTypes"].Value)
	assert.Equal(t, true, args["zoneShiftScaleOutHealthyZonesOnly"].Value)
}

// Synthetic: zone shift options without a policy block; no target showed this.
func TestEssZoneShiftArgsWithoutPolicy(t *testing.T) {
	args := essZoneShiftArgs(&essclient.DescribeScalingGroupsResponseBodyScalingGroups{
		ZoneShiftOptions: &essclient.DescribeScalingGroupsResponseBodyScalingGroupsZoneShiftOptions{},
	})
	assert.Equal(t, []any{}, args["zoneShiftImpairedZoneIds"].Value)
	assert.Equal(t, types.Nil, args["zoneShiftExpiresAt"].Type)
	assert.Equal(t, types.Nil, args["zoneShiftImpairedZoneHealthCheck"].Type)
	assert.Equal(t, types.Nil, args["zoneShiftScaleInBlockedRuleTypes"].Type)
	assert.Equal(t, types.Nil, args["zoneShiftScaleOutHealthyZonesOnly"].Type)
}
