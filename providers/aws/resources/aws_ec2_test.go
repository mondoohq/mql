// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/aws/connection"
)

func TestShouldExcludeInstance(t *testing.T) {
	instance := ec2types.Instance{
		InstanceId: aws.String("iid"),
		Tags: []ec2types.Tag{
			{
				Key:   aws.String("key-1"),
				Value: aws.String("val-1"),
			},
			{
				Key:   aws.String("key-2"),
				Value: aws.String("val-2"),
			},
		},
	}

	t.Run("should exclude instance by id", func(t *testing.T) {
		filters := connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{
				ExcludeTags: map[string]string{
					"key-3": "val3",
				},
			},
			Ec2: connection.Ec2DiscoveryFilters{
				ExcludeInstanceIds: []string{
					"iid",
				},
			},
		}
		require.True(t, shouldExcludeInstance(instance, filters))
	})

	t.Run("should exclude instance by matching tag", func(t *testing.T) {
		filters := connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{
				ExcludeTags: map[string]string{
					"key-2": "val2",
				},
			},
			Ec2: connection.Ec2DiscoveryFilters{
				ExcludeInstanceIds: []string{
					"iid-2",
				},
			},
		}
		require.False(t, shouldExcludeInstance(instance, filters))
	})

	t.Run("should not exclude instance with only a matching tag key", func(t *testing.T) {
		filters := connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{
				ExcludeTags: map[string]string{
					"key-2": "val3",
					"key-3": "val3",
				},
			},
			Ec2: connection.Ec2DiscoveryFilters{
				ExcludeInstanceIds: []string{
					"iid-2",
				},
			},
		}
		require.False(t, shouldExcludeInstance(instance, filters))
	})

	t.Run("should not exclude instance when instance id and tags don't match", func(t *testing.T) {
		filters := connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{
				ExcludeTags: map[string]string{
					"key-3": "val3",
				},
			},
			Ec2: connection.Ec2DiscoveryFilters{
				ExcludeInstanceIds: []string{
					"iid-2",
				},
			},
		}
		require.False(t, shouldExcludeInstance(instance, filters))
	})

	t.Run("should exclude instances with matching values for the same tag", func(t *testing.T) {
		filters := connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{
				ExcludeTags: map[string]string{
					"key-1": "val-1,val-2,val-3",
				},
			},
			Ec2: connection.Ec2DiscoveryFilters{
				ExcludeInstanceIds: []string{},
			},
		}
		require.True(t, shouldExcludeInstance(instance, filters))
	})

	t.Run("should not exclude instances when no tag values match", func(t *testing.T) {
		filters := connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{
				ExcludeTags: map[string]string{
					"key-1": "val-2,val-3",
					"key-2": "val-1,val-3",
					"key-3": "val-1,val-2",
				},
			},
			Ec2: connection.Ec2DiscoveryFilters{
				ExcludeInstanceIds: []string{},
			},
		}
		require.False(t, shouldExcludeInstance(instance, filters))
	})
}

func TestImdsSupport(t *testing.T) {
	t.Run("empty value returns none", func(t *testing.T) {
		assert.Equal(t, "none", imdsSupport(""))
	})

	t.Run("v2.0 value is preserved", func(t *testing.T) {
		assert.Equal(t, "v2.0", imdsSupport(ec2types.ImdsSupportValuesV20))
	})
}

func TestImageScanResultArgs(t *testing.T) {
	keys := []string{
		"inspectorScannedAt", "inspectorHighestSeverity",
		"inspectorCriticalFixAvailableSince", "inspectorHighFixAvailableSince",
		"inspectorMediumFixAvailableSince", "inspectorLowFixAvailableSince",
		"inspectorInformationalFixAvailableSince",
	}

	// Synthetic: an AMI Inspector never scanned carries no ScanResults.
	t.Run("not scanned is null, not zero", func(t *testing.T) {
		args := imageScanResultArgs(nil)
		require.Len(t, args, len(keys))
		for _, k := range keys {
			assert.Same(t, llx.NilData, args[k], k)
		}
	})

	// Synthetic: a scanned AMI without findings has a scan date and no label.
	t.Run("scanned without findings has a null severity", func(t *testing.T) {
		scanned := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
		args := imageScanResultArgs(&ec2types.ScanResults{FindingScanDate: &scanned})
		assert.Equal(t, &scanned, args["inspectorScannedAt"].Value)
		assert.Same(t, llx.NilData, args["inspectorHighestSeverity"])
		assert.Same(t, llx.NilData, args["inspectorCriticalFixAvailableSince"])
	})

	// Synthetic: each severity's date lands on its own field.
	t.Run("fix dates map to their severity", func(t *testing.T) {
		day := func(d int) *time.Time {
			v := time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC)
			return &v
		}
		args := imageScanResultArgs(&ec2types.ScanResults{
			FindingScanDate:                day(29),
			HighestFindingSeverityLabel:    ec2types.SeverityLabelCritical,
			CriticalFixAvailableSince:      day(1),
			HighFixAvailableSince:          day(2),
			MediumFixAvailableSince:        day(3),
			LowFixAvailableSince:           day(4),
			InformationalFixAvailableSince: day(5),
		})
		assert.Equal(t, "critical", args["inspectorHighestSeverity"].Value)
		assert.Equal(t, day(1), args["inspectorCriticalFixAvailableSince"].Value)
		assert.Equal(t, day(2), args["inspectorHighFixAvailableSince"].Value)
		assert.Equal(t, day(3), args["inspectorMediumFixAvailableSince"].Value)
		assert.Equal(t, day(4), args["inspectorLowFixAvailableSince"].Value)
		assert.Equal(t, day(5), args["inspectorInformationalFixAvailableSince"].Value)
	})
}

func TestDescribeLaunchTemplatesInputTagFilters(t *testing.T) {
	in := describeLaunchTemplatesInput(connection.GeneralDiscoveryFilters{
		Tags: map[string]string{"env": "prod,staging"},
	})
	require.Len(t, in.Filters, 1)
	assert.Equal(t, "tag:env", aws.ToString(in.Filters[0].Name))
	assert.Equal(t, []string{"prod", "staging"}, in.Filters[0].Values)

	in = describeLaunchTemplatesInput(connection.GeneralDiscoveryFilters{})
	assert.Empty(t, in.Filters)
}

func TestNetworkAclRegionAndId(t *testing.T) {
	region, id, ok := networkAclRegionAndId("arn:aws:ec2:us-east-1:123456789012:network-acl/acl-0abc")
	require.True(t, ok)
	assert.Equal(t, "us-east-1", region)
	assert.Equal(t, "acl-0abc", id)

	_, _, ok = networkAclRegionAndId("arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc")
	assert.False(t, ok)
	_, _, ok = networkAclRegionAndId("acl-0abc")
	assert.False(t, ok)
}
