// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
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

func TestImageFindingsArgs(t *testing.T) {
	const imageKey = "us-east-1/ami-0123456789abcdef0"
	observed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)

	// Synthetic: every field of a fully populated finding lands on its own key.
	t.Run("maps every field", func(t *testing.T) {
		args := imageFindingsArgs(imageKey, []ec2types.ImageFinding{{
			Title:           aws.String("CVE-2026-0001 - openssl"),
			SeverityLabel:   ec2types.SeverityLabelCritical,
			Score:           aws.Float64(9.8),
			FixAvailable:    aws.Bool(true),
			Paths:           []string{"/usr/lib64/libssl.so.3"},
			SnapshotId:      aws.String("snap-0aaaaaaaaaaaaaaaa"),
			FirstObservedAt: &observed,
			UpdatedAt:       &updated,
		}})
		require.Len(t, args, 1)
		a := args[0]
		assert.Equal(t, "CVE-2026-0001 - openssl", a["title"].Value)
		assert.Equal(t, "critical", a["severity"].Value)
		assert.Equal(t, 9.8, a["score"].Value)
		assert.Equal(t, true, a["fixAvailable"].Value)
		assert.Equal(t, []any{"/usr/lib64/libssl.so.3"}, a["paths"].Value)
		assert.Equal(t, "snap-0aaaaaaaaaaaaaaaa", a["snapshotId"].Value)
		assert.Equal(t, &observed, a["firstObservedAt"].Value)
		assert.Equal(t, &updated, a["updatedAt"].Value)
		assert.Equal(t,
			imageKey+"/inspectorFinding/snap-0aaaaaaaaaaaaaaaa|CVE-2026-0001 - openssl|/usr/lib64/libssl.so.3",
			a["__id"].Value)
	})

	// Synthetic: absent values stay null instead of a zero score, a false fix
	// flag or year-1 dates.
	t.Run("absent values are null, not zero", func(t *testing.T) {
		args := imageFindingsArgs(imageKey, []ec2types.ImageFinding{{Title: aws.String("t")}})
		require.Len(t, args, 1)
		a := args[0]
		for _, k := range []string{"severity", "score", "fixAvailable", "snapshotId", "firstObservedAt", "updatedAt"} {
			assert.Nil(t, a[k].Value, k)
		}
		assert.Equal(t, []any{}, a["paths"].Value)
	})

	// Synthetic: the same title in two snapshots, or on different paths, is two findings.
	t.Run("ids distinguish snapshot and paths", func(t *testing.T) {
		args := imageFindingsArgs(imageKey, []ec2types.ImageFinding{
			{Title: aws.String("CVE-2026-0002 - zlib"), SnapshotId: aws.String("snap-1"), Paths: []string{"/a"}},
			{Title: aws.String("CVE-2026-0002 - zlib"), SnapshotId: aws.String("snap-2"), Paths: []string{"/a"}},
			{Title: aws.String("CVE-2026-0002 - zlib"), SnapshotId: aws.String("snap-1"), Paths: []string{"/b"}},
		})
		ids := map[any]bool{}
		for _, a := range args {
			ids[a["__id"].Value] = true
		}
		assert.Len(t, ids, 3)
	})

	// Synthetic: path order from the API does not change the id.
	t.Run("id ignores path order", func(t *testing.T) {
		a := imageFindingId(imageKey, ec2types.ImageFinding{Title: aws.String("x"), Paths: []string{"/b", "/a"}})
		b := imageFindingId(imageKey, ec2types.ImageFinding{Title: aws.String("x"), Paths: []string{"/a", "/b"}})
		assert.Equal(t, a, b)
	})

	// Synthetic: two images reporting the same finding keep separate ids.
	t.Run("id carries the image", func(t *testing.T) {
		f := ec2types.ImageFinding{Title: aws.String("x"), SnapshotId: aws.String("snap-1")}
		assert.NotEqual(t,
			imageFindingId("us-east-1/ami-1", f),
			imageFindingId("us-west-2/ami-1", f))
	})

	// Synthetic: an exact repeat is kept as its own finding, not collapsed by the cache.
	t.Run("exact repeats get distinct ids", func(t *testing.T) {
		f := ec2types.ImageFinding{Title: aws.String("x"), SnapshotId: aws.String("snap-1")}
		args := imageFindingsArgs(imageKey, []ec2types.ImageFinding{f, f})
		require.Len(t, args, 2)
		assert.NotEqual(t, args[0]["__id"].Value, args[1]["__id"].Value)
	})
}

func TestIsSnapshotNotVisible(t *testing.T) {
	// Measured: aws ec2 describe-snapshots on an unknown id, us-east-1,
	// 2026-10-30, answers InvalidSnapshot.NotFound.
	assert.True(t, isSnapshotNotVisible(&smithy.GenericAPIError{Code: "InvalidSnapshot.NotFound"}))
	// Synthetic: a denial is not an absence.
	assert.False(t, isSnapshotNotVisible(&smithy.GenericAPIError{Code: "UnauthorizedOperation"}))
	// Synthetic: a transport error is not an absence.
	assert.False(t, isSnapshotNotVisible(errors.New("dial tcp: i/o timeout")))
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
