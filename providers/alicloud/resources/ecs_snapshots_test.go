// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEcsImageIsShared(t *testing.T) {
	tests := []struct {
		name             string
		accounts, groups []any
		expected         bool
	}{
		{"private image", []any{}, []any{}, false},
		{"shared with a named account", []any{"1234567890"}, []any{}, true},
		{"shared with a group", []any{}, []any{"ALL"}, true},
		{"both", []any{"1234567890"}, []any{"ALL"}, true},
		// permissions that could not be read look the same as none, which is
		// why isShared is documented as insufficient evidence of privacy
		{"nothing read", nil, nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, ecsImageIsShared(test.accounts, test.groups))
		})
	}
}

func TestEcsSnapshotTagsToMap(t *testing.T) {
	t.Run("absent tag block", func(t *testing.T) {
		// an empty map, never nil: a nil map would surface as a null tag set
		assert.Equal(t, map[string]any{}, ecsSnapshotTagsToMap(nil))
	})

	t.Run("flattens key-value pairs", func(t *testing.T) {
		tags := &ecsclient.DescribeSnapshotsResponseBodySnapshotsSnapshotTags{
			Tag: []*ecsclient.DescribeSnapshotsResponseBodySnapshotsSnapshotTagsTag{
				{TagKey: new("env"), TagValue: new("prod")},
				// a key with no value is still a tag that filters match on
				{TagKey: new("owner")},
				// entries with no key cannot be indexed and are dropped
				nil,
				{TagValue: new("orphan")},
			},
		}
		assert.Equal(t, map[string]any{"env": "prod", "owner": ""}, ecsSnapshotTagsToMap(tags))
	})
}

// TestEcsSnapshotDecode pins the SDK struct tags this change depends on. A
// mistyped tag would decode to a zero value, so an encrypted snapshot would
// report encrypted false and pass an encryption check it should fail.
func TestEcsSnapshotDecode(t *testing.T) {
	payload := `{
      "SnapshotId": "s-bp67acfmxazb4p",
      "SnapshotName": "nightly",
      "SourceDiskId": "d-bp67acfmxazb4p",
      "SourceDiskType": "system",
      "SourceDiskSize": "40",
      "Encrypted": true,
      "KMSKeyId": "0e478b7a-4262-4802-b8cb-00d3fb40",
      "Status": "accomplished",
      "Available": true,
      "RetentionDays": 30,
      "SnapshotType": "auto",
      "FullSnapshotSizeInBytes": 1073741824,
      "InstantAccess": false,
      "CreationTime": "2024-01-02T03:04Z"
    }`

	var snap ecsclient.DescribeSnapshotsResponseBodySnapshotsSnapshot
	require.NoError(t, json.Unmarshal([]byte(payload), &snap))

	assert.Equal(t, "s-bp67acfmxazb4p", tea.StringValue(snap.SnapshotId))
	assert.Equal(t, "d-bp67acfmxazb4p", tea.StringValue(snap.SourceDiskId))
	assert.True(t, tea.BoolValue(snap.Encrypted))
	assert.Equal(t, "0e478b7a-4262-4802-b8cb-00d3fb40", tea.StringValue(snap.KMSKeyId))
	assert.Equal(t, "accomplished", tea.StringValue(snap.Status))
	assert.Equal(t, int32(30), tea.Int32Value(snap.RetentionDays))
	assert.Equal(t, int64(1073741824), tea.Int64Value(snap.FullSnapshotSizeInBytes))
	assert.False(t, tea.BoolValue(snap.InstantAccess))
	if assert.NotNil(t, parseEcsTime(snap.CreationTime)) {
		assert.Equal(t, "2024-01-02T03:04:00Z", parseEcsTime(snap.CreationTime).Format("2006-01-02T15:04:05Z"))
	}
}

// TestEcsSnapshotDecodeAbsentValues checks that an absent member reads as the
// safe value rather than as a claim.
func TestEcsSnapshotDecodeAbsentValues(t *testing.T) {
	var snap ecsclient.DescribeSnapshotsResponseBodySnapshotsSnapshot
	require.NoError(t, json.Unmarshal([]byte(`{"SnapshotId":"s-1"}`), &snap))

	// an absent Encrypted must read as unencrypted, never as encrypted
	assert.False(t, tea.BoolValue(snap.Encrypted))
	assert.Equal(t, "", tea.StringValue(snap.KMSKeyId))
	// an absent timestamp must stay null rather than becoming the zero time,
	// which a report would render as 1 January year 1
	assert.Nil(t, parseEcsTime(snap.CreationTime))
}
