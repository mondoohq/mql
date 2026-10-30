// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpinstancesnapshot

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDiskUrl(t *testing.T) {
	diskUrl := "https://www.googleapis.com/compute/beta/projects/my-project-1234/zones/us-central1-a/disks/super-dupa-disk"
	projectID, zone, disk, err := parseDiskUrl(diskUrl)
	require.NoError(t, err)
	assert.Equal(t, "my-project-1234", projectID)
	assert.Equal(t, "us-central1-a", zone)
	assert.Equal(t, "super-dupa-disk", disk)
}

func TestParseDiskUrlMalformed(t *testing.T) {
	// url.Parse accepts nearly anything, so these reach the path-component
	// indexing. They must return an error rather than panic.
	for _, diskUrl := range []string{
		"",
		"not-a-disk-url",
		"https://www.googleapis.com/compute/v1/projects/my-project-1234",
		"projects/my-project-1234/zones/us-central1-a/disks/super-dupa-disk",
	} {
		t.Run(diskUrl, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, _, _, err := parseDiskUrl(diskUrl)
				assert.Error(t, err)
			})
		})
	}
}

func TestIsCrossZoneClone(t *testing.T) {
	const diskUrl = "https://www.googleapis.com/compute/v1/projects/my-project-1234/zones/us-central1-a/disks/super-dupa-disk"

	tests := []struct {
		name       string
		sourceDisk string
		targetZone string
		expected   bool
	}{
		{
			name:       "different zone bridges through a snapshot",
			sourceDisk: diskUrl,
			targetZone: "us-west1-a",
			expected:   true,
		},
		{
			name:       "same zone clones directly",
			sourceDisk: diskUrl,
			targetZone: "us-central1-a",
			expected:   false,
		},
		{
			name:       "same region but a different zone still bridges",
			sourceDisk: diskUrl,
			targetZone: "us-central1-b",
			expected:   true,
		},
		{
			// an unparseable url must fall back to the direct clone rather than
			// bridging on a zone we never actually determined
			name:       "unparseable source disk does not bridge",
			sourceDisk: "not-a-disk-url",
			targetZone: "us-west1-a",
			expected:   false,
		},
		{
			name:       "empty source disk does not bridge",
			sourceDisk: "",
			targetZone: "us-west1-a",
			expected:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, isCrossZoneClone(test.sourceDisk, test.targetZone))
		})
	}
}
