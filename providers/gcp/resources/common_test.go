// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestBoolValueToPtr(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := boolValueToPtr(nil)
		assert.Nil(t, result)
	})

	t.Run("true value", func(t *testing.T) {
		result := boolValueToPtr(wrapperspb.Bool(true))
		require.NotNil(t, result)
		assert.True(t, *result)
	})

	t.Run("false value", func(t *testing.T) {
		result := boolValueToPtr(wrapperspb.Bool(false))
		require.NotNil(t, result)
		assert.False(t, *result)
	})
}

func TestRegionNameFromRegionUrl(t *testing.T) {
	assert.Equal(t, "us-central1", RegionNameFromRegionUrl("https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1"))
	assert.Equal(t, "europe-west1", RegionNameFromRegionUrl("europe-west1"))
	assert.Equal(t, "", RegionNameFromRegionUrl(""))
}

func TestParseSubnetworkURL(t *testing.T) {
	t.Run("www.googleapis.com host", func(t *testing.T) {
		project, region, name, ok := parseSubnetworkURL("https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/subnetworks/subnet-1")
		require.True(t, ok)
		assert.Equal(t, "my-project", project)
		assert.Equal(t, "us-central1", region)
		assert.Equal(t, "subnet-1", name)
	})
	t.Run("compute.googleapis.com host", func(t *testing.T) {
		project, region, name, ok := parseSubnetworkURL("https://compute.googleapis.com/compute/v1/projects/my-project/regions/europe-west1/subnetworks/subnet-2")
		require.True(t, ok)
		assert.Equal(t, "my-project", project)
		assert.Equal(t, "europe-west1", region)
		assert.Equal(t, "subnet-2", name)
	})
	t.Run("empty url", func(t *testing.T) {
		_, _, _, ok := parseSubnetworkURL("")
		assert.False(t, ok)
	})
	t.Run("malformed / too short does not panic", func(t *testing.T) {
		_, _, _, ok := parseSubnetworkURL("https://www.googleapis.com/compute/v1/projects/my-project")
		assert.False(t, ok)
	})
	t.Run("wrong resource kind", func(t *testing.T) {
		_, _, _, ok := parseSubnetworkURL("https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/disks/disk-1")
		assert.False(t, ok)
	})
}

func TestGetDiskIdByUrl(t *testing.T) {
	okCases := []struct {
		url                   string
		project, region, name string
	}{
		{
			"https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/disks/disk-1",
			"p1", "us-central1-a", "disk-1",
		},
		{
			"https://compute.googleapis.com/compute/v1/projects/p2/regions/us-east1/disks/rdisk",
			"p2", "us-east1", "rdisk",
		},
	}
	for _, c := range okCases {
		id, err := getDiskIdByUrl(c.url)
		require.NoError(t, err)
		assert.Equal(t, c.project, id.Project)
		assert.Equal(t, c.region, id.Region)
		assert.Equal(t, c.name, id.Name)
	}

	// Malformed URLs must return an error, not panic on an out-of-range index.
	for _, u := range []string{"", "not-a-url", "https://www.googleapis.com/compute/v1/projects/p1"} {
		_, err := getDiskIdByUrl(u)
		assert.Error(t, err, "getDiskIdByUrl(%q) should error", u)
	}
}

func TestProjectFromResourceName(t *testing.T) {
	cases := map[string]string{
		"projects/my-proj/topics/t1":              "my-proj",
		"projects/p2/locations/us/backupVaults/v": "p2",
		"projects/only-project":                   "only-project",
		"organizations/123/folders/456":           "",
		"no-projects-segment/here":                "",
		"":                                        "",
	}
	for in, want := range cases {
		assert.Equal(t, want, projectFromResourceName(in), "projectFromResourceName(%q)", in)
	}
}
