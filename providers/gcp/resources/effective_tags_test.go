// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestComputeSelfLinkToResourceName(t *testing.T) {
	tests := []struct {
		name     string
		selfLink string
		want     string
	}{
		{
			name:     "zonal instance",
			selfLink: "https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/instances/vm1",
			want:     "//compute.googleapis.com/projects/p1/zones/us-central1-a/instances/vm1",
		},
		{
			name:     "regional disk",
			selfLink: "https://www.googleapis.com/compute/v1/projects/p1/regions/us-central1/disks/d1",
			want:     "//compute.googleapis.com/projects/p1/regions/us-central1/disks/d1",
		},
		{
			name:     "global network",
			selfLink: "https://www.googleapis.com/compute/v1/projects/p1/global/networks/default",
			want:     "//compute.googleapis.com/projects/p1/global/networks/default",
		},
		{
			name:     "global firewall",
			selfLink: "https://www.googleapis.com/compute/v1/projects/p1/global/firewalls/allow-ssh",
			want:     "//compute.googleapis.com/projects/p1/global/firewalls/allow-ssh",
		},
		{
			name:     "compute.googleapis.com host form",
			selfLink: "https://compute.googleapis.com/compute/v1/projects/p1/zones/z1/instances/vm1",
			want:     "//compute.googleapis.com/projects/p1/zones/z1/instances/vm1",
		},
		{
			name:     "beta api version",
			selfLink: "https://www.googleapis.com/compute/beta/projects/p1/zones/z1/instances/vm1",
			want:     "//compute.googleapis.com/projects/p1/zones/z1/instances/vm1",
		},
		{
			// A resource created before the field was cached reports no selfLink.
			// It must resolve to "" so the caller reports no tags rather than
			// querying a malformed resource name.
			name:     "empty selfLink",
			selfLink: "",
			want:     "",
		},
		{
			name:     "prefix present but no path",
			selfLink: "https://www.googleapis.com/compute/v1/",
			want:     "",
		},
		{
			name:     "unrecognized host",
			selfLink: "https://example.com/compute/v1/projects/p1/zones/z1/instances/vm1",
			want:     "",
		},
		{
			// A non-compute self link must not be rewritten as a compute one.
			name:     "different service url",
			selfLink: "https://storage.googleapis.com/storage/v1/b/bucket1",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, computeSelfLinkToResourceName(tt.selfLink))
		})
	}
}

// The cache key must stay distinct per resource. An inherited tag value applies
// to every resource under its parent, so keying on the tag value alone would
// make the first resource's tag list stand in for all of them.
func TestEffectiveTagCacheKeyIsPerResource(t *testing.T) {
	vm1 := "//compute.googleapis.com/projects/p1/zones/z1/instances/vm1"
	vm2 := "//compute.googleapis.com/projects/p1/zones/z1/instances/vm2"
	sharedValue := "tagValues/456"

	k1 := effectiveTagCacheKey(vm1, sharedValue)
	k2 := effectiveTagCacheKey(vm2, sharedValue)

	assert.NotEqual(t, k1, k2, "same tag value on two resources must not share a cache key")
	assert.Equal(t, vm1+"/"+sharedValue, k1)
}

func TestEffectiveTagCacheKeyDistinguishesValues(t *testing.T) {
	vm := "//compute.googleapis.com/projects/p1/zones/z1/instances/vm1"

	assert.NotEqual(t,
		effectiveTagCacheKey(vm, "tagValues/1"),
		effectiveTagCacheKey(vm, "tagValues/2"),
		"two tag values on one resource must not share a cache key")
}

func TestStringFields(t *testing.T) {
	set := func(s string) plugin.TValue[string] {
		return plugin.TValue[string]{Data: s, State: plugin.StateIsSet}
	}

	t.Run("all present", func(t *testing.T) {
		p := set("project1")
		n := set("instance1")
		got, ok, err := stringFields(&p, &n)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, []string{"project1", "instance1"}, got)
	})

	t.Run("empty field reports not ok", func(t *testing.T) {
		p := set("project1")
		n := set("")
		got, ok, err := stringFields(&p, &n)
		require.NoError(t, err)
		assert.False(t, ok, "an empty segment must not build a resource name")
		assert.Nil(t, got)
	})

	t.Run("field error propagates", func(t *testing.T) {
		p := set("project1")
		n := plugin.TValue[string]{Error: assert.AnError, State: plugin.StateIsSet}
		_, ok, err := stringFields(&p, &n)
		assert.Error(t, err)
		assert.False(t, ok)
	})

	t.Run("error wins over later empty field", func(t *testing.T) {
		p := plugin.TValue[string]{Error: assert.AnError, State: plugin.StateIsSet}
		n := set("")
		_, _, err := stringFields(&p, &n)
		assert.Error(t, err, "a read failure must not be reported as a missing value")
	})
}
