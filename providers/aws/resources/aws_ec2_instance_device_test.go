// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every block device mapping used to share one cache key. id() returns
// cacheVolumeId, which is assigned only after CreateResource has already
// computed the key from it, so the key was "" for every device in the account.
// CreateResource is first-wins, so the first device seen anywhere was returned
// for every device everywhere.
func TestInstanceDeviceCacheKeySeparatesDevicesOnOneInstance(t *testing.T) {
	root := instanceDeviceCacheKey("us-east-1", "i-05ff4488b72b3a050", "/dev/xvda")
	extra := instanceDeviceCacheKey("us-east-1", "i-05ff4488b72b3a050", "/dev/sdf")

	require.NotEqual(t, root, extra,
		"two devices on one instance must have distinct cache keys")
	assert.Equal(t, "us-east-1/i-05ff4488b72b3a050//dev/xvda", root)
}

// Two instances that both have a /dev/xvda are the ordinary case, and they must
// not collapse into one another.
func TestInstanceDeviceCacheKeySeparatesInstances(t *testing.T) {
	first := instanceDeviceCacheKey("us-east-1", "i-05ff4488b72b3a050", "/dev/xvda")
	second := instanceDeviceCacheKey("us-east-1", "i-085611f4927f5091e", "/dev/xvda")

	assert.NotEqual(t, first, second,
		"the same device name on two instances must have distinct cache keys")
}

// The same instance id cannot appear in two regions, but the region is part of
// the key so a device can never be resolved against the wrong regional client.
func TestInstanceDeviceCacheKeyIncludesRegion(t *testing.T) {
	east := instanceDeviceCacheKey("us-east-1", "i-abc", "/dev/xvda")
	west := instanceDeviceCacheKey("us-west-2", "i-abc", "/dev/xvda")

	assert.NotEqual(t, east, west)
}

// A whole fleet's worth of devices must produce a whole fleet's worth of keys.
// Under the old scheme this set had exactly one member.
func TestInstanceDeviceCacheKeysAreUniquePerDevice(t *testing.T) {
	type dev struct{ region, instance, name string }
	devices := []dev{
		{"us-east-1", "i-05ff4488b72b3a050", "/dev/xvda"},
		{"us-east-1", "i-05ff4488b72b3a050", "/dev/sdf"},
		{"us-east-1", "i-085611f4927f5091e", "/dev/sda1"},
		{"us-east-1", "i-085611f4927f5091e", "/dev/sdb"},
		{"us-west-2", "i-0dd81acba6ed990d7", "/dev/xvda"},
	}

	keys := map[string]bool{}
	for _, d := range devices {
		k := instanceDeviceCacheKey(d.region, d.instance, d.name)
		require.False(t, keys[k], "duplicate cache key %q for %+v", k, d)
		keys[k] = true
	}
	assert.Len(t, keys, len(devices))
}

// An instance id or device name AWS did not return must not silently merge two
// devices; the key still varies by whatever is known.
func TestInstanceDeviceCacheKeyWithMissingParts(t *testing.T) {
	assert.NotEqual(t,
		instanceDeviceCacheKey("us-east-1", "", "/dev/xvda"),
		instanceDeviceCacheKey("us-east-1", "", "/dev/sdf"))
	assert.NotEqual(t,
		instanceDeviceCacheKey("us-east-1", "i-abc", ""),
		instanceDeviceCacheKey("us-east-1", "i-def", ""))
}
