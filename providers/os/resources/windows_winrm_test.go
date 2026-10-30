// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWinRMBool(t *testing.T) {
	t.Run("present and 1 is true", func(t *testing.T) {
		items := map[string]int64{"allowbasic": 1}
		assert.True(t, winrmBool(items, "AllowBasic", false))
	})

	t.Run("present and 0 is false", func(t *testing.T) {
		items := map[string]int64{"allowbasic": 0}
		// default is true, but an explicit 0 disables it
		assert.False(t, winrmBool(items, "AllowBasic", true))
	})

	t.Run("absent uses the documented default", func(t *testing.T) {
		assert.True(t, winrmBool(map[string]int64{}, "AllowBasic", true))
		assert.False(t, winrmBool(nil, "AllowAutoConfig", false))
	})

	t.Run("value name matching is case insensitive", func(t *testing.T) {
		items := map[string]int64{"allowunencryptedtraffic": 1}
		assert.True(t, winrmBool(items, "AllowUnencryptedTraffic", false))
	})

	t.Run("any non-1 value is false", func(t *testing.T) {
		items := map[string]int64{"allowbasic": 2}
		assert.False(t, winrmBool(items, "AllowBasic", true))
	})
}

func TestComputeWinRMService(t *testing.T) {
	// Only the two policy-key settings are resolved here. Basic authentication,
	// unencrypted traffic and remote shell access have a live WS-Management
	// value that already carries any policy, and are read from there instead:
	// a stock Server 2016, 2019 and 2022 all report Basic and unencrypted as
	// off on the service, which is the opposite of what an absent policy key
	// used to be reported as.
	t.Run("absent uses documented defaults", func(t *testing.T) {
		disableRunAs, autoConfig := computeWinRMService(map[string]int64{})
		assert.False(t, disableRunAs) // not disabled by default
		assert.False(t, autoConfig)   // listener not auto-configured by default
	})

	t.Run("nil map uses documented defaults", func(t *testing.T) {
		disableRunAs, autoConfig := computeWinRMService(nil)
		assert.False(t, disableRunAs)
		assert.False(t, autoConfig)
	})

	t.Run("explicit values override defaults", func(t *testing.T) {
		disableRunAs, autoConfig := computeWinRMService(map[string]int64{
			"disablerunas":    1,
			"allowautoconfig": 1,
		})
		assert.True(t, disableRunAs)
		assert.True(t, autoConfig)
	})

	t.Run("explicit zero is not the same as absent for a default-true setting", func(t *testing.T) {
		// both of these default to false, so an explicit 0 and an absence agree;
		// the assertion is that an explicit 0 is still read rather than skipped
		disableRunAs, autoConfig := computeWinRMService(map[string]int64{
			"disablerunas":    0,
			"allowautoconfig": 0,
		})
		assert.False(t, disableRunAs)
		assert.False(t, autoConfig)
	})
}

func TestComputeWinRMServiceStartMode(t *testing.T) {
	t.Run("present value is returned", func(t *testing.T) {
		assert.Equal(t, int64(2), computeWinRMServiceStartMode(map[string]int64{"start": 2}))
		assert.Equal(t, int64(4), computeWinRMServiceStartMode(map[string]int64{"start": 4}))
	})

	t.Run("absent uses documented default (manual)", func(t *testing.T) {
		assert.Equal(t, int64(3), computeWinRMServiceStartMode(map[string]int64{}))
		assert.Equal(t, int64(3), computeWinRMServiceStartMode(nil))
	})

	t.Run("case insensitive value name", func(t *testing.T) {
		// loader lower-cases names; the lookup uses the lower-cased "start"
		assert.Equal(t, int64(2), computeWinRMServiceStartMode(map[string]int64{"start": 2}))
	})
}

// windows.winrm.client and windows.winrm.service are each both a field path on
// windows.winrm and a resource name, which is the condition that makes an Init
// necessary: the compiler resolves the resource name first, so the dotted form
// skips the parent's accessor and every field the parent would have populated
// stays unset.
func TestWindowsWinrmSingletonsAreReachableByTheirOwnPath(t *testing.T) {
	for _, path := range []string{
		"windows.winrm.client",
		"windows.winrm.service",
	} {
		t.Run(path, func(t *testing.T) {
			_, isField := getDataFields[path]
			require.True(t, isField, "%s should be a field path on its parent", path)

			factory, isResource := resourceFactories[path]
			require.True(t, isResource, "%s should also be a registered resource name", path)

			assert.NotNil(t, factory.Init,
				"%s resolves to the resource, not the field, so without an Init every field reads null", path)
		})
	}
}
