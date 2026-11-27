// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveUpdateTarget(t *testing.T) {
	name := "os"

	t.Run("updates to latest when newer", func(t *testing.T) {
		target, update, err := ResolveUpdateTarget(name, "13.4.0", "13.4.1", UpdateProvidersConfig{})
		require.NoError(t, err)
		assert.True(t, update)
		assert.Equal(t, "13.4.1", target)
	})

	t.Run("no update when already latest", func(t *testing.T) {
		target, update, err := ResolveUpdateTarget(name, "13.4.1", "13.4.1", UpdateProvidersConfig{})
		require.NoError(t, err)
		assert.False(t, update)
		assert.Equal(t, "13.4.1", target)
	})

	t.Run("no update when installed newer than latest", func(t *testing.T) {
		_, update, err := ResolveUpdateTarget(name, "13.5.0", "13.4.1", UpdateProvidersConfig{})
		require.NoError(t, err)
		assert.False(t, update)
	})

	t.Run("pin holds exact version, ignoring newer latest", func(t *testing.T) {
		cfg := UpdateProvidersConfig{Pin: map[string]string{name: "13.4.0"}}
		target, update, err := ResolveUpdateTarget(name, "13.4.0", "13.9.9", cfg)
		require.NoError(t, err)
		assert.False(t, update, "already at pin, no update")
		assert.Equal(t, "13.4.0", target)
	})

	t.Run("pin installs pinned version when not present", func(t *testing.T) {
		cfg := UpdateProvidersConfig{Pin: map[string]string{name: "13.4.0"}}
		target, update, err := ResolveUpdateTarget(name, "13.2.0", "13.9.9", cfg)
		require.NoError(t, err)
		assert.True(t, update)
		assert.Equal(t, "13.4.0", target, "pin is authoritative, not latest")
	})

	t.Run("floor refuses a latest below the baseline", func(t *testing.T) {
		cfg := UpdateProvidersConfig{Floor: map[string]string{name: "13.4.0"}}
		target, update, err := ResolveUpdateTarget(name, "13.4.0", "13.3.0", cfg)
		require.NoError(t, err)
		assert.False(t, update, "latest below floor is refused")
		assert.Equal(t, "13.4.0", target)
	})

	t.Run("floor allows a latest at or above the baseline", func(t *testing.T) {
		cfg := UpdateProvidersConfig{Floor: map[string]string{name: "13.4.0"}}
		target, update, err := ResolveUpdateTarget(name, "13.4.0", "13.5.0", cfg)
		require.NoError(t, err)
		assert.True(t, update)
		assert.Equal(t, "13.5.0", target)
	})

	t.Run("pin takes precedence over floor", func(t *testing.T) {
		cfg := UpdateProvidersConfig{
			Pin:   map[string]string{name: "13.4.0"},
			Floor: map[string]string{name: "13.8.0"},
		}
		target, update, err := ResolveUpdateTarget(name, "13.2.0", "13.9.0", cfg)
		require.NoError(t, err)
		assert.True(t, update)
		assert.Equal(t, "13.4.0", target)
	})
}
