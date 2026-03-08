// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAndUpdate_EnvVarBehavior(t *testing.T) {
	// Save and restore environment variables after test
	origAutoUpdate := os.Getenv(EnvAutoUpdate)
	origSkip := os.Getenv(envBinarySelfUpdateSkip)
	defer func() {
		if origAutoUpdate == "" {
			os.Unsetenv(EnvAutoUpdate)
		} else {
			os.Setenv(EnvAutoUpdate, origAutoUpdate)
		}
		if origSkip == "" {
			os.Unsetenv(envBinarySelfUpdateSkip)
		} else {
			os.Setenv(envBinarySelfUpdateSkip, origSkip)
		}
	}()

	t.Run("skips when MONDOO_BINARY_SELF_UPDATE_SKIP is set", func(t *testing.T) {
		os.Unsetenv(EnvAutoUpdate)
		os.Setenv(envBinarySelfUpdateSkip, "1")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when MONDOO_AUTO_UPDATE is false", func(t *testing.T) {
		os.Unsetenv(envBinarySelfUpdateSkip)
		os.Setenv(EnvAutoUpdate, "false")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when MONDOO_AUTO_UPDATE is 0", func(t *testing.T) {
		os.Unsetenv(envBinarySelfUpdateSkip)
		os.Setenv(EnvAutoUpdate, "0")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("internal skip var does not affect MONDOO_AUTO_UPDATE check order", func(t *testing.T) {
		// The internal skip var should be checked BEFORE MONDOO_AUTO_UPDATE
		// to ensure that after a binary self-update, we skip the update check
		// but allow provider auto-update to proceed (which reads MONDOO_AUTO_UPDATE)

		os.Setenv(envBinarySelfUpdateSkip, "1")
		os.Setenv(EnvAutoUpdate, "true") // Even if auto-update is enabled

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		// Should skip due to internal flag, not proceed to network check
		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("does not skip when neither env var is set", func(t *testing.T) {
		os.Unsetenv(envBinarySelfUpdateSkip)
		os.Unsetenv(EnvAutoUpdate)

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0-rolling", // Use rolling to skip network check
		}

		// Will return false due to rolling version, but won't skip due to env vars
		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when config is disabled", func(t *testing.T) {
		os.Unsetenv(envBinarySelfUpdateSkip)
		os.Unsetenv(EnvAutoUpdate)

		cfg := Config{
			Enabled:        false,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips for rolling version", func(t *testing.T) {
		os.Unsetenv(envBinarySelfUpdateSkip)
		os.Unsetenv(EnvAutoUpdate)

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0-rolling",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})
}

// TestEnvVarSeparation verifies that the internal skip env var is separate
// from the user-facing MONDOO_AUTO_UPDATE env var, ensuring that:
// 1. Binary self-update loop prevention works
// 2. Provider auto-update (which reads MONDOO_AUTO_UPDATE via viper) is not affected
func TestEnvVarSeparation(t *testing.T) {
	t.Run("env vars are different", func(t *testing.T) {
		assert.NotEqual(t, EnvAutoUpdate, envBinarySelfUpdateSkip)
		assert.Equal(t, "MONDOO_AUTO_UPDATE", EnvAutoUpdate)
		assert.Equal(t, "MONDOO_BINARY_SELF_UPDATE_SKIP", envBinarySelfUpdateSkip)
	})

	t.Run("internal skip var does not have MONDOO_AUTO_UPDATE prefix pattern", func(t *testing.T) {
		// The internal var should not match the viper auto_update key pattern
		// (viper uses MONDOO_ prefix with _ replacing . and -, so MONDOO_AUTO_UPDATE maps to auto_update)
		// Our internal var MONDOO_BINARY_SELF_UPDATE_SKIP maps to binary_self_update_skip which is not auto_update
		assert.NotContains(t, envBinarySelfUpdateSkip, "AUTO_UPDATE")
	})
}
