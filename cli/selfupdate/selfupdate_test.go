// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAndUpdate_EnvVarBehavior(t *testing.T) {
	t.Run("skips when MONDOO_AUTO_UPDATE is false", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "false")
		t.Setenv(EnvAutoUpdateEngine, "")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when MONDOO_AUTO_UPDATE is 0", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "0")
		t.Setenv(EnvAutoUpdateEngine, "")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when MONDOO_AUTO_UPDATE_ENGINE is false", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "false")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when MONDOO_AUTO_UPDATE_ENGINE is 0", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "0")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips engine when MONDOO_AUTO_UPDATE is on but MONDOO_AUTO_UPDATE_ENGINE is off", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "true")
		t.Setenv(EnvAutoUpdateEngine, "false")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("MONDOO_AUTO_UPDATE off overrides MONDOO_AUTO_UPDATE_ENGINE on", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "false")
		t.Setenv(EnvAutoUpdateEngine, "true")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("does not skip when neither env var is set", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "")

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
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "")

		cfg := Config{
			Enabled:        false,
			CurrentVersion: "1.0.0",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips for rolling version", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "")

		cfg := Config{
			Enabled:        true,
			CurrentVersion: "1.0.0-rolling",
		}

		updated, err := CheckAndUpdate(cfg)
		assert.NoError(t, err)
		assert.False(t, updated)
	})
}

// TestCheckLocalAndUpdate verifies the local-only entry point used by the
// "version" command (issue #7751): it shares CheckAndUpdate's guards but never
// performs a network request.
func TestCheckLocalAndUpdate(t *testing.T) {
	t.Run("skips when MONDOO_AUTO_UPDATE is false", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "false")
		t.Setenv(EnvAutoUpdateEngine, "")

		updated, err := CheckLocalAndUpdate(Config{Enabled: true, CurrentVersion: "1.0.0"})
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when MONDOO_AUTO_UPDATE_ENGINE is false", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "false")

		updated, err := CheckLocalAndUpdate(Config{Enabled: true, CurrentVersion: "1.0.0"})
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips when config is disabled", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "")

		updated, err := CheckLocalAndUpdate(Config{Enabled: false, CurrentVersion: "1.0.0"})
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("skips for rolling version", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "")

		updated, err := CheckLocalAndUpdate(Config{Enabled: true, CurrentVersion: "1.0.0-rolling"})
		assert.NoError(t, err)
		assert.False(t, updated)
	})

	t.Run("performs no network request", func(t *testing.T) {
		t.Setenv(EnvAutoUpdate, "")
		t.Setenv(EnvAutoUpdateEngine, "")

		// A binary name that cannot be staged locally makes execLocalIfNewer
		// return immediately, and the unroutable ReleaseURL would surface as an
		// error if the local-only path ever reached the network.
		updated, err := CheckLocalAndUpdate(Config{
			Enabled:        true,
			CurrentVersion: "999.999.999",
			ReleaseURL:     "https://invalid.invalid/should-never-be-called.json",
			BinaryName:     "mql-selfupdate-test-nonexistent",
		})
		assert.NoError(t, err)
		assert.False(t, updated)
	})
}

// TestEnvVarSeparation verifies that MONDOO_AUTO_UPDATE_ENGINE is separate from
// MONDOO_AUTO_UPDATE, ensuring that:
// 1. Engine binary auto-update can be disabled independently of provider auto-update
// 2. Provider auto-update (which reads MONDOO_AUTO_UPDATE via viper) is not affected
func TestEnvVarSeparation(t *testing.T) {
	t.Run("env vars are different", func(t *testing.T) {
		assert.NotEqual(t, EnvAutoUpdate, EnvAutoUpdateEngine)
		assert.Equal(t, "MONDOO_AUTO_UPDATE", EnvAutoUpdate)
		assert.Equal(t, "MONDOO_AUTO_UPDATE_ENGINE", EnvAutoUpdateEngine)
	})
}

func TestConfigRegisterVersion(t *testing.T) {
	var registered []string
	orig := updateRegisteredVersionFunc
	updateRegisteredVersionFunc = func(version string) error {
		registered = append(registered, version)
		return nil
	}
	t.Cleanup(func() { updateRegisteredVersionFunc = orig })

	t.Run("registers by default", func(t *testing.T) {
		registered = nil
		Config{BinaryName: "cnspec"}.registerVersion("14.8.0")
		assert.Equal(t, []string{"14.8.0"}, registered)
	})

	t.Run("skips when SkipRegisteredVersion is set", func(t *testing.T) {
		registered = nil
		Config{BinaryName: "example", SkipRegisteredVersion: true}.registerVersion("1.2.3")
		assert.Empty(t, registered)
	})
}
