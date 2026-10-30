// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigTextFromResponse covers the shapes that used to become an empty
// string. Every running-config parser in this provider is a pure function of
// that string, and an empty one parses into a device with no AAA servers, no
// syslog collectors and no ACL bindings: a clean posture asserted from data
// that was never read. These have to be errors, not empty results.
func TestConfigTextFromResponse(t *testing.T) {
	t.Run("a body is returned as-is", func(t *testing.T) {
		got, err := configTextFromResponse(map[string]any{"output": "hostname leaf1\n"}, "running-config")
		require.NoError(t, err)
		assert.Equal(t, "hostname leaf1", got)
	})

	t.Run("no output key is an error", func(t *testing.T) {
		_, err := configTextFromResponse(map[string]any{}, "running-config")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no text output")
	})

	t.Run("a non-string output is an error, not a panic", func(t *testing.T) {
		_, err := configTextFromResponse(map[string]any{"output": 42}, "running-config")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no text output")
	})

	t.Run("an empty body is an error", func(t *testing.T) {
		// An EOS device never renders an empty configuration, so this is a
		// failed read rather than a bare device.
		for _, body := range []string{"", "   ", "\n\n"} {
			_, err := configTextFromResponse(map[string]any{"output": body}, "startup-config")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "empty configuration")
		}
	})

	t.Run("the error names which configuration failed", func(t *testing.T) {
		_, err := configTextFromResponse(map[string]any{}, "startup-config")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "startup-config")
	})
}
