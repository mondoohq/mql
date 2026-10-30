// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceID(t *testing.T) {
	t.Run("joins kind and parts", func(t *testing.T) {
		got, err := resourceID("digitalocean.app.deployment", "app-1", "dep-9")
		require.NoError(t, err)
		assert.Equal(t, "digitalocean.app.deployment/app-1/dep-9", got)
	})

	t.Run("single part", func(t *testing.T) {
		got, err := resourceID("digitalocean.droplet", "123")
		require.NoError(t, err)
		assert.Equal(t, "digitalocean.droplet/123", got)
	})

	// This is the case the helper exists for. A namespace uuid that the
	// listing leaves empty used to be concatenated anyway, producing a
	// well-formed looking key that every instance shared.
	t.Run("an empty part is refused", func(t *testing.T) {
		_, err := resourceID("digitalocean.function.action", "", "pkg", "hello")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "part 0 is empty")
	})

	t.Run("an empty part in the middle is refused", func(t *testing.T) {
		_, err := resourceID("digitalocean.function.action", "ns", "", "hello")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "part 1 is empty")
	})

	t.Run("no parts is refused", func(t *testing.T) {
		_, err := resourceID("digitalocean.thing")
		require.Error(t, err)
	})

	t.Run("no kind is refused", func(t *testing.T) {
		_, err := resourceID("", "a")
		require.Error(t, err)
	})

	// Two instances differing in any part must not share a key.
	t.Run("distinct parts give distinct keys", func(t *testing.T) {
		a, err := resourceID("digitalocean.function.action", "ns-1", "default", "hello")
		require.NoError(t, err)
		b, err := resourceID("digitalocean.function.action", "ns-2", "default", "hello")
		require.NoError(t, err)
		assert.NotEqual(t, a, b, "same action name in different namespaces must not alias")
	})
}
