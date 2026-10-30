// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/hetzner/connection"
)

func TestChildConfig(t *testing.T) {
	// Regression: an inventory-file or env-token asset can arrive with a nil
	// Options map. Config.Clone leaves it nil, so writing the discriminating
	// option must not panic on a nil-map assignment.
	t.Run("nil Options does not panic", func(t *testing.T) {
		conf := &inventory.Config{Type: "hetzner", Options: nil}
		var cfg *inventory.Config
		require.NotPanics(t, func() {
			cfg = childConfig(conf, 1, connection.OptionFirewall, "42")
		})
		require.NotNil(t, cfg.Options)
		assert.Equal(t, "42", cfg.Options[connection.OptionFirewall])
	})

	t.Run("existing Options are preserved", func(t *testing.T) {
		conf := &inventory.Config{
			Type:    "hetzner",
			Options: map[string]string{connection.OPTION_ENDPOINT: "https://example.test"},
		}
		cfg := childConfig(conf, 1, connection.OptionLoadBalancer, "7")
		assert.Equal(t, "https://example.test", cfg.Options[connection.OPTION_ENDPOINT])
		assert.Equal(t, "7", cfg.Options[connection.OptionLoadBalancer])
		// The clone must not mutate the source config's Options.
		assert.NotContains(t, conf.Options, connection.OptionLoadBalancer)
	})
}
