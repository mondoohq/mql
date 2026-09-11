// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/cli/config"
)

func channelCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "update"}
	cmd.Flags().String("channel", "", "")
	require.NoError(t, cmd.ParseFlags(args))
	return cmd
}

// resetChannelState returns the process-global channel inputs to "nothing
// configured, unknown build". Called by every subtest so none of them depends
// on what the previous one left behind, and so adding t.Parallel() later does
// not quietly couple them.
func resetChannelState(t *testing.T) {
	t.Helper()
	viper.Set(config.KeyUpdateChannel, "")
	config.SetRunningVersion("")
	t.Cleanup(func() {
		viper.Set(config.KeyUpdateChannel, "")
		config.SetRunningVersion("")
	})
}

// TestApplyChannelFlag covers the one-off override: a stable install trying a
// pre-release provider should not have to edit mondoo.yml and remember to put
// it back.
func TestApplyChannelFlag(t *testing.T) {
	t.Run("no flag leaves the configured channel alone", func(t *testing.T) {
		resetChannelState(t)
		viper.Set(config.KeyUpdateChannel, config.ChannelPreview)

		require.NoError(t, applyChannelFlag(channelCmd(t)))
		assert.Equal(t, config.ChannelPreview, config.GetUpdateChannel())
	})

	t.Run("preview overrides a stable build", func(t *testing.T) {
		resetChannelState(t)
		config.SetRunningVersion("13.38.1")
		require.Equal(t, config.ChannelStable, config.GetUpdateChannel())

		require.NoError(t, applyChannelFlag(channelCmd(t, "--channel", "preview")))
		assert.Equal(t, config.ChannelPreview, config.GetUpdateChannel())
	})

	t.Run("stable overrides a pre-release build", func(t *testing.T) {
		resetChannelState(t)
		config.SetRunningVersion("14.0.0-rc.2")
		require.Equal(t, config.ChannelPreview, config.GetUpdateChannel())

		require.NoError(t, applyChannelFlag(channelCmd(t, "--channel", "stable")))
		assert.Equal(t, config.ChannelStable, config.GetUpdateChannel())
	})

	t.Run("case and spacing are normalized", func(t *testing.T) {
		resetChannelState(t)

		require.NoError(t, applyChannelFlag(channelCmd(t, "--channel", "  PREVIEW ")))
		assert.Equal(t, config.ChannelPreview, config.GetUpdateChannel())
	})

	t.Run("an unknown channel is an error, not a fallback", func(t *testing.T) {
		// Elsewhere an unrecognized channel falls back to the build, because it
		// came from a config file nobody may be looking at. Here it was typed
		// on the command line, so it is worth saying so.
		resetChannelState(t)

		err := applyChannelFlag(channelCmd(t, "--channel", "beta"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "beta")
		assert.Contains(t, err.Error(), config.ChannelPreview)

		// And it must not have changed anything on its way out.
		assert.Equal(t, config.ChannelStable, config.GetUpdateChannel())
	})
}
