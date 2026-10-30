// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// A provider flag whose shorthand collides with an already-registered flag
// (e.g. -f for the global output-format) must not panic the CLI. The
// colliding shorthand is dropped and the long flag stays usable.
func TestAttachFlag_ShorthandCollisionDoesNotPanic(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.StringP("output-format", "f", "json", "global output format")

	require.NotPanics(t, func() {
		attachFlag(flags, plugin.Flag{
			Long:  "values",
			Short: "f",
			Type:  plugin.FlagType_List,
			Desc:  "provider flag that reuses -f",
		})
	})

	// long flag is registered, shorthand still belongs to the original owner
	assert.NotNil(t, flags.Lookup("values"), "long flag should be attached")
	assert.Equal(t, "output-format", flags.ShorthandLookup("f").Name, "shorthand should remain with the original flag")
}

// A non-colliding shorthand is preserved.
func TestAttachFlag_FreeShorthandPreserved(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)

	attachFlag(flags, plugin.Flag{
		Long:  "namespace",
		Short: "n",
		Type:  plugin.FlagType_String,
		Desc:  "release namespace",
	})

	f := flags.Lookup("namespace")
	require.NotNil(t, f)
	assert.Equal(t, "n", f.Shorthand, "free shorthand should be preserved")
}
