// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
)

// TestConnectorsSelectADialect pins the coupling between the connectors
// declared here and connection.DialectForConnector, which turns the connector
// name into the tool a configuration is read as.
//
// The failure it guards is silent: renaming a connector to something
// DialectForConnector does not know leaves the dialect unset, so the provider
// falls back to detecting it from the files. A mixed directory would then be
// read as OpenTofu no matter which connector was invoked, and nothing would
// report an error.
func TestConnectorsSelectADialect(t *testing.T) {
	want := map[string]connection.Dialect{
		"terraform": connection.DialectTerraform,
		"opentofu":  connection.DialectOpenTofu,
	}

	require.Len(t, Config.Connectors, len(want))
	for _, conn := range Config.Connectors {
		t.Run(conn.Name, func(t *testing.T) {
			expected, known := want[conn.Name]
			require.True(t, known, "unexpected connector %q", conn.Name)

			got, ok := connection.DialectForConnector(conn.Name)
			require.True(t, ok, "connector %q does not map onto a dialect", conn.Name)
			assert.Equal(t, expected, got)

			// Aliases reach the same connector, so they have to agree with it.
			for _, alias := range conn.Aliases {
				aliased, ok := connection.DialectForConnector(alias)
				require.True(t, ok, "alias %q does not map onto a dialect", alias)
				assert.Equal(t, expected, aliased, "alias %q", alias)
			}
		})
	}
}

// TestConnectorsShareTheSameFlags guards the two connectors against drifting
// apart: they read the same kinds of file, so a flag added to one belongs on
// the other. It also holds the line on the removed --iac-tool flag, which the
// connector name replaced.
func TestConnectorsShareTheSameFlags(t *testing.T) {
	names := func(flags []plugin.Flag) []string {
		out := make([]string, 0, len(flags))
		for _, f := range flags {
			out = append(out, f.Long)
		}
		return out
	}

	require.NotEmpty(t, Config.Connectors)
	first := names(Config.Connectors[0].Flags)
	assert.Equal(t, []string{"ignore-dot-terraform"}, first)

	for _, conn := range Config.Connectors[1:] {
		assert.Equal(t, first, names(conn.Flags), "connector %q", conn.Name)
	}
}
