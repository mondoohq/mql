// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/opcua/connection"
)

// A connection option the CLI never declares can never be set by a user, so
// every option key the connection reads needs a flag behind it.
func TestConnectorDeclaresEveryConnectionFlag(t *testing.T) {
	require.Len(t, Config.Connectors, 1)

	declared := map[string]bool{}
	for _, flag := range Config.Connectors[0].Flags {
		declared[flag.Long] = true
	}

	wanted := []string{
		connection.OptionEndpoint,
		connection.OptionSecurityPolicy,
		connection.OptionSecurityMode,
		connection.OptionCertFile,
		connection.OptionKeyFile,
		"username",
		"password",
	}
	for _, flag := range wanted {
		assert.True(t, declared[flag], "flag %q is not declared by the opcua connector", flag)
	}
}
