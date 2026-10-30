// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goPluginDefaultMinPort and goPluginDefaultMaxPort are the range go-plugin
// substitutes when a client leaves both MinPort and MaxPort at zero. It is the
// range the coordinator's ephemeral default exists to avoid, so the tests spell
// it out rather than import it from anywhere.
const (
	goPluginDefaultMinPort = 10000
	goPluginDefaultMaxPort = 25000
)

func TestPluginTransportEphemeralPortOnWindows(t *testing.T) {
	// The coordinator hands go-plugin MinPort 0 and MaxPort 1 to get an
	// OS-assigned port. If go-plugin ever starts rejecting port 0 or stops
	// trying MinPort first, this is the test that says so.
	addr, ok := startTestPlugin(t, 0, 1).(*net.TCPAddr)
	require.True(t, ok, "Windows plugin transport must be loopback TCP")
	assert.NotZero(t, addr.Port, "plugin reported port 0 instead of the port the OS assigned")
	assert.False(t, addr.Port >= goPluginDefaultMinPort && addr.Port <= goPluginDefaultMaxPort,
		"port %d is inside go-plugin's default range, the ephemeral request was not honored", addr.Port)
}

func TestPluginTransportZeroZeroMeansGoPluginDefaultOnWindows(t *testing.T) {
	// Documents the trap that forces MaxPort to be 1 above: a 0-0 range is not
	// "ephemeral" to go-plugin, it is "unset", and unset means 10000-25000.
	addr, ok := startTestPlugin(t, 0, 0).(*net.TCPAddr)
	require.True(t, ok, "Windows plugin transport must be loopback TCP")
	assert.GreaterOrEqual(t, addr.Port, goPluginDefaultMinPort)
	assert.LessOrEqual(t, addr.Port, goPluginDefaultMaxPort)
}
