// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
)

// The provider transport is whatever hashicorp/go-plugin picks: a Unix socket
// off Windows, loopback TCP on it. The coordinator relies on details of that
// choice which go-plugin does not document, above all that a MinPort of 0 with
// a non-zero MaxPort makes the plugin bind 127.0.0.1:0 and get an OS-assigned
// port (see providers/plugin_ports.go). These tests pin that behavior against
// the vendored version by running a real plugin handshake: the test binary
// re-executes itself as the plugin, which is the pattern go-plugin's own tests
// use.

// transportHelperEnv marks a re-execution of the test binary that should serve
// a plugin instead of running tests.
const transportHelperEnv = "MQL_PLUGIN_TRANSPORT_HELPER"

// servePluginForTransportTests is called first thing by TestMain. When this
// process is a re-execution spawned by startTestPlugin it serves a plugin until
// the client kills it and reports true so TestMain exits without running tests.
func servePluginForTransportTests() bool {
	if os.Getenv(transportHelperEnv) != "1" {
		return false
	}
	// Impl is nil on purpose: the tests only need the handshake, never a
	// provider call.
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         PluginMap,
		GRPCServer:      plugin.DefaultGRPCServer,
		Logger:          hclog.NewNullLogger(),
	})
	return true
}

// startTestPlugin spawns this test binary as a go-plugin plugin with the given
// port range and returns the address the plugin reported in its handshake.
func startTestPlugin(t *testing.T, minPort, maxPort uint) net.Addr {
	t.Helper()

	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), transportHelperEnv+"=1")

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          PluginMap,
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		MinPort:          minPort,
		MaxPort:          maxPort,
		Logger:           hclog.NewNullLogger(),
		StartTimeout:     30 * time.Second,
	})
	t.Cleanup(client.Kill)

	addr, err := client.Start()
	require.NoError(t, err, "plugin handshake failed")
	return addr
}
