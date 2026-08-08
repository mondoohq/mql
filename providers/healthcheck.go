// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os/exec"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	pp "go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// defaultHealthCheckTimeout bounds how long we wait for a freshly installed
// provider to launch and complete the plugin handshake. A healthy provider
// hands off in well under a second; this generous ceiling absorbs slow disks
// and antivirus scans on Windows without hanging an update indefinitely.
const defaultHealthCheckTimeout = 30 * time.Second

// healthCheckProvider launches the provider binary exactly the way the
// coordinator does at runtime (`run_as_plugin` + the hashicorp go-plugin
// handshake) and verifies it comes up and serves the provider interface, then
// shuts it back down. It exists so that a newly downloaded version is proven to
// actually start before we make it the active version.
//
// This catches the failure the old "compare the version string" check could
// not: a binary that is the right version on paper but cannot execute here at
// all (wrong architecture, a missing shared library, a panic during startup, a
// corrupt-but-correctly-sized payload). If this returns an error, the caller
// keeps the previous version active.
func healthCheckProvider(binPath string) error {
	pluginCmd := exec.Command(binPath, "run_as_plugin", "--log-level", zerolog.GlobalLevel().String())
	addColorConfig(pluginCmd)

	pluginLogger := &hclogger{Logger: log.Logger}
	pluginLogger.SetLevel(hclog.Error)

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: pp.Handshake,
		Plugins:         pp.PluginMap,
		Cmd:             pluginCmd,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC, plugin.ProtocolGRPC,
		},
		Logger:       pluginLogger,
		StartTimeout: defaultHealthCheckTimeout,
	})
	// Always tear the probe subprocess down; the caller only wanted to know
	// whether it *can* start, not to keep it running.
	defer client.Kill()

	// Client() spawns the subprocess and performs the handshake/protocol
	// negotiation. Success here already proves the binary launched and speaks
	// the plugin protocol.
	rpcClient, err := client.Client()
	if err != nil {
		return errors.Wrap(err, "provider failed to start")
	}

	// Dispense confirms the subprocess actually serves the provider plugin,
	// not just that a process started and handshook.
	if _, err := rpcClient.Dispense("provider"); err != nil {
		return errors.Wrap(err, "provider did not expose the expected plugin interface")
	}

	return nil
}
