// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	goruntime "runtime"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/config"
)

// Providers are hashicorp/go-plugin subprocesses. On Linux and macOS the host
// reaches them over a Unix socket, but go-plugin hard-codes loopback TCP on
// Windows and lets the client pick the port range, which the plugin walks in
// ascending order until a bind succeeds. That makes the bottom of the range
// the entire collision surface: a Windows host only ever uses the first few
// ports above the minimum, one per running provider. go-plugin's own default
// of 10000-25000 put us on port 10000 (Webmin, plenty of Java stacks), and a
// fixed minimum of 50000 would have put us on IBM Db2's default listener and
// on SAP NetWeaver's instance-00 ports.
//
// So by default there is no fixed range: the plugin binds 127.0.0.1:0 and the
// OS assigns a port from its dynamic range, honoring Hyper-V and WSL port
// exclusions and spreading across the range instead of clustering at a
// minimum, which is what every well-behaved local service does. Operators who
// need a predictable range for host-based tooling can still set one with
// provider_port_range.

// ephemeralPluginPortRange asks go-plugin for an OS-assigned port. go-plugin
// substitutes its 10000-25000 default only when both Min and Max are zero, so
// Max is 1 purely to get past that check. Its listener loop tries
// 127.0.0.1:<Min> first, and a bind to port 0 always succeeds, so port 1 is
// never attempted. Verified against the pinned go-plugin version: NewClient in
// client.go and serverListener_tcp in server.go.
var ephemeralPluginPortRange = pluginPortRange{Min: 0, Max: 1}

// pluginPortRange is the inclusive loopback TCP port range handed to a
// provider subprocess. Only Windows uses it; other platforms ignore it.
type pluginPortRange struct {
	Min, Max uint
}

// providerTransportUsesMTLS reports whether the host should negotiate go-plugin
// AutoMTLS with its provider subprocesses.
//
// It is gated to Windows for the same reason the port handling above is: there
// the transport is loopback TCP, connectable by any local process regardless of
// user. Without mutual TLS, a standard user could reach a running provider's
// gRPC API on that port and drive it at the provider's privileges (for example
// run a command through the live local connection, which under the cnspec
// Windows service is the service account). AutoMTLS makes the host mint a
// one-time certificate, hand it to the plugin, and refuse every connection that
// does not present it; the provider side negotiates this automatically in
// plugin.Serve, so already-installed provider binaries keep working.
//
// On Linux and macOS the transport is a Unix socket writable only by its owner,
// which already restricts it to the user the provider runs as, so mTLS would
// add a handshake with no security gain. The Windows cost is negligible: a full
// CIS Microsoft Windows Server 2022 Benchmark scan measured under 0.2% median
// difference with it on.
func providerTransportUsesMTLS() bool {
	return goruntime.GOOS == "windows"
}

// resolvePluginPortRange decides which ports a provider subprocess may listen
// on: provider_port_range from mondoo.yml or MONDOO_PROVIDER_PORT_RANGE as
// "min-max", or an OS-assigned port when unset.
func resolvePluginPortRange() (pluginPortRange, error) {
	return resolvePluginPortRangeFrom(config.GetProviderPortRange(), goruntime.GOOS == "windows")
}

// resolvePluginPortRangeFrom is the pure core of resolvePluginPortRange.
//
// transportUsesTCP says whether the setting has any effect on this platform.
// Where it does, a malformed value is an error rather than a silent fall back:
// an operator who set it did so to move away from a collision, and running on
// a different range would leave that collision in place unannounced. Where it
// does not (Unix sockets), the same typo must not take down scans over a
// setting that never applied, so it is logged and ignored.
func resolvePluginPortRangeFrom(configured string, transportUsesTCP bool) (pluginPortRange, error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return ephemeralPluginPortRange, nil
	}

	r, err := parsePluginPortRange(configured)
	if err == nil {
		return r, nil
	}

	err = errors.Wrapf(err, "invalid %s %q", config.KeyProviderPortRange, configured)
	if transportUsesTCP {
		return pluginPortRange{}, err
	}
	log.Warn().Err(err).Msg("ignoring the provider port range, this platform reaches providers over Unix sockets")
	return ephemeralPluginPortRange, nil
}

// parsePluginPortRange parses the "min-max" form, for example "50000-50100".
func parsePluginPortRange(s string) (pluginPortRange, error) {
	minS, maxS, ok := strings.Cut(s, "-")
	if !ok {
		return pluginPortRange{}, errors.New("expected the form min-max, for example 50000-50100")
	}
	minPort, err := parsePort(strings.TrimSpace(minS))
	if err != nil {
		return pluginPortRange{}, err
	}
	maxPort, err := parsePort(strings.TrimSpace(maxS))
	if err != nil {
		return pluginPortRange{}, err
	}
	if minPort > maxPort {
		return pluginPortRange{}, errors.Newf("min port %d is greater than max port %d", minPort, maxPort)
	}
	return pluginPortRange{Min: minPort, Max: maxPort}, nil
}

// parsePort accepts 1-65535. Port 0 is rejected: go-plugin reads a 0-0 range
// as "unset" and falls back to its own 10000-25000 default, and an OS-assigned
// port is what leaving the setting empty already gives you.
func parsePort(s string) (uint, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, errors.Newf("%q is not a valid port", s)
	}
	if p == 0 {
		return 0, errors.New("port 0 is not allowed")
	}
	return uint(p), nil
}
