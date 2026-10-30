// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package plugin

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPluginTransportIsUnixSocketOffWindows(t *testing.T) {
	// The port range is passed but must be irrelevant here: off Windows the
	// coordinator's port handling has no effect by construction, which is why
	// a malformed provider_port_range only warns on these platforms.
	addr := startTestPlugin(t, 0, 1)
	_, ok := addr.(*net.UnixAddr)
	assert.True(t, ok, "expected a Unix socket, got %T (%s)", addr, addr)
}
