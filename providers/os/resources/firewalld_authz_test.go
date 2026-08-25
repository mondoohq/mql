// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// firewall-cmd exits non-zero both when the firewall is stopped and when polkit
// refuses to answer an unprivileged caller. Only the second must be treated as
// "we could not determine"; conflating them reports a running firewall as off.
func TestIsFirewalldAuthzError(t *testing.T) {
	authz := []string{
		// verbatim from an unprivileged `firewall-cmd --state` on CentOS Stream 9
		"Authorization failed.\n    Make sure polkit agent is running or run the application as superuser.",
		"Authorization failed.",
		"Error: NOT_AUTHORIZED",
		"Failed to query polkit authority",
		"dbus.exceptions.DBusException: Permission denied",
		"Access denied",
		// case must not matter
		"AUTHORIZATION FAILED",
	}
	for _, s := range authz {
		t.Run("authz/"+s[:min(len(s), 28)], func(t *testing.T) {
			assert.True(t, isFirewalldAuthzError(s), "should be recognised as an authorization failure")
		})
	}

	notAuthz := []string{
		// what firewall-cmd prints when the daemon really is stopped
		"firewall-cmd: error: Failed to connect to bus: No such file or directory",
		"FirewallD is not running",
		"Error: COMMAND_FAILED",
		"command not found",
		"",
	}
	for _, s := range notAuthz {
		name := s
		if name == "" {
			name = "empty"
		}
		t.Run("stopped/"+name[:min(len(name), 28)], func(t *testing.T) {
			assert.False(t, isFirewalldAuthzError(s),
				"a genuinely stopped firewall must still report as not running")
		})
	}
}
