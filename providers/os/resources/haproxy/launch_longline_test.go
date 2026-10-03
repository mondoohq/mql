// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package haproxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEnvironmentFileKeepsKeysAfterLongLine(t *testing.T) {
	env := ParseEnvironmentFile("LONG=" + strings.Repeat("x", 70000) + "\nCONFIG=/srv/lb/main.cfg\n")
	assert.Equal(t, "/srv/lb/main.cfg", env["CONFIG"])
}

func TestParseSystemdServiceKeepsDirectivesAfterLongLine(t *testing.T) {
	unit := "[Service]\nEnvironment=\"LONG=" + strings.Repeat("x", 70000) + "\"\nExecStart=/usr/sbin/haproxy -f /srv/lb/main.cfg\n"
	svc := ParseSystemdService(unit)
	assert.Equal(t, "/usr/sbin/haproxy -f /srv/lb/main.cfg", svc.ExecStart)
}
