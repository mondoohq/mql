// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/inittab_aix73.txt holds the entries of /etc/inittab of AIX 7.3
// TL4 SP2.
func TestParseInittab(t *testing.T) {
	f, err := os.Open("testdata/inittab_aix73.txt")
	require.NoError(t, err)
	defer f.Close()
	entries, err := ParseInittab(f)
	require.NoError(t, err)
	byID := map[string]InittabEntry{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	assert.Len(t, entries, 40)

	assert.Equal(t, InittabEntry{ID: "cron", RunLevels: "23456789", Action: "respawn", Command: "/usr/sbin/cron"}, byID["cron"])
	assert.Equal(t, "off", byID["shdaemon"].Action)
	// the trailing comment is not part of the command
	assert.Equal(t, "/etc/rc.tcpip > /dev/console 2>&1", byID["rctcpip"].Command)
	assert.Equal(t, "", byID["brc"].RunLevels)
}
