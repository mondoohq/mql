// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSbinCommandCandidates(t *testing.T) {
	assert.Equal(t, []string{
		"vgs --reportformat json -o vg_name",
		"/usr/sbin/vgs --reportformat json -o vg_name",
		"/sbin/vgs --reportformat json -o vg_name",
	}, sbinCommandCandidates("vgs --reportformat json -o vg_name"))

	assert.Equal(t, []string{"zfs", "/usr/sbin/zfs", "/sbin/zfs"}, sbinCommandCandidates("zfs"))

	// a tool named by its path is run as is
	assert.Equal(t, []string{"/usr/local/sbin/zpool list"}, sbinCommandCandidates("/usr/local/sbin/zpool list"))
}

func TestIsCommandNotFound(t *testing.T) {
	assert.True(t, isCommandNotFound(127))
	assert.False(t, isCommandNotFound(0))
	assert.False(t, isCommandNotFound(5))
}
