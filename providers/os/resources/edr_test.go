// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/edr"
)

func TestDefenderMode(t *testing.T) {
	// The strings are the values Get-MpComputerStatus reports for
	// AMRunningMode. Passive and EDR-block both leave amServiceEnabled and
	// antivirusEnabled reading true while Defender remediates little or
	// nothing, which is the distinction this mapping exists to preserve.
	tests := []struct {
		amRunningMode string
		want          string
	}{
		{"Normal", "active"},
		{"Passive Mode", "passive"},
		{"SxS Passive Mode", "passive"},
		{"EDR Block Mode", "blockOnly"},
		{"Not running", ""},
		{"", ""},
		{"normal", ""},
	}

	for _, tc := range tests {
		t.Run(tc.amRunningMode, func(t *testing.T) {
			assert.Equal(t, tc.want, defenderMode(tc.amRunningMode))
		})
	}
}

func TestPickResources(t *testing.T) {
	all := []any{"a", "b", "c"}

	assert.Equal(t, []any{"a", "c"}, pickResources(all, []int{0, 2}))
	assert.Equal(t, []any{}, pickResources(all, nil))
	assert.Equal(t, []any{}, pickResources(nil, []int{0, 1}),
		"an index into a list that could not be read must not panic")
	assert.Equal(t, []any{"b"}, pickResources(all, []int{-1, 1, 99}),
		"out-of-range indices are dropped rather than crashing the scan")
}

func TestCatalogOnlyCostsWhatThePlatformNeeds(t *testing.T) {
	// Listing processes and reading the system extension database are not
	// free, so they are only fetched where a catalog entry reads them. These
	// assertions fail if a future entry adds that cost to a platform that
	// cannot use it.
	assert.False(t, catalogNeedsProcesses(edr.PlatformWindows),
		"no Windows agent is recognized by a process, so no scan should list them")
	assert.False(t, catalogNeedsProcesses(edr.PlatformLinux))
	assert.True(t, catalogNeedsProcesses(edr.PlatformMacOS),
		"Malwarebytes on macOS is recognized by its process")

	assert.False(t, catalogNeedsSystemExtensions(edr.PlatformWindows),
		"system extensions exist only on macOS")
	assert.False(t, catalogNeedsSystemExtensions(edr.PlatformLinux))
	assert.True(t, catalogNeedsSystemExtensions(edr.PlatformMacOS))

	assert.False(t, catalogNeedsProcesses("freebsd"))
	assert.False(t, catalogNeedsSystemExtensions("freebsd"))
}
