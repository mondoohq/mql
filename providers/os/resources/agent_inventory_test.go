// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/edr"
	"go.mondoo.com/mql/providers/os/resources/rmm"
)

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
	assert.False(t, catalogNeedsProcesses(edr.Catalog, edr.PlatformWindows),
		"no Windows agent is recognized by a process, so no scan should list them")
	assert.False(t, catalogNeedsProcesses(edr.Catalog, edr.PlatformLinux))
	assert.True(t, catalogNeedsProcesses(edr.Catalog, edr.PlatformMacOS),
		"Malwarebytes on macOS is recognized by its process")

	assert.False(t, catalogNeedsSystemExtensions(edr.Catalog, edr.PlatformWindows),
		"system extensions exist only on macOS")
	assert.False(t, catalogNeedsSystemExtensions(edr.Catalog, edr.PlatformLinux))
	assert.True(t, catalogNeedsSystemExtensions(edr.Catalog, edr.PlatformMacOS))

	assert.False(t, catalogNeedsProcesses(edr.Catalog, "freebsd"))
	assert.False(t, catalogNeedsSystemExtensions(edr.Catalog, "freebsd"))

	assert.False(t, catalogNeedsProcesses(rmm.Catalog, edr.PlatformWindows),
		"every Windows management agent runs as a service")
	assert.True(t, catalogNeedsProcesses(rmm.Catalog, edr.PlatformLinux),
		"the Kaseya VSA agent on Linux is recognized by its process")
	assert.True(t, catalogNeedsProcesses(rmm.Catalog, edr.PlatformMacOS),
		"the N-sight agent on macOS is recognized by its process")
	for _, platform := range []string{edr.PlatformWindows, edr.PlatformLinux, edr.PlatformMacOS} {
		assert.False(t, catalogNeedsSystemExtensions(rmm.Catalog, platform),
			"no management agent is recognized by a system extension")
	}
}
