// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestCatalogPlatforms(t *testing.T) {
	cat := CatalogPlatforms()
	require.NotEmpty(t, cat)

	// one entry per detector-tree leaf, no more, no less
	assert.Len(t, cat, len(osTree))

	byName := map[string]bool{}
	for _, pi := range cat {
		byName[pi.Name] = true
		// runtime is unconstrained for OS; kinds are the closed set
		assert.Empty(t, pi.Runtime, "OS runtime must stay unconstrained for %q", pi.Name)
		assert.Equal(t, osPlatformKinds, pi.Kind, "kinds for %q", pi.Name)
	}
	for name := range osTree {
		assert.True(t, byName[name], "tree leaf %q missing from catalog", name)
	}

	// a representative platform is present with the leaf-first family chain
	// matching what the runtime emits (see resolvePlatform)
	var ubuntu *struct {
		fam []string
	}
	for _, pi := range cat {
		if pi.Name == "ubuntu" {
			ubuntu = &struct{ fam []string }{pi.Family}
		}
	}
	require.NotNil(t, ubuntu, "ubuntu should be a catalogued platform")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, ubuntu.fam)

	// a resolver that emits more names than the one it is registered under has
	// to catalogue every one of them: the azurelinux resolver also handles
	// CBL-Mariner, which reports ID=mariner
	assert.True(t, byName["azurelinux"], "azurelinux should be a catalogued platform")
	assert.True(t, byName["mariner"], "mariner should be a catalogued platform")

	// BellSoft Alpaquita and BellSoft Hardened Containers are Alpine-lineage but
	// each is a platform of its own, with its own release line and its own
	// advisory feed. Detection reads the name straight off os-release either
	// way, so the catalog is what says they are known platforms rather than
	// unrecognized systems that happened to carry an ID.
	assert.True(t, byName["alpaquita"], "alpaquita should be a catalogued platform")
	assert.True(t, byName["bellsoft-hardened-containers"],
		"bellsoft-hardened-containers should be a catalogued platform")

	// darwin is a kernel and a family, never a platform of its own
	assert.True(t, byName["macos"], "macos should be a catalogued platform")
	assert.False(t, byName["darwin"], "darwin should not be a catalogued platform")
}

// Every name detection can actually emit has to be in the tree, or the platform
// carries no family chain and plugin.PlatformInfo.Apply cannot find it in the
// catalog, which degrades the asset to "unknown". The catalog test above only
// compares the catalog against the tree; nothing compared the tree against what
// resolvers really set, and a resolver does not always emit the name it is
// registered under.
//
// Leaves claimed by defaultLinux are excluded: that resolver can emit any ID an
// unknown system happens to carry, so it cannot be enumerated. A system landing
// there is its own known problem, reported as "scratch" for container images,
// and the fix is to give it a resolver.
func TestEveryEmittedPlatformNameIsInTheTree(t *testing.T) {
	fixtures, err := filepath.Glob("./testdata/*.toml")
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)
	sort.Strings(fixtures)

	for _, fixture := range fixtures {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(fixture))
		if err != nil {
			continue // not a platform-detection fixture
		}

		pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, conn)
		if !resolved || leaf == nil || leaf == defaultLinux || pf.Name == "" {
			continue
		}

		_, ok := osTree[pf.Name]
		assert.True(t, ok, "%s: resolver %q emits platform %q, which is not in the tree",
			filepath.Base(fixture), leaf.Name, pf.Name)
	}
}
