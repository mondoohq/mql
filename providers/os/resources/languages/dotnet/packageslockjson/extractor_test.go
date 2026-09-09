// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packageslockjson

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestPackagesLockJsonExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.packages.lock.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/packages.lock.json")
	require.NoError(t, err)

	// No root in packages.lock.json
	assert.Nil(t, info.Root())

	// Direct deps
	direct := info.Direct()
	assert.Equal(t, 2, len(direct))
	p := direct.Find("Newtonsoft.Json")
	require.NotNil(t, p)
	assert.Equal(t, "13.0.3", p.Version)
	assert.Equal(t, "pkg:nuget/Newtonsoft.Json@13.0.3", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/packages.lock.json"}}, p.EvidenceList)

	p = direct.Find("Serilog")
	require.NotNil(t, p)
	assert.Equal(t, "3.1.1", p.Version)

	// Transitive should NOT be in direct
	assert.Nil(t, direct.Find("System.Text.Json"))

	// All deps (direct + transitive)
	transitive := info.Transitive()
	assert.Equal(t, 4, len(transitive))

	p = transitive.Find("System.Text.Json")
	require.NotNil(t, p)
	assert.Equal(t, "8.0.0", p.Version)
	assert.Equal(t, "pkg:nuget/System.Text.Json@8.0.0", p.Purl)
}

// TestPackagesLockJsonDependencyEdges pins the .NET package->package graph.
//
// packages.lock.json states each entry's own `dependencies`, and it was parsed
// and discarded: a consumer knew WHICH packages a project restores and nothing
// about what reaches what, so no transitive package could be ruled in or out.
func TestPackagesLockJsonDependencyEdges(t *testing.T) {
	f, err := os.Open("./testdata/simple.packages.lock.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "packages.lock.json")
	require.NoError(t, err)
	all := info.Transitive()

	serilog := all.Find("Serilog")
	require.NotNil(t, serilog)
	// The edge target carries the RESOLVED version (5.0.1), never the minimum
	// constraint written beside the id in `dependencies` (4.0.0). A purl built
	// from the constraint names a package that is not in this inventory, so the
	// edge would point at nothing.
	assert.Equal(t, []string{"pkg:nuget/Serilog.Sinks.Console@5.0.1"}, serilog.DependsOn,
		"edges resolve by id against the package set, not from the minimum-version constraint")

	console := all.Find("Serilog.Sinks.Console")
	require.NotNil(t, console)
	assert.Equal(t, []string{"pkg:nuget/System.Text.Json@8.0.0"}, console.DependsOn)

	// A leaf states no dependencies and must carry no edges rather than an
	// empty slice, so "has no dependencies" and "was never asked" stay distinct
	// downstream.
	stj := all.Find("System.Text.Json")
	require.NotNil(t, stj)
	assert.Nil(t, stj.DependsOn)

	// Direct() reports the same edges: it is the same package, and a consumer
	// that reads only the direct set must not see a different graph.
	direct := info.Direct()
	require.NotNil(t, direct.Find("Serilog"))
	assert.Equal(t, serilog.DependsOn, direct.Find("Serilog").DependsOn)
}

// TestPackagesLockJsonDropsUnresolvedEdgeTargets: `Serilog` names
// `NotRestored.Package` in its dependencies and the lockfile resolves no such
// entry. Synthesising the node would assert a package the project does not
// restore, and the reachability classifier reads an edge's target as a package
// that exists.
func TestPackagesLockJsonDropsUnresolvedEdgeTargets(t *testing.T) {
	f, err := os.Open("./testdata/simple.packages.lock.json")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "packages.lock.json")
	require.NoError(t, err)

	serilog := info.Transitive().Find("Serilog")
	require.NotNil(t, serilog)
	for _, ref := range serilog.DependsOn {
		assert.NotContains(t, ref, "NotRestored",
			"a dependency the lockfile did not resolve must not become an edge")
	}
	assert.Nil(t, info.Transitive().Find("NotRestored.Package"),
		"and it must not become a package either")
}

// TestPackagesLockJsonMultiFrameworkIsDeterministic guards a coin toss.
//
// A multi-targeting project can resolve one package to different versions per
// target framework. The framework map was ranged directly, so WHICH version got
// inventoried depended on Go's map iteration order — the same file, on the same
// commit, producing a different SBOM between runs. Sorted order makes
// first-occurrence-wins a rule.
func TestPackagesLockJsonMultiFrameworkIsDeterministic(t *testing.T) {
	first := ""
	for i := 0; i < 20; i++ {
		f, err := os.Open("./testdata/multiframework.packages.lock.json")
		require.NoError(t, err)
		info, err := (&Extractor{}).Parse(f, "packages.lock.json")
		_ = f.Close()
		require.NoError(t, err)

		p := info.Transitive().Find("Contoso.Core")
		require.NotNil(t, p)
		if first == "" {
			first = p.Version
			continue
		}
		require.Equal(t, first, p.Version, "the inventoried version must not depend on map iteration order")
	}
	// net472 sorts before net9.0, so it is the one that wins.
	assert.Equal(t, "1.0.0", first)
}
