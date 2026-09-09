// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemfilelock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestGemfileLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.Gemfile.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "path/to/Gemfile.lock")
	require.NoError(t, err)

	assert.Nil(t, info.Root())

	// Direct dependencies (from DEPENDENCIES section)
	direct := info.Direct()
	assert.Equal(t, 3, len(direct))

	p := direct.Find("actioncable")
	require.NotNil(t, p)
	assert.Equal(t, "7.1.3", p.Version)
	assert.Equal(t, "pkg:gem/actioncable@7.1.3", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: "path/to/Gemfile.lock"}}, p.EvidenceList)

	p = direct.Find("puma")
	require.NotNil(t, p)
	assert.Equal(t, "6.4.2", p.Version)

	p = direct.Find("nokogiri")
	require.NotNil(t, p)
	assert.Equal(t, "1.16.2", p.Version) // platform suffix stripped

	// Transitive deps should NOT be in direct
	assert.Nil(t, direct.Find("rack"))
	assert.Nil(t, direct.Find("nio4r"))

	// Transitive = all gems
	transitive := info.Transitive()
	assert.Equal(t, 8, len(transitive))

	p = transitive.Find("rack")
	require.NotNil(t, p)
	assert.Equal(t, "3.0.8", p.Version)
	assert.Equal(t, "pkg:gem/rack@3.0.8", p.Purl)

	p = transitive.Find("nio4r")
	require.NotNil(t, p)
	assert.Equal(t, "2.7.0", p.Version)

	p = transitive.Find("websocket-extensions")
	require.NotNil(t, p)
	assert.Equal(t, "0.1.5", p.Version)
}

func TestParseGemEntry(t *testing.T) {
	assert.Equal(t, gemEntry{Name: "rack", Version: "3.0.8"}, parseGemEntry("rack (3.0.8)"))
	assert.Equal(t, gemEntry{Name: "nokogiri", Version: "1.16.2"}, parseGemEntry("nokogiri (1.16.2-x86_64-linux)"))
	assert.Equal(t, gemEntry{Name: "puma", Version: "6.4.2"}, parseGemEntry("puma (6.4.2)"))
	assert.Equal(t, gemEntry{}, parseGemEntry("invalid line"))
}

// TestGemfileLockDependencyEdges pins the RubyGems package->package graph.
//
// Bundler writes each gem's own dependencies beneath it in the specs section,
// and the parser skipped every line indented past the gem — so a consumer saw
// which gems a project resolves and nothing about which of them any other gem
// pulls in.
func TestGemfileLockDependencyEdges(t *testing.T) {
	f, err := os.Open("./testdata/simple.Gemfile.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "Gemfile.lock")
	require.NoError(t, err)
	all := info.Transitive()

	ac := all.Find("actioncable")
	require.NotNil(t, ac)
	// `nio4r (~> 2.0)` is a REQUIREMENT; 2.7.0 is what Bundler resolved, and it
	// is on nio4r's own spec entry. An edge built from the requirement would
	// name pkg:gem/nio4r@2.0 — a package that is not in this inventory, so the
	// edge would point at nothing.
	assert.Equal(t, []string{
		"pkg:gem/actionpack@7.1.3",
		"pkg:gem/nio4r@2.7.0",
		"pkg:gem/websocket-driver@0.7.6",
	}, ac.DependsOn, "edges resolve by name against the gem set, not from the requirement")

	assert.Equal(t, []string{"pkg:gem/rack@3.0.8"}, all.Find("actionpack").DependsOn)
	assert.Equal(t, []string{"pkg:gem/websocket-extensions@0.1.5"}, all.Find("websocket-driver").DependsOn)
	assert.Equal(t, []string{"pkg:gem/nio4r@2.7.0"}, all.Find("puma").DependsOn)

	// A leaf gem states no dependencies and carries no edges, so "depends on
	// nothing" and "was never read" stay distinct downstream.
	assert.Nil(t, all.Find("rack").DependsOn)
	assert.Nil(t, all.Find("nokogiri").DependsOn)

	// Direct() must report the same graph as Transitive(): it is the same gem.
	direct := info.Direct()
	require.NotNil(t, direct.Find("actioncable"))
	assert.Equal(t, ac.DependsOn, direct.Find("actioncable").DependsOn)
}

// TestGemfileLockDependencyLinesAreNotGems is the other half of reading those
// lines: they must feed the graph WITHOUT becoming packages. Counting
// `nio4r (~> 2.0)` as a gem would inventory a version the project does not
// install, three times over in this fixture.
func TestGemfileLockDependencyLinesAreNotGems(t *testing.T) {
	f, err := os.Open("./testdata/simple.Gemfile.lock")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, "Gemfile.lock")
	require.NoError(t, err)

	all := info.Transitive()
	assert.Equal(t, 8, len(all), "the specs section resolves 8 gems; dependency lines are edges, not entries")
	for _, p := range all {
		assert.NotContains(t, p.Version, "~", "a requirement must never become a version")
		assert.NotContains(t, p.Version, ">", "a requirement must never become a version")
	}
}

func TestGemDepName(t *testing.T) {
	cases := map[string]string{
		"rack (~> 2.2)":               "rack",
		"rack":                        "rack",
		"actionpack (= 7.1.3)":        "actionpack",
		"websocket-driver (>= 0.6.1)": "websocket-driver",
		"mygem!":                      "mygem",
		"":                            "",
	}
	for in, want := range cases {
		assert.Equal(t, want, gemDepName(in), "gemDepName(%q)", in)
	}
}
