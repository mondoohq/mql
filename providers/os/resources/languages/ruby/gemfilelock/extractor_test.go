// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemfilelock

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
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

func parseLockFile(t *testing.T, name string) *gemfileLock {
	t.Helper()
	f, err := os.Open(name)
	require.NoError(t, err)
	defer f.Close()
	lock, err := parseGemfileLock(f)
	require.NoError(t, err)
	return lock
}

func packageNames(pkgs []*languages.Package) []string {
	out := []string{}
	for _, p := range pkgs {
		out = append(out, p.Name+"@"+p.Version)
	}
	sort.Strings(out)
	return out
}

// A lock written by Bundler 4.0 (CHECKSUMS after DEPENDENCIES) for a Rails
// app with one gem from a git source. Only the six gems under DEPENDENCIES are
// direct: the CHECKSUMS lines name every gem in the lock and must not extend
// the DEPENDENCIES section. The git-sourced rack-test is installed like any
// other gem and belongs in the inventory.
func TestGemfileLockChecksumsAndGitSource(t *testing.T) {
	lock := parseLockFile(t, "testdata/bundler4-checksums-git.Gemfile.lock")

	assert.Equal(t, []string{
		"nokogiri@1.11.0", "puma@5.6.9", "rack-test@1.1.0", "rack@2.2.3", "rails@6.1.4", "rspec@3.10.0",
	}, packageNames(lock.Direct()))

	all := lock.Transitive()
	assert.Len(t, all, 58, "57 GEM specs and 1 GIT spec")
	rackTest := all.Find("rack-test")
	require.NotNil(t, rackTest)
	assert.Equal(t, "1.1.0", rackTest.Version)
	assert.Equal(t, "pkg:gem/rack-test@1.1.0", rackTest.Purl)
	assert.Equal(t, []string{"pkg:gem/rack@2.2.3"}, rackTest.DependsOn)

	// actionpack depends on rack-test, which now resolves to the git gem
	assert.Contains(t, all.Find("actionpack").DependsOn, "pkg:gem/rack-test@1.1.0")

	assert.Equal(t, "4.0.20", lock.BundledWith)
}

// A PATH source and a RUBY VERSION section after DEPENDENCIES.
func TestGemfileLockPathSourceAndRubyVersion(t *testing.T) {
	lock := parseLockFile(t, "testdata/path-ruby-version.Gemfile.lock")

	assert.Equal(t, []string{"billing@0.4.0", "money@6.19.0"}, packageNames(lock.Direct()))
	assert.Equal(t, []string{"billing@0.4.0", "concurrent-ruby@1.3.3", "i18n@1.14.5", "money@6.19.0"}, packageNames(lock.Transitive()))
	assert.False(t, lock.DirectDeps["ruby"], "the RUBY VERSION line is not a dependency")
	assert.Equal(t, []string{"pkg:gem/money@6.19.0"}, lock.Transitive().Find("billing").DependsOn)
	assert.Equal(t, "2.4.22", lock.BundledWith)
}

// rails 7.1's Gemfile.lock, resolved for three platforms, lists nokogiri once
// per platform. With the platform stripped that is the same gem three times,
// and ruby.packages reported three packages with one id. Fails if the entries
// are no longer merged, or if a platform entry's dependency lines are
// attached to the wrong gem.
func TestGemfileLockMergesPlatformVariants(t *testing.T) {
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.4)
    nokogiri (1.15.4)
      mini_portile2 (~> 2.8.2)
      racc (~> 1.4)
    nokogiri (1.15.4-x86_64-darwin)
      racc (~> 1.4)
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.1)

PLATFORMS
  ruby
  x86_64-darwin
  x86_64-linux

DEPENDENCIES
  nokogiri
`
	bom, err := (&Extractor{}).Parse(strings.NewReader(lock), "Gemfile.lock")
	require.NoError(t, err)

	var ids []string
	for _, p := range bom.Transitive() {
		ids = append(ids, p.Name+"@"+p.Version)
	}
	assert.Equal(t, []string{"mini_portile2@2.8.4", "nokogiri@1.15.4", "racc@1.7.1"}, ids)

	direct := bom.Direct()
	require.Len(t, direct, 1)
	assert.Equal(t, []string{"pkg:gem/mini_portile2@2.8.4", "pkg:gem/racc@1.7.1"}, direct[0].DependsOn)
}
