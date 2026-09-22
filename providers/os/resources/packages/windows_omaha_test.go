// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/registry"
)

// fakeOmahaRegistry backs omahaChildrenFunc/omahaItemsFunc with canned data,
// so buildOmahaVersions can be exercised without a real Windows registry.
type fakeOmahaRegistry struct {
	children    map[string][]registry.RegistryKeyChild
	childrenErr map[string]error
	items       map[string][]registry.RegistryKeyItem
}

func (f *fakeOmahaRegistry) Children(path string) ([]registry.RegistryKeyChild, error) {
	if err, ok := f.childrenErr[path]; ok {
		return nil, err
	}
	return f.children[path], nil
}

func (f *fakeOmahaRegistry) Items(path string) ([]registry.RegistryKeyItem, error) {
	return f.items[path], nil
}

// TestBuildOmahaVersions pins buildOmahaVersions' happy path: a subkey with a
// valid name+pv pair is read into the map, lowercased, from either root.
func TestBuildOmahaVersions(t *testing.T) {
	fake := &fakeOmahaRegistry{
		children: map[string][]registry.RegistryKeyChild{
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`: {
				{Name: "{8A69D345-D564-463c-AFF1-A69D9E530F96}", Path: `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`},
			},
			`HKLM\SOFTWARE\Google\Update\Clients`: {
				{Name: "{D0AB2EBC-931B-4013-9FEB-C9C4C2225C8C}", Path: `HKLM\SOFTWARE\Google\Update\Clients`},
			},
		},
		items: map[string][]registry.RegistryKeyItem{
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients\{8A69D345-D564-463c-AFF1-A69D9E530F96}`: {
				{Key: "name", Value: sz("Google Chrome")},
				{Key: "pv", Value: sz("153.0.8010.53")},
			},
			`HKLM\SOFTWARE\Google\Update\Clients\{D0AB2EBC-931B-4013-9FEB-C9C4C2225C8C}`: {
				{Key: "name", Value: sz("Google Drive")},
				{Key: "pv", Value: sz("87.0.5.0")},
			},
		},
	}

	got := buildOmahaVersions(omahaClientsNativeRoots, fake.Children, fake.Items)
	assert.Equal(t, map[string]string{
		"google chrome": "153.0.8010.53",
		"google drive":  "87.0.5.0",
	}, got)
}

// TestBuildOmahaVersions_MissingRootIsSilent pins that a root which fails to
// enumerate (the 64-bit Google\Update\Clients view, absent on every host
// verified so far) is skipped rather than aborting the whole read -- the
// Wow6432Node root must still be read.
func TestBuildOmahaVersions_MissingRootIsSilent(t *testing.T) {
	fake := &fakeOmahaRegistry{
		children: map[string][]registry.RegistryKeyChild{
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`: {
				{Name: "{GUID}", Path: `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`},
			},
		},
		childrenErr: map[string]error{
			`HKLM\SOFTWARE\Google\Update\Clients`: errors.New("registry key not found"),
		},
		items: map[string][]registry.RegistryKeyItem{
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients\{GUID}`: {
				{Key: "name", Value: sz("Google Chrome")},
				{Key: "pv", Value: sz("153.0.8010.53")},
			},
		},
	}

	got := buildOmahaVersions(omahaClientsNativeRoots, fake.Children, fake.Items)
	assert.Equal(t, map[string]string{"google chrome": "153.0.8010.53"}, got)
}

// TestBuildOmahaVersions_DropsEmptyOrUnshapedPV is the negative the ticket
// calls out by name: an empty "pv" -- observed on a real VM where the MSI had
// registered an Add/Remove-Programs entry without ever completing the
// product's deploy -- must never enter the map, since applyOmahaVersions
// would otherwise use it to blank out a package's real, good version.
// A "pv" that is present but not version-shaped is dropped the same way.
func TestBuildOmahaVersions_DropsEmptyOrUnshapedPV(t *testing.T) {
	fake := &fakeOmahaRegistry{
		children: map[string][]registry.RegistryKeyChild{
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`: {
				{Name: "{EMPTY}", Path: `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`},
				{Name: "{GARBAGE}", Path: `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`},
				{Name: "{NONAME}", Path: `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`},
				{Name: "{GOOD}", Path: `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`},
			},
		},
		items: map[string][]registry.RegistryKeyItem{
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients\{EMPTY}`: {
				{Key: "name", Value: sz("Google Chrome")},
				{Key: "pv", Value: sz("")},
			},
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients\{GARBAGE}`: {
				{Key: "name", Value: sz("Google Earth")},
				{Key: "pv", Value: sz("not-a-version")},
			},
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients\{NONAME}`: {
				{Key: "pv", Value: sz("1.2.3")},
			},
			`HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients\{GOOD}`: {
				{Key: "name", Value: sz("GCPW")},
				{Key: "pv", Value: sz("125.0.6422.60")},
			},
		},
	}

	got := buildOmahaVersions(omahaClientsNativeRoots, fake.Children, fake.Items)
	assert.Equal(t, map[string]string{"gcpw": "125.0.6422.60"}, got,
		"empty pv, non-version pv, and a missing name must all be dropped")
}

// TestParseOmahaClientsOutput_Array is the ordinary multi-product shape:
// ConvertTo-Json renders more than one result as a JSON array.
func TestParseOmahaClientsOutput_Array(t *testing.T) {
	const data = `[{"name":"Google Chrome","pv":"153.0.8010.53"},{"name":"Google Drive","pv":"87.0.5.0"}]`
	got, err := parseOmahaClientsOutput(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"google chrome": "153.0.8010.53",
		"google drive":  "87.0.5.0",
	}, got)
}

// TestParseOmahaClientsOutput_SingleObjectCollapse pins the ConvertTo-Json
// quirk this parser exists to survive: with exactly one result -- the live
// shape on every VM this was verified against, which has only Chrome
// installed under Omaha -- ConvertTo-Json renders a bare JSON object instead
// of a one-element array. Without the fallback, json.Unmarshal into a slice
// fails and every Omaha-managed package on that host silently keeps its
// stale ARP version.
func TestParseOmahaClientsOutput_SingleObjectCollapse(t *testing.T) {
	const data = `{"name":"Google Chrome","pv":"153.0.8010.53"}`
	got, err := parseOmahaClientsOutput(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"google chrome": "153.0.8010.53"}, got)
}

// TestParseOmahaClientsOutput_Empty pins that no output (ConvertTo-Json
// writes nothing for an empty collection) parses as an empty map, not an
// error.
func TestParseOmahaClientsOutput_Empty(t *testing.T) {
	got, err := parseOmahaClientsOutput(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestParseOmahaClientsOutput_Malformed pins that genuinely invalid JSON
// (neither an array nor a single object) is reported as an error rather than
// silently swallowed.
func TestParseOmahaClientsOutput_Malformed(t *testing.T) {
	_, err := parseOmahaClientsOutput(strings.NewReader("not json at all"))
	assert.Error(t, err)
}

// TestApplyOmahaVersions_RewritesMatchingPackage is the ticket's core case:
// a stale Add/Remove-Programs entry frozen at the raw MSI ProductVersion
// (observed live: "69.218.16502") is rewritten to Google Update's own "pv",
// and the rewrite reaches the purl and the CPEs, not just Version -- the
// task's explicit correctness requirement, since PUrl/CPE are what
// vulnerability matching and SBOM export actually key on.
func TestApplyOmahaVersions_RewritesMatchingPackage(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	pkgs := []Package{
		*createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform),
	}
	omahaVersions := map[string]string{"google chrome": "153.0.8010.53"}

	applyOmahaVersions(pkgs, omahaVersions, platform)

	assert.Equal(t, "153.0.8010.53", pkgs[0].Version)
	assert.Equal(t, "pkg:windows/windows/Google%20Chrome@153.0.8010.53?arch=arm64", pkgs[0].PUrl)
	require.NotEmpty(t, pkgs[0].CPEs, "CPEs must be rebuilt, not left at the stale version")
	for _, c := range pkgs[0].CPEs {
		assert.Contains(t, c, "153.0.8010.53")
		assert.NotContains(t, c, "69.218.16502")
	}
}

// TestApplyOmahaVersions_NoMatchLeavesPackageUntouched is the negative the
// ticket calls out by name: an app Omaha does not track must be left
// completely alone, byte for byte.
func TestApplyOmahaVersions_NoMatchLeavesPackageUntouched(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	original := *createPackage("Notepad++", "8.6.9", "windows/app", "arm64", "Notepad++ Team", "", platform)
	pkgs := []Package{original}
	omahaVersions := map[string]string{"google chrome": "153.0.8010.53"}

	applyOmahaVersions(pkgs, omahaVersions, platform)

	assert.Equal(t, original, pkgs[0])
}

// TestApplyOmahaVersions_EmptyMapIsNoop pins the other negative the ticket
// calls out: an empty Omaha map (no Omaha-managed products found, or the
// read failed and was logged-and-skipped) must never touch a package.
func TestApplyOmahaVersions_EmptyMapIsNoop(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	original := *createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform)
	pkgs := []Package{original}

	applyOmahaVersions(pkgs, nil, platform)

	assert.Equal(t, original, pkgs[0], "an empty/nil Omaha map must never blank or alter a version")
}

// TestApplyOmahaVersions_SkipsNonWindowsAppFormat pins that the rewrite is
// scoped to "windows/app" packages: an appx or hotfix package that happens to
// carry a name Omaha also tracks must not be touched, since Omaha only ever
// describes the Add/Remove-Programs (ARP) view of a product.
func TestApplyOmahaVersions_SkipsNonWindowsAppFormat(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	original := Package{Name: "Google Chrome", Version: "69.218.16502", Format: "windows/appx", PUrl: "pkg:appx/windows/Google%20Chrome@69.218.16502"}
	pkgs := []Package{original}
	omahaVersions := map[string]string{"google chrome": "153.0.8010.53"}

	applyOmahaVersions(pkgs, omahaVersions, platform)

	assert.Equal(t, original, pkgs[0])
}

// TestApplyOmahaVersions_CaseInsensitiveNameMatch pins that the match is
// case-insensitive (Omaha's own "name" value and the ARP DisplayName have
// been observed to match exactly, but the lookup itself lowercases both
// sides) while still being an exact match, never fuzzy.
func TestApplyOmahaVersions_CaseInsensitiveNameMatch(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	pkgs := []Package{
		*createPackage("GOOGLE CHROME", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform),
	}
	omahaVersions := map[string]string{"google chrome": "153.0.8010.53"}

	applyOmahaVersions(pkgs, omahaVersions, platform)

	assert.Equal(t, "153.0.8010.53", pkgs[0].Version)
}
