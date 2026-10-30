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

// machineScoped marks a package as the machine-wide install the registry
// walk would have reported it as. applyOmahaVersions only rewrites
// machine-scope rows (the versions it reads come from HKLM), so a fixture
// with no scope would be skipped for a reason the test is not about.
func machineScoped(p *Package) *Package {
	p.InstallScope = installScopeMachine
	return p
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
		*machineScoped(createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform)),
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
	original := *machineScoped(createPackage("Notepad++", "8.6.9", "windows/app", "arm64", "Notepad++ Team", "", platform))
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
	original := *machineScoped(createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform))
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
	original := Package{Name: "Google Chrome", Version: "69.218.16502", Format: "windows/appx", InstallScope: installScopeMachine, PUrl: "pkg:appx/windows/Google%20Chrome@69.218.16502"}
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
		*machineScoped(createPackage("GOOGLE CHROME", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform)),
	}
	omahaVersions := map[string]string{"google chrome": "153.0.8010.53"}

	applyOmahaVersions(pkgs, omahaVersions, platform)

	assert.Equal(t, "153.0.8010.53", pkgs[0].Version)
}

// TestApplyOmahaVersions_SkipsUserScopedInstall is the guard against the
// worst failure this feature can produce. The versions come from HKLM, so
// they describe the machine-wide install; a per-user install of the same
// product keeps its own Google Update state under HKCU, which is not read.
// Stamping the machine version onto a user's row would describe a genuinely
// out-of-date browser as patched and clear its findings.
func TestApplyOmahaVersions_SkipsUserScopedInstall(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	userChrome := *createPackage("Google Chrome", "140.0.7339.16", "windows/app", "arm64", "Google LLC", "", platform)
	userChrome.InstallScope = installScopeUser
	userChrome.InstallUser = "S-1-5-21-1111111111-2222222222-3333333333-1001"

	machineChrome := *machineScoped(createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform))

	pkgs := []Package{userChrome, machineChrome}
	applyOmahaVersions(pkgs, map[string]string{"google chrome": "153.0.8010.53"}, platform)

	assert.Equal(t, "140.0.7339.16", pkgs[0].Version, "a user's own install keeps its own version")
	assert.Contains(t, pkgs[0].PUrl, "140.0.7339.16", "and its purl must not claim the machine version")
	assert.Equal(t, "153.0.8010.53", pkgs[1].Version, "the machine-wide row is still repaired")
}

// TestUsableOmahaVersion covers what may replace a real DisplayVersion.
// Overwriting one with a value that identifies nothing is strictly worse than
// leaving it stale: the stale value at least came from the product's installer.
func TestUsableOmahaVersion(t *testing.T) {
	tests := []struct {
		pv     string
		want   bool
		reason string
	}{
		{"153.0.8010.53", true, "a real Chrome pv, read off a live host"},
		{"87.0.5.0", true, "trailing zero component is still a real version"},
		{"v1.2.3", true, "leading v is decoration, not a rejection"},
		{"", false, "observed live: Clients subkey present, pv empty, browser never deployed"},
		{"not-a-version", false, "not version-shaped"},
		{"0.0.0.0", false, "Omaha's registered-but-not-installed sentinel"},
		{"0.0", false, "same sentinel, fewer components"},
		{"0", false, "same sentinel, one component"},
	}
	for _, test := range tests {
		t.Run(test.pv, func(t *testing.T) {
			assert.Equal(t, test.want, usableOmahaVersion(test.pv), test.reason)
		})
	}
}

// TestBuildOmahaVersions_CaseInsensitiveValueNames pins that the value names
// are matched case-insensitively. Both registry readers compare value names
// case-sensitively (RegistryHandler.GetNativeRegistryKeyItems says so in its
// own doc comment), so a hive restored from a .reg export carrying Name/PV
// would otherwise yield two empty strings and silently disable the feature.
func TestBuildOmahaVersions_CaseInsensitiveValueNames(t *testing.T) {
	root := `HKLM\SOFTWARE\Wow6432Node\Google\Update\Clients`
	fake := &fakeOmahaRegistry{
		children: map[string][]registry.RegistryKeyChild{
			root: {{Name: "{8A69D345-D564-463c-AFF1-A69D9E530F96}", Path: root}},
		},
		items: map[string][]registry.RegistryKeyItem{
			root + `\{8A69D345-D564-463c-AFF1-A69D9E530F96}`: {
				{Key: "Name", Value: sz("Google Chrome")},
				{Key: "PV", Value: sz("153.0.8010.53")},
			},
		},
	}

	got := buildOmahaVersions([]string{root}, fake.Children, fake.Items)
	assert.Equal(t, map[string]string{"google chrome": "153.0.8010.53"}, got)
}

// TestBuildOmahaVersions_FirstRootWins pins the precedence rule for a host
// with the same product in both registry views, which is what Google Update's
// 32->64-bit transition leaves behind. Without a rule the winner is decided by
// loop order, which nobody can reason about; with one it is at least stable.
func TestBuildOmahaVersions_FirstRootWins(t *testing.T) {
	wow, native := omahaClientsNativeRoots[0], omahaClientsNativeRoots[1]
	fake := &fakeOmahaRegistry{
		children: map[string][]registry.RegistryKeyChild{
			wow:    {{Name: "{8A69D345}", Path: wow}},
			native: {{Name: "{8A69D345}", Path: native}},
		},
		items: map[string][]registry.RegistryKeyItem{
			wow + `\{8A69D345}`: {
				{Key: "name", Value: sz("Google Chrome")},
				{Key: "pv", Value: sz("153.0.8010.53")},
			},
			native + `\{8A69D345}`: {
				{Key: "name", Value: sz("Google Chrome")},
				{Key: "pv", Value: sz("120.0.6099.110")},
			},
		},
	}

	got := buildOmahaVersions(omahaClientsNativeRoots, fake.Children, fake.Items)
	assert.Equal(t, "153.0.8010.53", got["google chrome"], "the first root's value survives the second's")
}

// TestBuildOmahaVersions_ReadsChildPathVerbatim pins the wiring contract that
// the offline/filesystem path got wrong: the children come back carrying a
// FULLY-QUALIFIED Path, so the per-subkey read must use that path as-is. The
// offline closure re-resolved the hive root onto it, producing
// HKLM\TmpReg_SOFTWARE\HKLM\TmpReg_SOFTWARE\..., every read missed, and the
// map came back empty on every device/image scan with no error and no log.
func TestBuildOmahaVersions_ReadsChildPathVerbatim(t *testing.T) {
	// The shape RegistryHandler produces: Path already carries the resolved
	// hive root, and the subkey is only reachable at exactly that path.
	root := `HKLM\TmpReg_SOFTWARE\Wow6432Node\Google\Update\Clients`
	fake := &fakeOmahaRegistry{
		children: map[string][]registry.RegistryKeyChild{
			root: {{Name: "{8A69D345}", Path: root}},
		},
		items: map[string][]registry.RegistryKeyItem{
			root + `\{8A69D345}`: {
				{Key: "name", Value: sz("Google Chrome")},
				{Key: "pv", Value: sz("153.0.8010.53")},
			},
		},
	}

	got := buildOmahaVersions([]string{root}, fake.Children, fake.Items)
	assert.Equal(t, "153.0.8010.53", got["google chrome"],
		"the child's own Path must be used unchanged, never re-prefixed")
}

// TestConvergeOmahaArch_PromotesX86WhenHostArchSiblingExists covers the other
// half of the duplicate. Google Update is 32-bit, so the entry it registers
// lands under Wow6432Node and is labelled x86, while the 64-bit MSI's entry
// for the SAME install is labelled with the host arch. Equal versions are not
// enough to collapse them: the arch reaches the purl.
func TestConvergeOmahaArch_PromotesX86WhenHostArchSiblingExists(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	pkgs := []Package{
		*machineScoped(createPackage("Google Chrome", "153.0.8010.53", "windows/app", "x86", "Google LLC", "", platform)),
		*machineScoped(createPackage("Google Chrome", "153.0.8010.53", "windows/app", "arm64", "Google LLC", "", platform)),
	}

	convergeOmahaArch(pkgs, map[string]string{"google chrome": "153.0.8010.53"}, platform)

	assert.Equal(t, "arm64", pkgs[0].Arch, "the Wow6432Node label describes the updater, not the product")
	assert.Equal(t, pkgs[1].PUrl, pkgs[0].PUrl, "both rows must converge on one identity")
	assert.Len(t, collapsePackages(pkgs), 1, "and therefore collapse to one package")
}

// TestConvergeOmahaArch_LeavesLoneX86Alone is what keeps the promotion above
// honest. A genuinely 32-bit install on a 64-bit host is a real thing, and
// with no host-arch sibling there is no evidence of a 64-bit install to
// prefer -- promoting it would invent a fact about the machine.
func TestConvergeOmahaArch_LeavesLoneX86Alone(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	original := *machineScoped(createPackage("Google Chrome", "153.0.8010.53", "windows/app", "x86", "Google LLC", "", platform))
	pkgs := []Package{original}

	convergeOmahaArch(pkgs, map[string]string{"google chrome": "153.0.8010.53"}, platform)

	assert.Equal(t, original, pkgs[0], "no sibling, no evidence, no change")
}

// TestConvergeOmahaArch_DifferentVersionIsNotASibling pins that the sibling
// match is on the whole install identity, not just the name: a leftover 32-bit
// install at an older version is a different install and must keep its arch.
func TestConvergeOmahaArch_DifferentVersionIsNotASibling(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	pkgs := []Package{
		*machineScoped(createPackage("Google Chrome", "120.0.6099.110", "windows/app", "x86", "Google LLC", "", platform)),
		*machineScoped(createPackage("Google Chrome", "153.0.8010.53", "windows/app", "arm64", "Google LLC", "", platform)),
	}

	convergeOmahaArch(pkgs, map[string]string{"google chrome": "153.0.8010.53"}, platform)

	assert.Equal(t, "x86", pkgs[0].Arch, "a different version is a different install")
	assert.Len(t, collapsePackages(pkgs), 2)
}

// TestApplyOmahaVersions_ConvergesArchNotJustVersion pins the WIRING, not just
// convergeOmahaArch itself. Repairing the version alone does not remove the
// duplicate: the two rows still differ in arch, the arch reaches the purl, and
// collapsePackages keeps both. Calling convergeOmahaArch directly cannot catch
// a caller that never calls it, which is the failure this test exists for.
//
// The fixture is the ticket's own shape with the registry views it really
// has: Google Update is 32-bit, so the entry it maintains is labelled x86,
// while the MSI's stale twin sits in the native view at the host arch.
func TestApplyOmahaVersions_ConvergesArchNotJustVersion(t *testing.T) {
	platform := &inventory.Platform{Name: "windows", Arch: "arm64", Family: []string{"windows"}}
	pkgs := []Package{
		*machineScoped(createPackage("Google Chrome", "152.0.7933.0", "windows/app", "x86", "Google LLC", "", platform)),
		*machineScoped(createPackage("Google Chrome", "69.218.16502", "windows/app", "arm64", "Google LLC", "", platform)),
	}

	applyOmahaVersions(pkgs, map[string]string{"google chrome": "153.0.8010.53"}, platform)

	assert.Equal(t, pkgs[1].PUrl, pkgs[0].PUrl, "one install must end as one identity")
	collapsed := collapsePackages(pkgs)
	require.Len(t, collapsed, 1, "the duplicate the ticket reports must be gone")
	assert.Equal(t, "153.0.8010.53", collapsed[0].Version)
}
