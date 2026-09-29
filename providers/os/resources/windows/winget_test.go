// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Package full names below follow the AppX full-name format
// <Name>_<Version>_<Architecture>_<ResourceId>_<PublisherId>. The names,
// versions, and architectures of App Installer 1.29.380.0 and its three
// framework dependencies are taken from the winget-cli v1.29.380 release
// (Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle and
// DesktopAppInstaller_Dependencies.zip).
const (
	wingetX64     = "Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe"
	wingetArm64   = "Microsoft.DesktopAppInstaller_1.29.380.0_arm64__8wekyb3d8bbwe"
	wingetBundle  = "Microsoft.DesktopAppInstaller_1.29.380.0_neutral_~_8wekyb3d8bbwe"
	wingetOldX64  = "Microsoft.DesktopAppInstaller_1.28.240.0_x64__8wekyb3d8bbwe"
	vclibsX64     = "Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe"
	vclibsX86     = "Microsoft.VCLibs.140.00_14.0.33519.0_x86__8wekyb3d8bbwe"
	uwpDesktopX64 = "Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__8wekyb3d8bbwe"
	appRuntimeX64 = "Microsoft.WindowsAppRuntime.1.8_8000.616.304.0_x64__8wekyb3d8bbwe"
)

// The Identity and Dependencies elements of AppxManifest.xml from the x64
// package in the winget-cli v1.29.380 msixbundle, cut after Dependencies.
func loadWingetManifest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/winget/AppxManifest_1.29.380.0_x64.xml")
	require.NoError(t, err)
	return string(data)
}

func TestParseAppxFullName(t *testing.T) {
	id, ok := ParseAppxFullName(wingetX64)
	require.True(t, ok)
	assert.Equal(t, AppxPackageID{
		Name:         "Microsoft.DesktopAppInstaller",
		Version:      "1.29.380.0",
		Architecture: "x64",
		ResourceID:   "",
		PublisherID:  "8wekyb3d8bbwe",
	}, id)

	id, ok = ParseAppxFullName(wingetBundle)
	require.True(t, ok)
	assert.Equal(t, "neutral", id.Architecture)
	assert.Equal(t, "~", id.ResourceID)

	for _, bad := range []string{"", "Deleted", "Microsoft.DesktopAppInstaller_1.29.380_x64__8wekyb3d8bbwe", "a_b_c"} {
		_, ok := ParseAppxFullName(bad)
		assert.False(t, ok, bad)
	}
}

func TestCompareAppxVersionIsNumeric(t *testing.T) {
	// a string comparison would order 1.9 after 1.10
	assert.Equal(t, 1, compareAppxVersion("1.10.0.0", "1.9.0.0"))
	assert.Equal(t, -1, compareAppxVersion("1.28.240.0", "1.29.380.0"))
	assert.Equal(t, 0, compareAppxVersion("1.29.380.0", "1.29.380.0"))
	assert.Equal(t, 1, compareAppxVersion("1.0.0.0", "garbage"))
}

func TestSelectWingetCandidate(t *testing.T) {
	t.Run("single directory", func(t *testing.T) {
		c, id, ok := SelectWingetCandidate([]WingetCandidate{
			{FullName: wingetX64, HasExe: true},
		}, "AMD64")
		require.True(t, ok)
		assert.Equal(t, wingetX64, c.FullName)
		assert.Equal(t, "1.29.380.0", id.Version)
	})

	t.Run("newest version wins regardless of order", func(t *testing.T) {
		c, _, ok := SelectWingetCandidate([]WingetCandidate{
			{FullName: wingetX64, HasExe: true},
			{FullName: wingetOldX64, HasExe: true},
		}, "AMD64")
		require.True(t, ok)
		assert.Equal(t, wingetX64, c.FullName)
	})

	t.Run("a folder without winget.exe does not count", func(t *testing.T) {
		c, _, ok := SelectWingetCandidate([]WingetCandidate{
			{FullName: wingetX64, HasExe: false},
			{FullName: wingetOldX64, HasExe: true},
			{FullName: wingetBundle, HasExe: true},
		}, "AMD64")
		require.True(t, ok)
		assert.Equal(t, wingetOldX64, c.FullName)
	})

	t.Run("an x64 machine cannot run the arm64 package", func(t *testing.T) {
		_, _, ok := SelectWingetCandidate([]WingetCandidate{
			{FullName: wingetArm64, HasExe: true},
		}, "AMD64")
		assert.False(t, ok)
	})

	t.Run("arm64 machine prefers native on a tie", func(t *testing.T) {
		c, _, ok := SelectWingetCandidate([]WingetCandidate{
			{FullName: wingetX64, HasExe: true},
			{FullName: wingetArm64, HasExe: true},
		}, "ARM64")
		require.True(t, ok)
		assert.Equal(t, wingetArm64, c.FullName)
	})

	t.Run("nothing found", func(t *testing.T) {
		_, _, ok := SelectWingetCandidate(nil, "AMD64")
		assert.False(t, ok)
	})
}

func TestParseWingetState(t *testing.T) {
	// Windows PowerShell flattens a one-element array into the element and
	// serializes @() results as {"value":[...],"Count":n}; both must decode.
	in := `{"MachineArch":"AMD64","Packages":{"value":["` + wingetX64 + `","` + vclibsX64 + `"],"Count":2},` +
		`"Candidates":{"FullName":"` + wingetX64 + `","Root":"C:\\Program Files\\WindowsApps\\` + wingetX64 + `","HasExe":true,"Manifest":null},` +
		`"Policy":{"EnableAppInstaller":0,"EnableDefaultSource":null,"AdditionalSources":[],"AllowedSources":"{}"},` +
		`"UserSources":null}`
	s, err := ParseWingetState(strings.NewReader(in))
	require.NoError(t, err)
	assert.Equal(t, "AMD64", s.MachineArch)
	assert.Equal(t, PSStringArray{wingetX64, vclibsX64}, s.Packages)
	require.Len(t, s.Candidates, 1)
	assert.True(t, s.Candidates[0].HasExe)
	assert.Equal(t, `C:\Program Files\WindowsApps\`+wingetX64, s.Candidates[0].Root)
	require.NotNil(t, s.Policy)
	require.NotNil(t, s.Policy.EnableAppInstaller)
	assert.Nil(t, s.Policy.EnableDefaultSource)
	assert.False(t, s.Policy.Enabled())
	assert.Nil(t, s.UserSources)

	_, err = ParseWingetState(strings.NewReader("  "))
	assert.Error(t, err)
}

// Windows PowerShell 5.1 writes file contents read with Get-Content as objects
// unless the script casts them to [string]. The payload must still decode, and
// the file text must come through.
func TestParseWingetStatePowerShell51Strings(t *testing.T) {
	in := `{"MachineArch":"ARM64","Packages":["` + wingetArm64 + `"],` +
		`"Candidates":[{"FullName":"` + wingetArm64 + `","Root":"C:\\Program Files\\WindowsApps\\` + wingetArm64 + `","HasExe":true,` +
		`"ExeVersion":"1.29.380.0","Manifest":` + psGetContentString + `}],` +
		`"Policy":null,"UserSources":` + psGetContentString + `}`
	s, err := ParseWingetState(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, s.Candidates, 1)
	assert.Equal(t, PSString("<Package/>\r\n"), s.Candidates[0].Manifest)
	assert.Equal(t, PSString("1.29.380.0"), s.Candidates[0].ExeVersion)
	require.NotNil(t, s.UserSources)
	assert.Equal(t, PSString("<Package/>\r\n"), *s.UserSources)
}

func TestParseAppxDependencies(t *testing.T) {
	deps, err := ParseAppxDependencies(loadWingetManifest(t))
	require.NoError(t, err)
	assert.Equal(t, []AppxDependency{
		{Name: "Microsoft.WindowsAppRuntime.1.8", MinVersion: "8000.616.304.0", Publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"},
		{Name: "Microsoft.VCLibs.140.00", MinVersion: "14.0.33519.0", Publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"},
		{Name: "Microsoft.VCLibs.140.00.UWPDesktop", MinVersion: "14.0.33728.0", Publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"},
	}, deps)

	_, err = ParseAppxDependencies("<Package><Dependencies>")
	assert.Error(t, err)
}

func TestMissingDependencies(t *testing.T) {
	deps, err := ParseAppxDependencies(loadWingetManifest(t))
	require.NoError(t, err)

	t.Run("all present", func(t *testing.T) {
		missing := MissingDependencies(deps, []string{wingetX64, vclibsX64, uwpDesktopX64, appRuntimeX64}, "x64")
		assert.Empty(t, missing)
		assert.NotNil(t, missing)
	})

	t.Run("missing framework", func(t *testing.T) {
		missing := MissingDependencies(deps, []string{wingetX64, vclibsX64, uwpDesktopX64}, "x64")
		assert.Equal(t, []string{"Microsoft.WindowsAppRuntime.1.8 >= 8000.616.304.0"}, missing)
	})

	t.Run("framework only for another architecture", func(t *testing.T) {
		missing := MissingDependencies(deps, []string{vclibsX86, uwpDesktopX64, appRuntimeX64}, "x64")
		assert.Equal(t, []string{"Microsoft.VCLibs.140.00 >= 14.0.33519.0"}, missing)
	})

	t.Run("framework too old", func(t *testing.T) {
		old := "Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe"
		missing := MissingDependencies(deps, []string{vclibsX64, old, appRuntimeX64}, "x64")
		assert.Equal(t, []string{"Microsoft.VCLibs.140.00.UWPDesktop >= 14.0.33728.0"}, missing)
	})
}

func sourceNames(sources []WingetSource) []string {
	out := make([]string, len(sources))
	for i, s := range sources {
		out[i] = s.Origin + ":" + s.Name
	}
	return out
}

// userSourcesDoc is laid out the way winget's YAML emitter writes the
// user_sources setting (keys in the order SourceList.cpp emits them).
const userSourcesDoc = `Sources:
  - Name: contoso
    Type: Microsoft.Rest
    Arg: https://pkgs.contoso.example/api
    Data: ""
    Identifier: contoso
    IsTombstone: false
    IsOverride: false
    Explicit: false
    TrustLevel: 0
    Priority: 0
  - Name: msstore
    Type: Microsoft.Rest
    Arg: https://storeedgefd.dsx.mp.microsoft.com/v9.0
    Data: ""
    Identifier: StoreEdgeFD
    IsTombstone: true
    IsOverride: false
    Explicit: false
    TrustLevel: 0
    Priority: 0`

func int64p(v int64) *int64 { return &v }

func TestResolveWingetSources(t *testing.T) {
	t.Run("defaults only", func(t *testing.T) {
		got := ResolveWingetSources(nil, nil)
		assert.Equal(t, []string{"default:msstore", "default:winget", "default:winget-font"}, sourceNames(got))
		assert.Equal(t, "https://cdn.winget.microsoft.com/cache", got[1].URL)
		assert.Equal(t, "Microsoft.PreIndexed.Package", got[1].Type)
		assert.True(t, got[2].Explicit)
	})

	t.Run("user source added and default removed", func(t *testing.T) {
		doc := userSourcesDoc
		got := ResolveWingetSources(nil, &doc)
		assert.Equal(t, []string{"user:contoso", "default:winget", "default:winget-font"}, sourceNames(got))
		assert.Equal(t, "https://pkgs.contoso.example/api", got[0].URL)
	})

	t.Run("policy requiring msstore ignores the tombstone", func(t *testing.T) {
		doc := userSourcesDoc
		got := ResolveWingetSources(&WingetPolicy{EnableMicrosoftStoreSource: int64p(1)}, &doc)
		assert.Equal(t, []string{"user:contoso", "default:msstore", "default:winget", "default:winget-font"}, sourceNames(got))
	})

	t.Run("policy disables the default source and blocks user sources", func(t *testing.T) {
		doc := userSourcesDoc
		got := ResolveWingetSources(&WingetPolicy{EnableDefaultSource: int64p(0), EnableAllowedSources: int64p(0)}, &doc)
		assert.Equal(t, []string{"default:winget-font"}, sourceNames(got))
	})

	t.Run("allowed list admits only listed sources", func(t *testing.T) {
		doc := userSourcesDoc
		p := &WingetPolicy{
			EnableAllowedSources: int64p(1),
			AllowedSources:       PSStringArray{`{"Name":"contoso","Arg":"https://pkgs.contoso.example/api","Type":"Microsoft.Rest","Data":"","Identifier":"contoso"}`},
		}
		got := ResolveWingetSources(p, &doc)
		assert.Equal(t, []string{"user:contoso", "default:winget", "default:winget-font"}, sourceNames(got))

		p.AllowedSources = PSStringArray{`{"Name":"other","Arg":"https://other.example","Type":"Microsoft.Rest","Data":"","Identifier":"other"}`}
		got = ResolveWingetSources(p, &doc)
		assert.Equal(t, []string{"default:winget", "default:winget-font"}, sourceNames(got))
	})

	t.Run("policy adds a source that wins over a user source of the same name", func(t *testing.T) {
		doc := userSourcesDoc
		p := &WingetPolicy{
			EnableAdditionalSources: int64p(1),
			AdditionalSources: PSStringArray{
				`{"Name":"contoso","Arg":"https://mirror.contoso.example/api","Type":"Microsoft.Rest","Data":"","Identifier":"contoso-mirror","Explicit":true}`,
				`{"Name":"incomplete","Arg":"https://x.example"}`,
			},
		}
		got := ResolveWingetSources(p, &doc)
		assert.Equal(t, []string{"policy:contoso", "default:winget", "default:winget-font"}, sourceNames(got))
		assert.Equal(t, "https://mirror.contoso.example/api", got[0].URL)
		assert.True(t, got[0].Explicit)
	})

	t.Run("unparsable user sources contribute nothing", func(t *testing.T) {
		doc := "Sources: [unterminated"
		got := ResolveWingetSources(nil, &doc)
		assert.Equal(t, []string{"default:msstore", "default:winget", "default:winget-font"}, sourceNames(got))
	})
}
