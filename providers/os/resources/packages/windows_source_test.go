// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// testdata/source/windows holds what the two queries returned on a Windows 11
// 24H2 VM (build 26100, Microsoft Store available) after a Store app, winget
// and Chocolatey installs:
//
//   - appx-packages.json is a selection of WINDOWS_QUERY_APPX_PACKAGES's output,
//     the package list:
//     a system component, inbox apps, Edge and Teams, a provisioned
//     third-party app, a framework, a component Windows pushed after first
//     logon, a Store app a user installed, and the package Notepad++'s
//     installer registers.
//   - source-facts.json is windowsSourceQuery's output, its AppX part cut to
//     the same packages.
const windowsFixtures = "testdata/source/windows"

func windowsFixtureSources(t *testing.T) map[string]Source {
	t.Helper()
	data, err := os.ReadFile(windowsFixtures + "/appx-packages.json")
	require.NoError(t, err)
	pkgs, err := ParseWindowsAppxPackages(&inventory.Platform{Name: "windows", Arch: "x86_64"}, bytes.NewReader(data))
	require.NoError(t, err)
	factsData, err := os.ReadFile(windowsFixtures + "/source-facts.json")
	require.NoError(t, err)
	facts := parseWindowsSourceFacts(factsData)

	out := map[string]Source{}
	for _, p := range pkgs {
		out[p.Name] = windowsPackageSource(p, facts)
	}
	return out
}

func TestWindowsAppxSources(t *testing.T) {
	got := windowsFixtureSources(t)
	osSrc := Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Windows"}

	// signature kind System: the shell's own components
	assert.Equal(t, osSrc, got["Microsoft.Windows.ShellExperienceHost"])
	// Store-signed, but provisioned in the Windows image
	assert.Equal(t, osSrc, got["Microsoft.WindowsCalculator"])
	assert.Equal(t, osSrc, got["Microsoft.Windows.Photos"])
	assert.Equal(t, osSrc, got["Microsoft.WindowsStore"])
	// Developer-signed, and provisioned
	assert.Equal(t, osSrc, got["Microsoft.MicrosoftEdge.Stable"])
	assert.Equal(t, osSrc, got["MSTeams"])
	// a third party's app Windows provisions
	assert.Equal(t, osSrc, got["Clipchamp.Clipchamp"])
	// a Microsoft framework the inbox apps depend on
	assert.Equal(t, osSrc, got["Microsoft.VCLibs.140.00"])
	// published by "CN=Microsoft Windows", Store-signed
	assert.Equal(t, osSrc, got["MicrosoftWindows.Client.WebExperience"])

	store := Source{OSProvided: osProvided(false), Channel: ChannelAppStore, Name: "microsoft-store"}
	// installed by a user from the Store
	assert.Equal(t, store, got["19282JackieLiu.Notepads-Beta"])
	// Windows installs this one through the Store after first logon; nothing
	// on the system tells it apart from a user's Store install
	assert.Equal(t, store, got["Microsoft.StartExperiencesApp"])
	// registered by Notepad++'s own installer, Developer-signed
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelDirect}, got["NotepadPlusPlus"])
}

func TestAppxSignatureKind(t *testing.T) {
	assert.Equal(t, appxSignatureStore, appxSignatureKind(json.RawMessage(`3`)))
	assert.Equal(t, appxSignatureSystem, appxSignatureKind(json.RawMessage(`"System"`)), "PowerShell 7 can write the name")
	assert.Equal(t, -1, appxSignatureKind(json.RawMessage(`9`)))
	assert.Equal(t, -1, appxSignatureKind(nil))
}

func TestWindowsAppxWithoutPowerShell(t *testing.T) {
	// an AppX package found by its manifest on disk carries no signature kind
	system := Package{Name: "Microsoft.Windows.ShellExperienceHost", Format: WindowsAppxPkgFormat,
		Files: []FileRecord{{Path: `C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy`}}}
	assert.Equal(t, ChannelOS, windowsPackageSource(system, windowsSourceFacts{}).Channel)
	other := Package{Name: "Microsoft.WindowsCalculator", Format: WindowsAppxPkgFormat,
		Files: []FileRecord{{Path: `C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2502.2.0_x64__8wekyb3d8bbwe`}}}
	assert.Equal(t, unknownSource(), windowsPackageSource(other, windowsSourceFacts{}))
}

func TestParseWindowsSourceFacts(t *testing.T) {
	data, err := os.ReadFile(windowsFixtures + "/source-facts.json")
	require.NoError(t, err)
	facts := parseWindowsSourceFacts(data)
	assert.Len(t, facts.provisioned, 49)
	assert.Equal(t, appxInfo{family: "Microsoft.WindowsCalculator_8wekyb3d8bbwe", signatureKind: appxSignatureStore},
		facts.appx["Microsoft.WindowsCalculator/"+calculatorVersion(t)])
	assert.True(t, facts.provisioned["microsoft.windowscalculator_8wekyb3d8bbwe"])
	// Edge, WebView2, and Edge Update's own entry, which has no uninstall
	// command and is skipped
	assert.Equal(t, []string{
		"c:/program files (x86)/microsoft/edge/application",
		"c:/program files (x86)/microsoft/edgewebview/application",
	}, facts.edgeDirs)

	// PowerShell writes a one-element array as its element
	one := parseWindowsSourceFacts([]byte(`{"provisioned":"Microsoft.Paint_11.2601.440.0_neutral_~_8wekyb3d8bbwe","edge":null}`))
	assert.True(t, one.provisioned["microsoft.paint_8wekyb3d8bbwe"])
	assert.Empty(t, parseWindowsSourceFacts([]byte("not json")).provisioned)
}

func calculatorVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(windowsFixtures + "/appx-packages.json")
	require.NoError(t, err)
	var list []struct{ Name, Version string }
	require.NoError(t, json.Unmarshal(data, &list))
	for _, p := range list {
		if p.Name == "Microsoft.WindowsCalculator" {
			return p.Version
		}
	}
	t.Fatal("no Calculator in the fixture")
	return ""
}

func TestIsProductCode(t *testing.T) {
	assert.True(t, isProductCode("{23170F69-40C1-2702-2501-000001000000}"))
	assert.True(t, isProductCode("{ac76ba86-7ad7-1033-7b44-ac0f074e4100}"))
	assert.False(t, isProductCode("7-Zip"))
	assert.False(t, isProductCode("Notepad++"))
	assert.False(t, isProductCode("{23170F69-40C1-2702-2501-00000100000}"), "one digit short")
	assert.False(t, isProductCode("{23170F69_40C1-2702-2501-000001000000}"))
	assert.False(t, isProductCode("{23170F69-40C1-2702-2501-00000100000G}"))
}

func TestWindowsAppSource(t *testing.T) {
	data, err := os.ReadFile(windowsFixtures + "/source-facts.json")
	require.NoError(t, err)
	facts := parseWindowsSourceFacts(data)

	// winget's PuTTY install: an MSI, named by its ProductCode
	msi := Package{Name: "PuTTY release 0.85 (64-bit)", Format: WindowsAppPkgFormat, Vendor: "Simon Tatham",
		installIdentity: newInstallIdentity("{3B0346D3-A9DC-4E45-B8F9-1A7C1E0B4E3C}", true, "", "MsiExec.exe /X{3B0346D3-A9DC-4E45-B8F9-1A7C1E0B4E3C}")}
	got := windowsPackageSource(msi, facts)
	assert.Equal(t, Source{Channel: ChannelInstaller, Name: "{3B0346D3-A9DC-4E45-B8F9-1A7C1E0B4E3C}"}, got)
	assert.Nil(t, got.OSProvided, "Windows records nothing that says whether such a program came with it")

	exe := Package{Name: "Notepad++ (64-bit x64)", Format: WindowsAppPkgFormat, Vendor: "Notepad++ Team",
		installIdentity: newInstallIdentity("Notepad++", false, "", `"C:\Program Files\Notepad++\uninstall.exe"`)}
	assert.Equal(t, Source{Channel: ChannelInstaller}, windowsPackageSource(exe, facts))

	// Edge and WebView2 came with Windows: Edge Update records it
	osSrc := Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Windows"}
	edge := Package{Name: "Microsoft Edge", Format: WindowsAppPkgFormat, Vendor: "Microsoft Corporation",
		Files: []FileRecord{{Path: `C:\Program Files (x86)\Microsoft\Edge\Application`}}}
	assert.Equal(t, osSrc, windowsPackageSource(edge, facts))
	webview := Package{Name: "Microsoft Edge WebView2 Runtime", Format: WindowsAppPkgFormat, Vendor: "Microsoft Corporation",
		Files: []FileRecord{{Path: `C:\Program Files (x86)\Microsoft\EdgeWebView\Application`}}}
	assert.Equal(t, osSrc, windowsPackageSource(webview, facts))
	assert.Equal(t, osSrc, windowsPackageSource(Package{Name: "Microsoft Edge Update", Format: WindowsAppPkgFormat, Vendor: "Microsoft Corporation"}, facts))
	// an Edge someone installed: Edge Update records another source
	assert.Equal(t, ChannelInstaller, windowsPackageSource(edge, windowsSourceFacts{}).Channel)

	dotnet := Package{Name: dotNetFrameworkName, Format: WindowsAppPkgFormat, Vendor: "Microsoft"}
	assert.Equal(t, osSrc, windowsPackageSource(dotnet, facts))
	runtime := Package{Name: dotNetFrameworkName, Format: WindowsAppPkgFormat, Vendor: "Microsoft Corporation"}
	assert.Equal(t, ChannelInstaller, windowsPackageSource(runtime, facts).Channel, "an Uninstall entry is not the built-in runtime")

	// after listing, the identity lives only in the purl
	putty := Package{Name: "PuTTY release 0.85 (64-bit)", Format: WindowsAppPkgFormat, Vendor: "Simon Tatham",
		PUrl: "pkg:windows/windows/PuTTY%20release%200.85%20%2864-bit%29@0.85.0.0?arch=AMD64&installer=msi&product_code=3B0346D3-A9DC-4E45-B8F9-1A7C1E0B4E3C"}
	assert.Equal(t, "{3B0346D3-A9DC-4E45-B8F9-1A7C1E0B4E3C}", windowsPackageSource(putty, facts).Name)

	hotfix := Package{Name: "KB5034441", Format: WindowsHotfixPkgFormat}
	assert.Equal(t, ChannelOS, windowsPackageSource(hotfix, facts).Channel)
}

func TestEdgeApplicationDir(t *testing.T) {
	assert.Equal(t, "c:/program files (x86)/microsoft/edge/application",
		edgeApplicationDir(`C:\Program Files (x86)\Microsoft\Edge\Application\154.0.4258.62\Installer\setup.exe`))
	assert.Equal(t, "", edgeApplicationDir(`C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`))
	assert.Equal(t, "", edgeApplicationDir(""))
}
