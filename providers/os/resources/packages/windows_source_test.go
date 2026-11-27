// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
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

// testdata/winget holds winget's tracking catalogs (installed.db, VACUUMed)
// copied from a Windows 11 Enterprise 23H2 (22631) host with App Installer
// 1.29.380.0, on 2026-11-27, after winget installed 7-Zip, Chrome, Acrobat
// Reader, Notepad++, jq and Visual Studio Code:
//
//   - system-Microsoft.Winget.Source.db is SYSTEM's catalog of the community
//     source, from the unpackaged state directory.
//   - user-Microsoft.Winget.Source.db is an Entra user's catalog of the same
//     source, from the packaged state directory.
const wingetFixtures = "testdata/winget"

const (
	wingetSystemDir = "Windows/System32/config/systemprofile/AppData/Local/Microsoft/WinGet/State/defaultState/"
	wingetUserDir   = "Users/entra/AppData/Local/Packages/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe/LocalState/"
	wingetCommunity = "Microsoft.Winget.Source_8wekyb3d8bbwe"
)

func writeWingetFile(t *testing.T, fs afero.Fs, p string, data []byte) {
	t.Helper()
	require.NoError(t, fs.MkdirAll(path.Dir(p), 0o755))
	require.NoError(t, afero.WriteFile(fs, p, data, 0o644))
}

func wingetFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(wingetFixtures + "/" + name)
	require.NoError(t, err)
	return data
}

// wingetFixtureFS is an offline Windows volume with both measured catalogs.
func wingetFixtureFS(t *testing.T) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	writeWingetFile(t, fs, wingetSystemDir+wingetCommunity+"/installed.db", wingetFixture(t, "system-Microsoft.Winget.Source.db"))
	writeWingetFile(t, fs, wingetUserDir+wingetCommunity+"/installed.db", wingetFixture(t, "user-Microsoft.Winget.Source.db"))
	return fs
}

func uninstallEntry(name, version, key string) Package {
	return Package{Name: name, Version: version, Format: WindowsAppPkgFormat,
		installIdentity: newInstallIdentity(key, false, "", "")}
}

func wingetSource(id string) Source {
	return Source{OSProvided: osProvided(false), Channel: ChannelWinget, Name: id}
}

func TestWingetSources(t *testing.T) {
	facts := windowsSourceFacts{winget: readWingetCatalogs(wingetFixtureFS(t), mountedSystemDrivePath)}

	// Measured: Windows 11 23H2 22631, 2026-11-27; each program is installed by
	// winget and its Uninstall key and DisplayVersion are what the registry shows.
	measured := []struct {
		name string
		pkg  Package
		id   string
	}{
		// HKLM, product code "7-zip" in three manifests (26.00, 26.02, 26.03)
		{"7-Zip", uninstallEntry("7-Zip", "26.03", "7-Zip"), "7zip.7zip"},
		{"Chrome", uninstallEntry("Google Chrome", "154.0.8037.58", "{C8B3A0BF-0F75-32C9-B05B-BE6FE9F5ED90}"), "Google.Chrome"},
		// HKLM\WOW6432Node, the same GUID in two manifests
		{"Acrobat Reader", uninstallEntry("Adobe Acrobat Reader MUI", "26.002.21931", "{AC76BA86-7AD7-FFFF-7B44-AC0F074E4100}"), "Adobe.Acrobat.Reader.32-bit"},
		{"Notepad++", uninstallEntry("Notepad++ (x64)", "8.9.9.1", "{A23B657D-838B-4C9B-8F9D-386E50C1A76B}"), "Notepad++.Notepad++"},
		// HKU of the user who ran winget, tracked in that user's catalog
		{"Visual Studio Code", uninstallEntry("Microsoft Visual Studio Code (User)", "1.139.0", "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1"), "Microsoft.VisualStudioCode"},
		// portable: the key is "<id>_<source>_<family>", under HKU\S-1-5-18
		{"jq", uninstallEntry("jq 1.8.2", "1.8.2", "jqlang.jq_Microsoft.Winget.Source_8wekyb3d8bbwe"), "jqlang.jq"},
	}
	for _, tc := range measured {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, wingetSource(tc.id), windowsPackageSource(tc.pkg, facts))
		})
	}

	// Measured: Zoom, installed by its own MSI, is in no catalog
	zoom := Package{Name: "Zoom (64-bit)", Version: "5.16.22807", Format: WindowsAppPkgFormat,
		installIdentity: newInstallIdentity("{130C5F26-7D81-4285-9F6C-C18D91503887}", true, "", "MsiExec.exe /X{130C5F26-7D81-4285-9F6C-C18D91503887}")}
	got := windowsPackageSource(zoom, facts)
	assert.Equal(t, Source{Channel: ChannelInstaller, Name: "{130C5F26-7D81-4285-9F6C-C18D91503887}"}, got)
	assert.Nil(t, got.OSProvided)

	// Synthetic: the package has no Uninstall key; no target showed this.
	noKey := Package{Name: "7-Zip", Version: "26.03", Format: WindowsAppPkgFormat}
	assert.Equal(t, Source{Channel: ChannelInstaller}, windowsPackageSource(noKey, facts))
}

func TestWingetKeyIsCaseInsensitive(t *testing.T) {
	facts := windowsSourceFacts{winget: readWingetCatalogs(wingetFixtureFS(t), mountedSystemDrivePath)}
	// Synthetic: the catalog lower-cases keys; an installer may write them in
	// any case. Measured keys already differ in case ("7-Zip" vs "7-zip").
	assert.Equal(t, wingetSource("7zip.7zip"), windowsPackageSource(uninstallEntry("7-Zip", "26.03", "7-ZIP"), facts))
}

func TestWingetStaleCatalogStillAttributes(t *testing.T) {
	// Measured: the user's catalog holds 7-Zip 26.00 while the registry says
	// 26.03 (SYSTEM upgraded it). Only the user's catalog is present here.
	fs := afero.NewMemMapFs()
	writeWingetFile(t, fs, wingetUserDir+wingetCommunity+"/installed.db", wingetFixture(t, "user-Microsoft.Winget.Source.db"))
	facts := windowsSourceFacts{winget: readWingetCatalogs(fs, mountedSystemDrivePath)}
	assert.Equal(t, wingetSource("7zip.7zip"), windowsPackageSource(uninstallEntry("7-Zip", "26.03", "7-Zip"), facts))
}

func TestWingetCatalogLocations(t *testing.T) {
	// Measured: the packaged path (a user) and the unpackaged path (SYSTEM)
	// both exist on one host, and each holds programs the other does not.
	fs := afero.NewMemMapFs()
	writeWingetFile(t, fs, wingetUserDir+wingetCommunity+"/installed.db", wingetFixture(t, "user-Microsoft.Winget.Source.db"))
	user := readWingetCatalogs(fs, mountedSystemDrivePath)
	assert.Contains(t, user, "{771fd6b0-fa20-440a-a002-3b3bac16dc50}_is1")
	assert.NotContains(t, user, "{a23b657d-838b-4c9b-8f9d-386e50c1a76b}")

	fs = afero.NewMemMapFs()
	writeWingetFile(t, fs, wingetSystemDir+wingetCommunity+"/installed.db", wingetFixture(t, "system-Microsoft.Winget.Source.db"))
	system := readWingetCatalogs(fs, mountedSystemDrivePath)
	assert.Contains(t, system, "{a23b657d-838b-4c9b-8f9d-386e50c1a76b}")
	assert.NotContains(t, system, "{771fd6b0-fa20-440a-a002-3b3bac16dc50}_is1")

	// Synthetic: an unpackaged user catalog under C:\Users\<u>\AppData\Local\Microsoft\WinGet; no target showed this.
	fs = afero.NewMemMapFs()
	writeWingetFile(t, fs, "Users/other/AppData/Local/Microsoft/WinGet/State/defaultState/"+wingetCommunity+"/installed.db", wingetFixture(t, "system-Microsoft.Winget.Source.db"))
	assert.Contains(t, readWingetCatalogs(fs, mountedSystemDrivePath), "7-zip")

	// Synthetic: a volume without winget state
	assert.Empty(t, readWingetCatalogs(afero.NewMemMapFs(), mountedSystemDrivePath))
}

func TestWingetEntryPicksTheInstalledVersion(t *testing.T) {
	// Synthetic: two manifests of different ids name one key; no host showed
	// this (every measured key had one id across its manifests).
	idx := wingetIndex{"key": {
		{id: "Old.Id", version: "1.0", written: 10, sourceDir: "a"},
		{id: "New.Id", version: "2.0", written: 20, sourceDir: "a"},
	}}
	src, ok := idx.source(uninstallEntry("x", "1.0", "KEY"))
	require.True(t, ok)
	assert.Equal(t, "Old.Id", src.Name, "the manifest of the installed version wins over a newer one")
	src, _ = idx.source(uninstallEntry("x", "3.0", "KEY"))
	assert.Equal(t, "New.Id", src.Name, "without a version match the most recently tracked one wins")
	src, _ = idx.source(uninstallEntry("x", "2.0", "KEY"))
	assert.Equal(t, "New.Id", src.Name)
}

func TestWingetMicrosoftStoreSource(t *testing.T) {
	// Synthetic: no host showed an msstore Win32 install; the catalog of the
	// msstore source lives in StoreEdgeFD.
	fs := afero.NewMemMapFs()
	writeWingetFile(t, fs, wingetSystemDir+"StoreEdgeFD/installed.db", wingetFixture(t, "system-Microsoft.Winget.Source.db"))
	facts := windowsSourceFacts{winget: readWingetCatalogs(fs, mountedSystemDrivePath)}
	assert.Equal(t, Source{OSProvided: osProvided(false), Channel: ChannelAppStore, Name: "microsoft-store"},
		windowsPackageSource(uninstallEntry("7-Zip", "26.03", "7-Zip"), facts))

	// Synthetic: a custom source directory reports winget with the package id.
	fs = afero.NewMemMapFs()
	writeWingetFile(t, fs, wingetSystemDir+"Contoso.Source_8wekyb3d8bbwe/installed.db", wingetFixture(t, "system-Microsoft.Winget.Source.db"))
	facts = windowsSourceFacts{winget: readWingetCatalogs(fs, mountedSystemDrivePath)}
	assert.Equal(t, wingetSource("7zip.7zip"), windowsPackageSource(uninstallEntry("7-Zip", "26.03", "7-Zip"), facts))
}

func TestWingetBadCatalogsAreSkipped(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Synthetic: a corrupt file and a file over the size bound next to a good
	// catalog; no target showed either.
	writeWingetFile(t, fs, wingetUserDir+"Corrupt.Source/installed.db", []byte("this is not a sqlite database"))
	writeWingetFile(t, fs, wingetUserDir+"Huge.Source/installed.db", make([]byte, wingetMaxCatalogBytes+1))
	writeWingetFile(t, fs, wingetSystemDir+wingetCommunity+"/installed.db", wingetFixture(t, "system-Microsoft.Winget.Source.db"))
	idx := readWingetCatalogs(fs, mountedSystemDrivePath)
	assert.Contains(t, idx, "7-zip")
	assert.Len(t, wingetCatalogPaths(fs, mountedSystemDrivePath), 3)
}

func TestWingetCatalogWithWriteAheadLog(t *testing.T) {
	// Synthetic: a catalog winget holds open keeps its newest rows in the
	// -wal file; no target showed one (winget 1.29 uses a rollback journal).
	dir := t.TempDir()
	local := filepath.Join(dir, "installed.db")
	db, err := sql.Open("sqlite", "file:"+local+"?_pragma=journal_mode(wal)&_pragma=wal_autocheckpoint(0)")
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`CREATE TABLE ids(rowid INTEGER PRIMARY KEY, id TEXT)`,
		`CREATE TABLE versions(rowid INTEGER PRIMARY KEY, version TEXT)`,
		`CREATE TABLE productcodes(rowid INTEGER PRIMARY KEY, productcode TEXT)`,
		`CREATE TABLE manifest(rowid INTEGER PRIMARY KEY, id INT, version INT)`,
		`CREATE TABLE productcodes_map(manifest INT, productcode INT)`,
		`CREATE TABLE manifest_metadata(manifest INT, metadata INT, value TEXT)`,
		`INSERT INTO ids VALUES (1, 'Wal.Package')`,
		`INSERT INTO versions VALUES (1, '1.0')`,
		`INSERT INTO productcodes VALUES (1, 'wal-key')`,
		`INSERT INTO manifest VALUES (1, 1, 1)`,
		`INSERT INTO productcodes_map VALUES (1, 1)`,
	} {
		_, err := db.Exec(stmt)
		require.NoError(t, err, stmt)
	}
	dbBytes, err := os.ReadFile(local)
	require.NoError(t, err)
	walBytes, err := os.ReadFile(local + "-wal")
	require.NoError(t, err)
	require.NotEmpty(t, walBytes)

	fs := afero.NewMemMapFs()
	p := wingetSystemDir + wingetCommunity + "/installed.db"
	writeWingetFile(t, fs, p, dbBytes)
	assert.Empty(t, readWingetCatalogs(fs, mountedSystemDrivePath), "without the log the tables are not there")
	writeWingetFile(t, fs, p+"-wal", walBytes)
	idx := readWingetCatalogs(fs, mountedSystemDrivePath)
	require.Contains(t, idx, "wal-key")
	assert.Equal(t, "Wal.Package", idx["wal-key"][0].id)
}

func TestWingetDoesNotOverrideInboxRules(t *testing.T) {
	// Synthetic: a catalog that names the Edge and .NET Framework entries
	// (winget can track Microsoft.Edge); the inbox rules keep precedence.
	idx := wingetIndex{
		"microsoft edge": {{id: "Microsoft.Edge", version: "158", sourceDir: "microsoft.winget.source_8wekyb3d8bbwe"}},
		"dotnetfx":       {{id: "Microsoft.DotNet.Framework", version: "4.8", sourceDir: "microsoft.winget.source_8wekyb3d8bbwe"}},
	}
	facts := windowsSourceFacts{winget: idx, edgeDirs: []string{"c:/program files (x86)/microsoft/edge/application"}}
	osSrc := Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "Windows"}

	edge := Package{Name: "Microsoft Edge", Version: "158", Format: WindowsAppPkgFormat, Vendor: "Microsoft Corporation",
		Files:           []FileRecord{{Path: `C:\Program Files (x86)\Microsoft\Edge\Application`}},
		installIdentity: newInstallIdentity("Microsoft Edge", false, "", "")}
	assert.Equal(t, osSrc, windowsPackageSource(edge, facts))

	dotnet := Package{Name: dotNetFrameworkName, Version: "4.8", Format: WindowsAppPkgFormat, Vendor: "Microsoft",
		installIdentity: newInstallIdentity("dotnetfx", false, "", "")}
	assert.Equal(t, osSrc, windowsPackageSource(dotnet, facts))

	// the same catalog still decides an Edge entry that did not come with Windows
	facts.edgeDirs = nil
	assert.Equal(t, wingetSource("Microsoft.Edge"), windowsPackageSource(edge, facts))
}
