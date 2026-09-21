// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestWindowsAppPackagesParser(t *testing.T) {
	f, err := os.Open("./testdata/windows_packages.json")
	require.NoError(t, err)
	defer f.Close()

	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.18363",
		Arch:    "x86",
		Family:  []string{"windows"},
	}
	pkgs, err := ParseWindowsAppPackages(pf, f)
	assert.Nil(t, err)
	assert.Equal(t, 19, len(pkgs), "detected the right amount of packages")

	p := findPkg(pkgs, "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913")
	assert.Equal(t, Package{
		Name:    "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913",
		Version: "14.28.29913.0",
		Arch:    "x86",
		Format:  "windows/app",
		PUrl:    `pkg:windows/windows/Microsoft%20Visual%20C%2B%2B%202015-2019%20Redistributable%20%28x86%29%20-%2014.28.29913@14.28.29913.0?arch=x86`,
		CPEs: []string{
			"cpe:2.3:a:microsoft_corporation:microsoft_visual_c\\+\\+_2015-2019_redistributable_\\(x86\\)_-_14.28.29913:14.28.29913.0:*:*:*:*:*:*:*",
		},
		Vendor: "Microsoft Corporation",
	}, p)

	// check empty return
	pkgs, err = ParseWindowsAppxPackages(pf, strings.NewReader(""))
	assert.Nil(t, err)
	assert.Equal(t, 0, len(pkgs), "detected the right amount of packages")
}

func TestWindowsAppPackagesParserWithPSPath(t *testing.T) {
	// Simulate a 64-bit system with packages from both native and Wow6432Node paths
	jsonData := `[
		{"DisplayName":"Microsoft .NET Runtime - 8.0.7 (x64)","DisplayVersion":"8.0.7.33813","Publisher":"Microsoft Corporation","EstimatedSize":1234,"InstallSource":null,"UninstallString":"uninstall-x64","InstallLocation":"","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{abc}"},
		{"DisplayName":"Microsoft .NET Runtime - 8.0.7 (x86)","DisplayVersion":"8.0.7.33813","Publisher":"Microsoft Corporation","EstimatedSize":1234,"InstallSource":null,"UninstallString":"uninstall-x86","InstallLocation":"","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{def}"}
	]`

	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.17763",
		Arch:    "amd64",
		Family:  []string{"windows"},
	}
	pkgs, err := ParseWindowsAppPackages(pf, strings.NewReader(jsonData))
	require.NoError(t, err)
	require.Equal(t, 2, len(pkgs))

	x64Pkg := findPkg(pkgs, "Microsoft .NET Runtime - 8.0.7 (x64)")
	assert.Equal(t, "amd64", x64Pkg.Arch, "native path package should have platform arch")

	x86Pkg := findPkg(pkgs, "Microsoft .NET Runtime - 8.0.7 (x86)")
	assert.Equal(t, "x86", x86Pkg.Arch, "Wow6432Node path package should have x86 arch")
}

func TestWindowsAppxPackagesParserSkipsEmptyNames(t *testing.T) {
	pf := &inventory.Platform{Name: "windows", Arch: "x86", Family: []string{"windows"}}

	// the middle entry has an empty Name and must be omitted entirely,
	// not turned into a zero-value Package hole
	const data = `[
		{"Name":"Microsoft.WindowsCalculator","Version":"1.0.0.0","Architecture":0,"Publisher":"CN=Microsoft"},
		{"Name":"","Version":"","Architecture":0,"Publisher":""},
		{"Name":"Microsoft.WindowsStore","Version":"2.0.0.0","Architecture":0,"Publisher":"CN=Microsoft"}
	]`

	pkgs, err := ParseWindowsAppxPackages(pf, strings.NewReader(data))
	require.NoError(t, err)
	require.Equal(t, 2, len(pkgs), "empty-name entry should be skipped, no holes")
	for _, p := range pkgs {
		assert.NotEmpty(t, p.Name, "no empty/zero-value package should be present")
	}
}

func TestWindowsAppxPackagesParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"windows"},
		},
	}, mock.WithPath("./testdata/windows_2019.toml"))
	if err != nil {
		t.Fatal(err)
	}

	c, err := mock.RunCommand(powershell.Wrap(WINDOWS_QUERY_APPX_PACKAGES))
	if err != nil {
		t.Fatal(err)
	}

	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.18363",
		Arch:    "x86",
		Family:  []string{"windows"},
	}

	// The purls below carry arch=neutral, not the host's x86: an
	// architecture-neutral appx has no architecture of its own, and reporting
	// the host's made Package.Arch and the purl disagree about one package
	// (https://github.com/mondoohq/mql/issues/10636).
	pkgs, err := ParseWindowsAppxPackages(pf, c.Stdout)
	require.NoError(t, err)
	require.Equal(t, 29, len(pkgs), "detected the right amount of packages")

	p := findPkg(pkgs, "Microsoft.Windows.Cortana")
	assert.Equal(t, Package{
		Name:    "Microsoft.Windows.Cortana",
		Version: "1.11.5.17763",
		Arch:    "neutral",
		Format:  "windows/appx",
		PUrl:    "pkg:appx/windows/Microsoft.Windows.Cortana@1.11.5.17763?arch=neutral",
		// TODO: this is a bug in the CPE generation, we need to extract the publisher from the package
		CPEs: []string{
			"cpe:2.3:a:cn\\=microsoft_corporation\\,_o\\=microsoft_corporation\\,_l\\=redmond\\,_s\\=washington\\,_c\\=us:microsoft.windows.cortana:1.11.5.17763:*:*:*:*:*:*:*",
		},
		Vendor: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
	}, p)

	p = findPkg(pkgs, "Microsoft.MicrosoftEdge.Stable")
	assert.Equal(t, Package{
		Name:    "Microsoft.MicrosoftEdge.Stable",
		Version: "112.0.1722.39",
		Arch:    "neutral",
		Format:  "windows/appx",
		PUrl:    "pkg:appx/windows/Microsoft.MicrosoftEdge.Stable@112.0.1722.39?arch=neutral",
		// TODO: this is a bug in the CPE generation, we need to extract the publisher from the package
		CPEs: []string{
			"cpe:2.3:a:cn\\=microsoft_corporation\\,_o\\=microsoft_corporation\\,_l\\=redmond\\,_s\\=washington\\,_c\\=us:microsoft.microsoftedge.stable:112.0.1722.39:*:*:*:*:*:*:*",
		},
		Vendor: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
		Files: []FileRecord{
			{
				Path: "C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftEdge.Stable_112.0.1722.39_neutral__8wekyb3d8bbwe",
			},
		},
		FilesAvailable: PkgFilesIncluded,
	}, p)

	// check empty return
	pkgs, err = ParseWindowsAppxPackages(pf, strings.NewReader(""))
	assert.Nil(t, err)
	assert.Equal(t, 0, len(pkgs), "detected the right amount of packages")
}

func TestWindowsHotFixParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"windows"},
		},
	}, mock.WithPath("./testdata/windows_2019.toml"))
	if err != nil {
		t.Fatal(err)
	}

	c, err := mock.RunCommand(powershell.Wrap(WINDOWS_QUERY_HOTFIXES))
	if err != nil {
		t.Fatal(err)
	}

	hotfixes, err := ParseWindowsHotfixes(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 6, len(hotfixes), "detected the right amount of packages")

	timestamp := hotfixes[0].InstalledOnTime()
	assert.NotNil(t, timestamp)

	// Real Get-HotFix JSON shape (see testdata/windows_2019.toml): InstalledOn
	// carries the raw PowerShell "\/Date(1599609600000)\/" value alongside the
	// human-readable DateTime, both for the same instant.
	expectedInstalledOn := time.Date(2020, time.September, 9, 0, 0, 0, 0, time.UTC)
	assert.True(t, timestamp.Equal(expectedInstalledOn), "expected InstalledOnTime to match the fixture's InstalledOn value")

	pkgs := HotFixesToPackages(hotfixes)
	p := findPkg(pkgs, "KB4486553")
	assert.Equal(t, Package{
		Name:        "KB4486553",
		Description: "Update",
		Format:      "windows/hotfix",
		InstallDate: expectedInstalledOn,
	}, p)

	// check empty return
	hotfixes, err = ParseWindowsHotfixes(strings.NewReader(""))
	assert.Nil(t, err)
	assert.Equal(t, 0, len(hotfixes), "detected the right amount of packages")
}

// TestHotFixesToPackagesMissingInstalledOn covers the entries the fixture
// above doesn't: Get-HotFix commonly omits InstalledOn (older hotfixes,
// hotfixes installed by an update agent rather than a user), and a stray
// value in that field must not panic HotFixesToPackages or fabricate a date.
func TestHotFixesToPackagesMissingInstalledOn(t *testing.T) {
	hotfixes := []PowershellWinHotFix{
		{
			// InstalledOn entirely absent from the JSON.
			HotFixId:    "KB0000001",
			Description: "Update",
		},
		{
			// InstalledOn present but its value does not match the
			// PowerShell "/Date(...)/ " shape PSJsonTimestamp expects.
			HotFixId:    "KB0000002",
			Description: "Update",
			InstalledOn: struct {
				Value    string `json:"value"`
				DateTime string `json:"DateTime"`
			}{Value: "not-a-date", DateTime: "garbage"},
		},
	}

	pkgs := HotFixesToPackages(hotfixes)
	require.Len(t, pkgs, 2)

	for _, p := range pkgs {
		assert.True(t, p.InstallDate.IsZero(), "InstallDate should be the zero value when InstalledOn is absent or unparseable")
	}
}

func TestGetPackageFromRegistryKeyItems(t *testing.T) {
	t.Run("get package from registry key items that are empty", func(t *testing.T) {
		items := []registry.RegistryKeyItem{}
		p := getPackageFromRegistryKeyItems(items, &inventory.Platform{
			Family: []string{"windows"},
		}, "amd64")
		assert.Nil(t, p)
	})
	t.Run("get package from registry key items with missing required values", func(t *testing.T) {
		items := []registry.RegistryKeyItem{
			{
				Key: "DisplayName",
				Value: registry.RegistryKeyValue{
					Kind:   registry.SZ,
					String: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913",
				},
			},
		}
		p := getPackageFromRegistryKeyItems(items, &inventory.Platform{
			Family: []string{"windows"},
		}, "amd64")
		assert.Nil(t, p)
	})

	t.Run("get package from registry key items", func(t *testing.T) {
		items := []registry.RegistryKeyItem{
			{
				Key: "DisplayName",
				Value: registry.RegistryKeyValue{
					Kind:   registry.SZ,
					String: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913",
				},
			},
			{
				Key: "UninstallString",
				Value: registry.RegistryKeyValue{
					Kind:   registry.SZ,
					String: "UninstallString",
				},
			},
			{
				Key: "DisplayVersion",
				Value: registry.RegistryKeyValue{
					Kind:   registry.SZ,
					String: "14.28.29913.0",
				},
			},
			{
				Key: "Publisher",
				Value: registry.RegistryKeyValue{
					Kind:   registry.SZ,
					String: "Microsoft Corporation",
				},
			},
		}
		p := getPackageFromRegistryKeyItems(items, &inventory.Platform{
			Name:   "windows",
			Arch:   "x86",
			Family: []string{"windows"},
		}, "x86")
		CPEs, err := cpe.NewPackage2Cpe(
			"Microsoft Corporation",
			"Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913",
			"14.28.29913.0",
			"",
			"")

		assert.Nil(t, err)

		expected := &Package{
			Name:    "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913",
			Version: "14.28.29913.0",
			Arch:    "x86",
			Format:  "windows/app",
			CPEs:    CPEs,
			Vendor:  "Microsoft Corporation",
			PUrl:    "pkg:windows/windows/Microsoft%20Visual%20C%2B%2B%202015-2019%20Redistributable%20%28x86%29%20-%2014.28.29913@14.28.29913.0?arch=x86",
		}
		assert.NotNil(t, p)
		assert.Equal(t, expected, p)
	})
}

func TestToPackage(t *testing.T) {
	winAppxPkg := winAppxPackages{
		Name:         "Microsoft.Windows.Cortana",
		Version:      "1.11.5.17763",
		Publisher:    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
		Architecture: 0,
	}

	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.18363",
		Arch:    "x86",
		Family:  []string{"windows"},
	}

	pkg := winAppxPkg.toPackage(pf)

	expected := Package{
		Name:    "Microsoft.Windows.Cortana",
		Version: "1.11.5.17763",
		Arch:    "x86",
		Format:  "windows/appx",
		PUrl:    "pkg:appx/windows/Microsoft.Windows.Cortana@1.11.5.17763?arch=x86",
		Vendor:  "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
		CPEs: []string{
			"cpe:2.3:a:cn\\=microsoft_corporation\\,_o\\=microsoft_corporation\\,_l\\=redmond\\,_s\\=washington\\,_c\\=us:microsoft.windows.cortana:1.11.5.17763:*:*:*:*:*:*:*",
		},
	}

	assert.Equal(t, expected, pkg)
}

func findPkgByName(pkgs []Package, name string) *Package {
	for i := range pkgs {
		if pkgs[i].Name == name {
			return &pkgs[i]
		}
	}
	return nil
}

func TestFindAndUpdateMsSqlHotfixes(t *testing.T) {
	// Setup: create a list of packages with SQL Server hotfixes and SQL Server packages
	packages := []Package{
		{Name: "SQL Server 2019 Database Engine Services", Version: "15.0.2000.5", PUrl: "pkg:windows/windows/SQL%20Server%202019%20Database%20Engine%20Services@15.0.2000.5?arch=x86"},
		{Name: "SQL Server 2019 Shared Management Objects", Version: "15.0.2000.5", PUrl: "pkg:windows/windows/SQL%20Server%202019%20Shared%20Management%20Objects@15.0.2000.5?arch=x86"},
		// We should not update the setup package
		{Name: "Microsoft SQL Server 2019 Setup (English)", Version: "15.0.2123.5", PUrl: "pkg:windows/windows/Microsoft%20SQL%20Server%202019%20Setup%20%28English%29@15.0.2123.5?arch=x86"},
		{Name: "Hotfix KB5001090 SQL Server", Version: "15.0.4102.2", PUrl: "pkg:windows/windows/Hotfix%20KB5001090%20SQL%20Server@15.0.4102.2?arch=x86"},
		{Name: "Hotfix KB5001091 SQL Server", Version: "15.0.4123.1", PUrl: "pkg:windows/windows/Hotfix%20KB5001091%20SQL%20Server@15.0.4123.1?arch=x86"},
		{Name: "Not a hotfix", Version: "1.0.0", PUrl: "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86"},
	}

	// Step 1: Find SQL Server hotfixes
	hotfixes := findMsSqlHotfixes(packages)
	require.Len(t, hotfixes, 2, "expected 2 hotfixes")

	// Step 2: Get the latest hotfix (should be the last one after sorting)
	latestHotfix := hotfixes[len(hotfixes)-1]
	expectedLatestVersion := "15.0.4123.1"
	require.Equal(t, expectedLatestVersion, latestHotfix.Version, "expected latest hotfix version")

	// Step 3: Update SQL Server packages with the latest hotfix version
	updated := updateMsSqlPackages(packages, latestHotfix)

	// Step 4: Check that all SQL Server packages have the updated version
	pkg := findPkgByName(updated, "SQL Server 2019 Database Engine Services")
	require.NotNil(t, pkg, "SQL Server 2019 Database Engine Services package should exist")
	require.Equal(t, expectedLatestVersion, pkg.Version, "expected SQL Server 2019 Database Engine Services to have updated version")
	assert.Equal(t, "pkg:windows/windows/SQL%20Server%202019%20Database%20Engine%20Services@15.0.4123.1?arch=x86", pkg.PUrl)

	pkg = findPkgByName(updated, "SQL Server 2019 Shared Management Objects")
	require.NotNil(t, pkg, "SQL Server 2019 Shared Management Objects package should exist")
	require.Equal(t, expectedLatestVersion, pkg.Version, "expected SQL Server 2019 Shared Management Objects to have updated version")
	assert.Equal(t, "pkg:windows/windows/SQL%20Server%202019%20Shared%20Management%20Objects@15.0.4123.1?arch=x86", pkg.PUrl)

	pkg = findPkgByName(updated, "Microsoft SQL Server 2019 Setup (English)")
	require.NotNil(t, pkg, "Microsoft SQL Server 2019 Setup (English) package should exist")
	require.Equal(t, "15.0.2123.5", pkg.Version, "expected Microsoft SQL Server 2019 Setup (English) to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Microsoft%20SQL%20Server%202019%20Setup%20%28English%29@15.0.2123.5?arch=x86", pkg.PUrl)

	pkg = findPkgByName(updated, "Hotfix KB5001090 SQL Server")
	require.NotNil(t, pkg, "Hotfix KB5001090 SQL Server package should exist")
	require.Equal(t, "15.0.4102.2", pkg.Version, "expected Hotfix KB5001090 SQL Server to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Hotfix%20KB5001090%20SQL%20Server@15.0.4102.2?arch=x86", pkg.PUrl)

	pkg = findPkgByName(updated, "Hotfix KB5001091 SQL Server")
	require.NotNil(t, pkg, "Hotfix KB5001091 SQL Server package should exist")
	require.Equal(t, "15.0.4123.1", pkg.Version, "expected Hotfix KB5001091 SQL Server to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Hotfix%20KB5001091%20SQL%20Server@15.0.4123.1?arch=x86", pkg.PUrl)

	// Step 5: Ensure non-SQL Server packages are unchanged
	pkg = findPkgByName(updated, "Not a hotfix")
	require.NotNil(t, pkg, "Not a hotfix package should exist")
	require.Equal(t, "1.0.0", pkg.Version, "expected non-SQL Server package to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86", pkg.PUrl)
}

func TestFindAndUpdateMsSqlGDR_en(t *testing.T) {
	// Setup: create a list of packages with SQL Server hotfixes and SQL Server packages
	packages := []Package{
		{Name: "SQL Server 2022 Database Engine Services", Version: "16.0.1000.6", PUrl: "pkg:windows/windows/SQL%20Server%202022%20Database%20Engine%20Services@16.0.1000.6?arch=x86"},
		{Name: "SQL Server 2022 Shared Management Objects", Version: "16.0.1000.6", PUrl: "pkg:windows/windows/SQL%20Server%202022%20Shared%20Management%20Objects@16.0.1000.6?arch=x86"},
		// We should not update the setup package
		{Name: "Microsoft SQL Server 2022 Setup (English)", Version: "16.0.1000.6", PUrl: "pkg:windows/windows/Microsoft%20SQL%20Server%202022%20Setup%20%28English%29@16.0.1000.6?arch=x86"},
		{Name: "GDR 1115 for SQL Server 2022 (KB5035432) (64-bit)", Version: "16.0.1115.1", PUrl: "pkg:windows/windows/GDR%201115%20for%20SQL%20Server%202022%20%28KB5035432%29%20%2864-bit%29@16.0.1115.1?arch=x86"},
		{Name: "GDR 1105 for SQL Server 2022 (KB5029379) (64-bit)", Version: "16.0.1105.1", PUrl: "pkg:windows/windows/GDR%201105%20for%20SQL%20Server%202022%20%28KB5029379%29%20%2864-bit%29@16.0.1105.1?arch=x86"},
		{Name: "Not a hotfix", Version: "1.0.0", PUrl: "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86"},
	}

	// Step 1: Find SQL Server gdrUpdates
	gdrUpdates := findMsSqlGdrUpdates(packages)
	require.Len(t, gdrUpdates, 2, "expected 2 updates")

	// Step 2: Get the latest hotfix (should be the last one after sorting)
	latestUpdate := gdrUpdates[len(gdrUpdates)-1]
	expectedLatestVersion := "16.0.1115.1"
	require.Equal(t, expectedLatestVersion, latestUpdate.Version, "expected latest update version")

	// Step 3: Update SQL Server packages with the latest hotfix version
	packages = updateMsSqlPackages(packages, latestUpdate)

	// Step 4: Check that all SQL Server packages have the updated version
	pkg := findPkgByName(packages, "SQL Server 2022 Database Engine Services")
	require.NotNil(t, pkg, "SQL Server 2022 Database Engine Services package should exist")
	require.Equal(t, expectedLatestVersion, pkg.Version, "expected SQL Server 2022 Database Engine Services to have updated version")
	assert.Equal(t, "pkg:windows/windows/SQL%20Server%202022%20Database%20Engine%20Services@16.0.1115.1?arch=x86", pkg.PUrl)

	pkg = findPkgByName(packages, "GDR 1105 for SQL Server 2022 (KB5029379) (64-bit)")
	require.NotNil(t, pkg, "KB5029379 SQL Server package should exist")
	require.Equal(t, "16.0.1105.1", pkg.Version, "expected Hotfix KB5029379 SQL Server to remain unchanged")

	pkg = findPkgByName(packages, "GDR 1115 for SQL Server 2022 (KB5035432) (64-bit)")
	require.NotNil(t, pkg, "KB5035432 SQL Server package should exist")
	require.Equal(t, "16.0.1115.1", pkg.Version, "expected Hotfix KB5035432 SQL Server to remain unchanged")

	// Step 5: Ensure non-SQL Server packages are unchanged
	pkg = findPkgByName(packages, "Not a hotfix")
	require.NotNil(t, pkg, "Not a hotfix package should exist")
	require.Equal(t, "1.0.0", pkg.Version, "expected non-SQL Server package to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86", pkg.PUrl)
}

func TestFindAndUpdateMsSqlGDR_de(t *testing.T) {
	// Setup: create a list of packages with SQL Server hotfixes and SQL Server packages
	packages := []Package{
		{Name: "SQL Server 2022 Database Engine Services", Version: "16.0.1050.5", PUrl: "pkg:windows/windows/SQL%20Server%202022%20Database%20Engine%20Services@16.0.1050.5?arch=x86"},
		{Name: "SQL Server 2022 Shared Management Objects", Version: "16.0.1050.5", PUrl: "pkg:windows/windows/SQL%20Server%202022%20Shared%20Management%20Objects@16.0.1050.5?arch=x86"},
		// We should not update the setup package
		{Name: "Microsoft SQL Server 2022 Setup (English)", Version: "16.0.1050.5", PUrl: "pkg:windows/windows/Microsoft%20SQL%20Server%202022%20Setup%20%28English%29@16.0.1050.5?arch=x86"},
		{Name: "GDR 1115 für SQL Server 2022 (KB5035432) (64-bit)", Version: "16.0.1115.1", PUrl: "pkg:windows/windows/GDR%201115%20f%C3%BCr%20SQL%20Server%202022%20%28KB5035432%29%20%2864-bit%29@16.0.1115.1?arch=x86"},
		{Name: "GDR 1110 für SQL Server 2022 (KB5032968) (64-bit)", Version: "16.0.1110.1", PUrl: "pkg:windows/windows/GDR%201110%20f%C3%BCr%20SQL%20Server%202022%20%28KB5032968%29%20%2864-bit%29@16.0.1110.1?arch=x86"},
		{Name: "Not a hotfix", Version: "1.0.0", PUrl: "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86"},
	}

	// Step 1: Find SQL Server gdrUpdates
	gdrUpdates := findMsSqlGdrUpdates(packages)
	require.Len(t, gdrUpdates, 2, "expected 2 updates")

	// Step 2: Get the latest hotfix (should be the last one after sorting)
	latestUpdate := gdrUpdates[len(gdrUpdates)-1]
	expectedLatestVersion := "16.0.1115.1"
	require.Equal(t, expectedLatestVersion, latestUpdate.Version, "expected latest update version")

	// Step 3: Update SQL Server packages with the latest hotfix version
	updated := updateMsSqlPackages(packages, latestUpdate)

	// Step 4: Check that all SQL Server packages have the updated version
	pkg := findPkgByName(updated, "SQL Server 2022 Database Engine Services")
	require.NotNil(t, pkg, "SQL Server 2022 Database Engine Services package should exist")
	require.Equal(t, expectedLatestVersion, pkg.Version, "expected SQL Server 2022 Database Engine Services to have updated version")
	assert.Equal(t, "pkg:windows/windows/SQL%20Server%202022%20Database%20Engine%20Services@16.0.1115.1?arch=x86", pkg.PUrl)

	pkg = findPkgByName(updated, "GDR 1115 für SQL Server 2022 (KB5035432) (64-bit)")
	require.NotNil(t, pkg, "KB5035432 SQL Server package should exist")
	require.Equal(t, "16.0.1115.1", pkg.Version, "expected Hotfix KB5001090 SQL Server to remain unchanged")

	pkg = findPkgByName(updated, "GDR 1110 für SQL Server 2022 (KB5032968) (64-bit)")
	require.NotNil(t, pkg, "KB5032968 SQL Server package should exist")
	require.Equal(t, "16.0.1110.1", pkg.Version, "expected Hotfix KB5001091 SQL Server to remain unchanged")

	// Step 5: Ensure non-SQL Server packages are unchanged
	pkg = findPkgByName(updated, "Not a hotfix")
	require.NotNil(t, pkg, "Not a hotfix package should exist")
	require.Equal(t, "1.0.0", pkg.Version, "expected non-SQL Server package to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86", pkg.PUrl)
}

func TestFindAndUpdateMsSqlGDR_de_special_characters(t *testing.T) {
	// Setup: create a list of packages with SQL Server hotfixes and SQL Server packages
	packages := []Package{
		{Name: "SQL Server 2017 Database Engine Services", Version: "14.0.1000.169", PUrl: "pkg:windows/windows/SQL%20Server%202017%20Database%20Engine%20Services@14.0.1000.169?arch=x86"},
		{Name: "SQL Server 2017 Shared Management Objects", Version: "14.0.1000.169", PUrl: "pkg:windows/windows/SQL%20Server%202022%20Shared%20Management%20Objects@14.0.1000.169?arch=x86"},
		// We should not update the setup package
		{Name: "Microsoft SQL Server 2017 Setup (English)", Version: "14.0.1000.169", PUrl: "pkg:windows/windows/Microsoft%20SQL%20Server%202017%20Setup%20%28English%29@14.0.1050.5"},
		// This package contains a non breaking space between SQL Server and 2017
		{Name: "GDR 2042 für SQL Server 2017 (KB5014354) (64-bit)", Version: "14.0.2042.3", PUrl: "pkg:windows/windows/GDR%202042%20f%C3%BCr%20SQL%20Server%202017%20%28KB5014354%29%20%2864-bit%29@14.0.2042.3?arch=x86"},
		// This package contains a non breaking space between SQL Server and 2017
		{Name: "GDR 2037 für SQL Server 2017 (KB4583456) (64-bit)", Version: "14.0.2037.2", PUrl: "pkg:windows/windows/GDR%202037%20f%C3%BCr%20SQL%20Server%202017%20%28KB4583456%29%20%2864-bit%29@14.0.2037.2?arch=x86"},
		{Name: "Not a hotfix", Version: "1.0.0", PUrl: "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86"},
	}

	// Step 1: Find SQL Server gdrUpdates
	gdrUpdates := findMsSqlGdrUpdates(packages)
	require.Len(t, gdrUpdates, 2, "expected 2 updates")

	// Step 2: Get the latest hotfix (should be the last one after sorting)
	latestUpdate := gdrUpdates[len(gdrUpdates)-1]
	expectedLatestVersion := "14.0.2042.3"
	require.Equal(t, expectedLatestVersion, latestUpdate.Version, "expected latest update version")

	// Step 3: Update SQL Server packages with the latest hotfix version
	updated := updateMsSqlPackages(packages, latestUpdate)

	// Step 4: Check that all SQL Server packages have the updated version
	pkg := findPkgByName(updated, "SQL Server 2017 Database Engine Services")
	require.NotNil(t, pkg, "SQL Server 2017 Database Engine Services package should exist")
	require.Equal(t, expectedLatestVersion, pkg.Version, "expected SQL Server 2017 Database Engine Services to have updated version")
	assert.Equal(t, "pkg:windows/windows/SQL%20Server%202017%20Database%20Engine%20Services@14.0.2042.3?arch=x86", pkg.PUrl)

	// Step 5: Ensure non-SQL Server packages are unchanged
	pkg = findPkgByName(updated, "Not a hotfix")
	require.NotNil(t, pkg, "Not a hotfix package should exist")
	require.Equal(t, "1.0.0", pkg.Version, "expected non-SQL Server package to remain unchanged")
	assert.Equal(t, "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86", pkg.PUrl)
}

// TestUpdateMsSqlPackages_NoEngineServicesPackage guards against corrupting the
// PURL of a "SQL Server" product bundle entry that carries an empty
// DisplayVersion when no "Database Engine Services" package is present (so the
// anchor version is empty). The buggy behavior prepended the update version to
// the PURL (e.g. "16.0.1150.1pkg:windows/windows/Microsoft%20SQL%20Server...").
func TestUpdateMsSqlPackages_NoEngineServicesPackage(t *testing.T) {
	packages := []Package{
		// Product bundle entry from the registry Uninstall key with an empty
		// DisplayVersion. The PURL has no version component.
		{Name: "Microsoft SQL Server 2022 (64-bit)", Version: "", PUrl: "pkg:windows/windows/Microsoft%20SQL%20Server%202022%20%2864-bit%29?arch=AMD64"},
		{Name: "GDR 1150 for SQL Server 2022 (KB5042215) (64-bit)", Version: "16.0.1150.1", PUrl: "pkg:windows/windows/GDR%201150%20for%20SQL%20Server%202022%20%28KB5042215%29%20%2864-bit%29@16.0.1150.1?arch=AMD64"},
	}

	gdrUpdates := findMsSqlGdrUpdates(packages)
	require.Len(t, gdrUpdates, 1, "expected 1 update")

	updated := updateMsSqlPackages(packages, gdrUpdates[len(gdrUpdates)-1])

	// Without a Database Engine Services anchor package, the bundle entry must be
	// left untouched: its PURL must stay valid and not gain a prepended version.
	pkg := findPkgByName(updated, "Microsoft SQL Server 2022 (64-bit)")
	require.NotNil(t, pkg, "Microsoft SQL Server 2022 (64-bit) package should exist")
	assert.Equal(t, "", pkg.Version, "expected bundle entry version to remain empty")
	assert.Equal(t, "pkg:windows/windows/Microsoft%20SQL%20Server%202022%20%2864-bit%29?arch=AMD64", pkg.PUrl)
	assert.True(t, strings.HasPrefix(pkg.PUrl, "pkg:"), "PURL must start with pkg:, not a version")
}

func TestNormalizeMsSqlVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// SP-era: MSI DisplayVersion encodes SP level in the minor; we rewrite
		// to Microsoft's canonical product version (minor=0). The build
		// component already identifies the SP (e.g., 6xxx for SQL 2016 SP3).
		{"SQL 2012 SP1", "11.1.3128.0", "11.0.3128.0"},
		{"SQL 2012 SP2", "11.2.5058.0", "11.0.5058.0"},
		{"SQL 2012 SP3", "11.3.6020.0", "11.0.6020.0"},
		{"SQL 2012 SP4", "11.4.7001.0", "11.0.7001.0"},
		{"SQL 2014 SP1", "12.1.4100.1", "12.0.4100.1"},
		{"SQL 2014 SP2", "12.2.5000.0", "12.0.5000.0"},
		{"SQL 2014 SP3", "12.3.6433.1", "12.0.6433.1"},
		{"SQL 2016 SP1", "13.1.4001.0", "13.0.4001.0"},
		{"SQL 2016 SP2", "13.2.5108.50", "13.0.5108.50"},
		{"SQL 2016 SP3 hotfix 6485", "13.3.6485.1", "13.0.6485.1"},

		// Already canonical: pass through unchanged.
		{"SQL 2016 RTM/SP3-GDR canonical", "13.0.6485.1", "13.0.6485.1"},
		{"SQL 2014 RTM canonical", "12.0.2000.8", "12.0.2000.8"},
		{"SQL 2012 RTM canonical", "11.0.2100.60", "11.0.2100.60"},

		// Post-SP-era (Modern Servicing Model, no Service Packs): unchanged.
		{"SQL 2017 GDR", "14.0.2110.2", "14.0.2110.2"},
		{"SQL 2017 CU31+GDR", "14.0.3530.2", "14.0.3530.2"},
		{"SQL 2019 GDR", "15.0.2170.1", "15.0.2170.1"},
		{"SQL 2019 CU32+GDR", "15.0.4470.1", "15.0.4470.1"},
		{"SQL 2022 GDR", "16.0.1180.1", "16.0.1180.1"},
		{"SQL 2022 CU24+GDR", "16.0.4252.3", "16.0.4252.3"},
		{"SQL 2025 GDR", "17.0.1115.1", "17.0.1115.1"},
		{"SQL 2025 CU4+GDR", "17.0.4040.1", "17.0.4040.1"},

		// Out of guarded major range: do not touch SQL 2008 / 2008 R2 or any
		// pre-2012 version. They had Service Packs too, but they're EOL and
		// the registry conventions on those binaries were different — leave
		// the original DisplayVersion intact rather than risk a wrong rewrite.
		{"SQL 2008 R2 SP3", "10.50.6000.34", "10.50.6000.34"},
		{"SQL 2008 SP4", "10.0.6000.29", "10.0.6000.29"},

		// Defensive: anything that doesn't match the strict 4-component shape
		// passes through. We only rewrite when we're confident about the form.
		{"empty", "", ""},
		{"3-component", "13.3.6485", "13.3.6485"},
		{"5-component", "13.3.6485.1.0", "13.3.6485.1.0"},
		{"non-numeric build", "13.3.6485x.1", "13.3.6485x.1"},
		{"minor 0 already", "13.0.6300.2", "13.0.6300.2"},
		{"minor 5 (out of SP range)", "13.5.6485.1", "13.5.6485.1"},
		{"leading whitespace", " 13.3.6485.1", " 13.3.6485.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMsSqlVersion(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFindAndUpdateMsSqlHotfixes_NormalizesSqlServer2016SP3(t *testing.T) {
	// Reproduces the SQL 2016 SP3 case from the field: MSI registers each
	// hotfix's DisplayVersion as 13.3.<build>.<rev>, but advisory data uses
	// the canonical 13.0.<build>.<rev>. updateMsSqlPackages must stamp the
	// canonical form so KB advisories compare correctly.
	packages := []Package{
		{Name: "SQL Server 2016 Database Engine Services", Version: "13.0.1601.5", PUrl: "pkg:windows/windows/SQL%20Server%202016%20Database%20Engine%20Services@13.0.1601.5?arch=x64"},
		{Name: "SQL Server 2016 Shared Management Objects", Version: "13.0.1601.5", PUrl: "pkg:windows/windows/SQL%20Server%202016%20Shared%20Management%20Objects@13.0.1601.5?arch=x64"},
		{Name: "Hotfix 6480 for Microsoft SQL Server 2016 (KB5077474) (64-bit)", Version: "13.3.6480.4", PUrl: "pkg:windows/windows/Hotfix%206480%20for%20Microsoft%20SQL%20Server%202016%20%28KB5077474%29%20%2864-bit%29@13.3.6480.4?arch=x64"},
		{Name: "Hotfix 6485 for Microsoft SQL Server 2016 (KB5084821) (64-bit)", Version: "13.3.6485.1", PUrl: "pkg:windows/windows/Hotfix%206485%20for%20Microsoft%20SQL%20Server%202016%20%28KB5084821%29%20%2864-bit%29@13.3.6485.1?arch=x64"},
	}

	hotfixes := findMsSqlHotfixes(packages)
	require.Len(t, hotfixes, 2)
	latest := hotfixes[len(hotfixes)-1]
	require.Equal(t, "13.3.6485.1", latest.Version, "hotfix's own DisplayVersion is left untouched")

	updated := updateMsSqlPackages(packages, latest)

	// Engine package is stamped with the normalized canonical version
	// (13.0.6485.1, matching Microsoft's build-versions table for KB5084821).
	pkg := findPkgByName(updated, "SQL Server 2016 Database Engine Services")
	require.NotNil(t, pkg)
	assert.Equal(t, "13.0.6485.1", pkg.Version)
	assert.Equal(t, "pkg:windows/windows/SQL%20Server%202016%20Database%20Engine%20Services@13.0.6485.1?arch=x64", pkg.PUrl)

	// Other engine-bound SQL Server packages get the same canonical stamping.
	pkg = findPkgByName(updated, "SQL Server 2016 Shared Management Objects")
	require.NotNil(t, pkg)
	assert.Equal(t, "13.0.6485.1", pkg.Version)

	// The hotfix package itself keeps its MSI DisplayVersion — it isn't
	// engine-bound (different currentVersion) so updateMsSqlPackages doesn't
	// rewrite it, and consumers identify the patch via the KB-encoded name.
	pkg = findPkgByName(updated, "Hotfix 6485 for Microsoft SQL Server 2016 (KB5084821) (64-bit)")
	require.NotNil(t, pkg)
	assert.Equal(t, "13.3.6485.1", pkg.Version)
}

func TestGetPackageFromRegistryKeyItemsWow6432Node(t *testing.T) {
	items := []registry.RegistryKeyItem{
		{
			Key: "DisplayName",
			Value: registry.RegistryKeyValue{
				Kind:   registry.SZ,
				String: "Microsoft .NET Runtime - 8.0.7 (x86)",
			},
		},
		{
			Key: "UninstallString",
			Value: registry.RegistryKeyValue{
				Kind:   registry.SZ,
				String: "UninstallString",
			},
		},
		{
			Key: "DisplayVersion",
			Value: registry.RegistryKeyValue{
				Kind:   registry.SZ,
				String: "8.0.7.33813",
			},
		},
		{
			Key: "Publisher",
			Value: registry.RegistryKeyValue{
				Kind:   registry.SZ,
				String: "Microsoft Corporation",
			},
		},
	}

	pf := &inventory.Platform{
		Name:   "windows",
		Arch:   "amd64",
		Family: []string{"windows"},
	}

	// Simulate package from Wow6432Node path (32-bit app on 64-bit Windows)
	p := getPackageFromRegistryKeyItems(items, pf, "x86")
	require.NotNil(t, p)
	assert.Equal(t, "x86", p.Arch, "package from Wow6432Node should have x86 arch")

	// Simulate same package from regular path (64-bit app)
	p = getPackageFromRegistryKeyItems(items, pf, "amd64")
	require.NotNil(t, p)
	assert.Equal(t, "amd64", p.Arch, "package from regular path should have platform arch")
}

func TestArchForRegistryPath(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		platformArch string
		expected     string
	}{
		{
			name:         "HKLM native path",
			path:         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
			platformArch: "amd64",
			expected:     "amd64",
		},
		{
			name:         "HKLM Wow6432Node path",
			path:         "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
			platformArch: "amd64",
			expected:     "x86",
		},
		{
			name:         "HKCU Wow6432Node path",
			path:         "HKCU\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
			platformArch: "amd64",
			expected:     "x86",
		},
		{
			name:         "PowerShell PSPath with Wow6432Node",
			path:         "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{abc}",
			platformArch: "amd64",
			expected:     "x86",
		},
		{
			name:         "PowerShell PSPath without Wow6432Node",
			path:         "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{abc}",
			platformArch: "amd64",
			expected:     "amd64",
		},
		{
			name:         "filesystem relative path with Wow6432Node",
			path:         "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
			platformArch: "amd64",
			expected:     "x86",
		},
		{
			name:         "empty PSPath falls back to platform arch",
			path:         "",
			platformArch: "amd64",
			expected:     "amd64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := archForRegistryPath(tt.path, tt.platformArch)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestArchFromInstallPath(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected string
	}{
		{
			name:     "Program Files (x86) in install location",
			paths:    []string{"C:\\Program Files (x86)\\Microsoft\\DotNet\\runtime"},
			expected: "x86",
		},
		{
			name:     "Program Files (x86) in uninstall string",
			paths:    []string{"", "\"C:\\Program Files (x86)\\Microsoft\\setup.exe\" /uninstall"},
			expected: "x86",
		},
		{
			name:     "native Program Files",
			paths:    []string{"C:\\Program Files\\Microsoft\\DotNet\\runtime"},
			expected: "",
		},
		{
			name:     "empty paths",
			paths:    []string{"", ""},
			expected: "",
		},
		{
			name:     "no paths",
			paths:    nil,
			expected: "",
		},
		{
			name:     "first match wins",
			paths:    []string{"C:\\Program Files (x86)\\app", "C:\\Program Files\\app"},
			expected: "x86",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := archFromInstallPath(tt.paths...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegistryKeyItemsArchFallbackToInstallPath(t *testing.T) {
	// Simulate a 32-bit app installed per-user (HKCU, shared path — no Wow6432Node).
	// The caller passes platform.Arch because archForRegistryPath couldn't determine x86.
	// The function should fall back to detecting "Program Files (x86)" in the install location.
	items := []registry.RegistryKeyItem{
		{
			Key:   "DisplayName",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "Some 32-bit App"},
		},
		{
			Key:   "UninstallString",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "MsiExec.exe /X{1234}"},
		},
		{
			Key:   "DisplayVersion",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "1.0.0"},
		},
		{
			Key:   "InstallLocation",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "C:\\Program Files (x86)\\SomeApp"},
		},
	}

	pf := &inventory.Platform{
		Name:   "windows",
		Arch:   "amd64",
		Family: []string{"windows"},
	}

	// Caller passes "amd64" because the HKCU path had no Wow6432Node
	p := getPackageFromRegistryKeyItems(items, pf, "amd64")
	require.NotNil(t, p)
	assert.Equal(t, "x86", p.Arch, "should detect x86 from Program Files (x86) install location")
}

func TestRegistryKeyItemsArchNoFallbackWhenAlreadyX86(t *testing.T) {
	// When arch is already determined from Wow6432Node, the install path check should not run.
	items := []registry.RegistryKeyItem{
		{
			Key:   "DisplayName",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "Some App"},
		},
		{
			Key:   "UninstallString",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "MsiExec.exe /X{1234}"},
		},
		{
			Key:   "DisplayVersion",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "1.0.0"},
		},
		{
			Key:   "InstallLocation",
			Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "C:\\Program Files\\NativeApp"},
		},
	}

	pf := &inventory.Platform{
		Name:   "windows",
		Arch:   "amd64",
		Family: []string{"windows"},
	}

	// Caller already determined x86 from Wow6432Node — should not be overridden
	p := getPackageFromRegistryKeyItems(items, pf, "x86")
	require.NotNil(t, p)
	assert.Equal(t, "x86", p.Arch, "Wow6432Node-determined arch must not be overridden by install path")
}

func TestWindowsAppPackagesParserInstallPathFallback(t *testing.T) {
	// HKCU entry (no Wow6432Node in PSPath) but installed under Program Files (x86)
	jsonData := `[
		{"DisplayName":"Per-User 32-bit App","DisplayVersion":"1.0","Publisher":"Test","EstimatedSize":100,"InstallSource":null,"UninstallString":"uninstall","InstallLocation":"C:\\Program Files (x86)\\PerUserApp","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{abc}"},
		{"DisplayName":"Per-User 64-bit App","DisplayVersion":"2.0","Publisher":"Test","EstimatedSize":100,"InstallSource":null,"UninstallString":"uninstall","InstallLocation":"C:\\Program Files\\PerUserApp64","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{def}"}
	]`

	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.17763",
		Arch:    "amd64",
		Family:  []string{"windows"},
	}

	pkgs, err := ParseWindowsAppPackages(pf, strings.NewReader(jsonData))
	require.NoError(t, err)
	require.Equal(t, 2, len(pkgs))

	pkg32 := findPkg(pkgs, "Per-User 32-bit App")
	assert.Equal(t, "x86", pkg32.Arch, "HKCU app in Program Files (x86) should be detected as x86")

	pkg64 := findPkg(pkgs, "Per-User 64-bit App")
	assert.Equal(t, "amd64", pkg64.Arch, "HKCU app in Program Files should keep platform arch")
}

// TestFsInstalledAppsArchAssignment validates that the exact registry path strings
// used in getFsInstalledApps produce distinct arch values on a 64-bit system.
// This is the unit-testable part of getFsInstalledApps; the full function requires
// Windows with loaded registry hive files.
func TestFsInstalledAppsArchAssignment(t *testing.T) {
	// These are the exact paths from getFsInstalledApps
	fsPaths := []string{
		"Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}
	platformArch := "amd64"

	archResults := make([]string, len(fsPaths))
	for i, p := range fsPaths {
		archResults[i] = archForRegistryPath(p, platformArch)
	}

	assert.Equal(t, "amd64", archResults[0], "native path should use platform arch")
	assert.Equal(t, "x86", archResults[1], "Wow6432Node path should use x86")
	assert.NotEqual(t, archResults[0], archResults[1], "the two paths must produce different arch values on a 64-bit system")
}

func TestCreatePackage(t *testing.T) {
	t.Run("create package with non-breaking space in name", func(t *testing.T) {
		// The name contains a non-breaking space between Server and 2017
		pkg := createPackage("GDR 2042 für SQL Server 2017 (KB5014354) (64-bit)", "1234", "windows/app", "x86_64", "Microsoft", "", nil)
		require.NotNil(t, pkg, "expected package to be created")

		// Here we check that the name is replaced with a regular space
		assert.Equal(t, "GDR 2042 für SQL Server 2017 (KB5014354) (64-bit)", pkg.Name)
	})

	t.Run("create package with non-breaking space in name - unicode", func(t *testing.T) {
		// The name contains a non-breaking space between Server and 2017
		pkg := createPackage("GDR 2042 für SQL Server\u00a02017 (KB5014354) (64-bit)", "1234", "windows/app", "x86_64", "Microsoft", "", nil)
		require.NotNil(t, pkg, "expected package to be created")

		// Here we check that the name is replaced with a regular space
		assert.Equal(t, "GDR 2042 für SQL Server 2017 (KB5014354) (64-bit)", pkg.Name)
	})

	t.Run("create package with control characters in name produces a valid purl", func(t *testing.T) {
		// Regression test for https://github.com/mondoohq/mql/issues/7975
		// Windows registry DisplayName values can carry trailing \r\n, which
		// previously leaked into the purl and failed with
		// "net/url: invalid control character in URL".
		pkg := createPackage("Arcserve UDP Host-Based VM Backup VM-Integrationsdienst\r\n", "8.0.5628.430", "windows/app", "x86_64", "Arcserve", "", nil)
		require.NotNil(t, pkg, "expected package to be created")

		// The control characters must be stripped from the name...
		assert.Equal(t, "Arcserve UDP Host-Based VM Backup VM-Integrationsdienst", pkg.Name)

		// ...and the resulting purl must be free of control characters and parseable as a URL.
		assert.NotContains(t, pkg.PUrl, "\r")
		assert.NotContains(t, pkg.PUrl, "\n")
		assert.NotContains(t, pkg.PUrl, "%0D")
		assert.NotContains(t, pkg.PUrl, "%0A")
		_, err := url.Parse(pkg.PUrl)
		assert.NoError(t, err, "purl must parse as a URL")
	})

	t.Run("create package strips control characters from version", func(t *testing.T) {
		pkg := createPackage("SomeApp", "1.2.3\r\n", "windows/app", "x86_64", "Vendor", "", nil)
		require.NotNil(t, pkg, "expected package to be created")

		assert.Equal(t, "1.2.3", pkg.Version)
		assert.NotContains(t, pkg.PUrl, "%0D")
		assert.NotContains(t, pkg.PUrl, "%0A")
	})

	t.Run("create package strips control characters from publisher", func(t *testing.T) {
		// Defends against the JSON-projection corruption mode mondoohq/server
		// observed: an Add/Remove entry whose Publisher carries a stray \r
		// can produce JSON like `{"vendor":"foo"\r"description":"…"}` after
		// PowerShell's ConvertTo-Json -Compress in some configurations,
		// which on the server side surfaces as
		// "invalid character 'd' after object key:value pair" inside
		// json.Unmarshal — and silently drops the entire OS-packages list.
		pkg := createPackage("SomeApp", "1.2.3", "windows/app", "x86_64", "Acme Corp\r\n", "", nil)
		require.NotNil(t, pkg, "expected package to be created")
		assert.Equal(t, "Acme Corp", pkg.Vendor,
			"vendor must be free of control characters so it round-trips cleanly through JSON")
		assert.NotContains(t, pkg.Vendor, "\r")
		assert.NotContains(t, pkg.Vendor, "\n")
	})

	t.Run("create package strips control characters from installLocation", func(t *testing.T) {
		// Same class of bug as vendor: installLocation lands on
		// pkg.Files[0].Path and is serialized through the same SBOM
		// projection.
		pkg := createPackage("SomeApp", "1.2.3", "windows/app", "x86_64", "Vendor",
			"C:\\Program Files\\Acme\r\n", nil)
		require.NotNil(t, pkg, "expected package to be created")
		require.Len(t, pkg.Files, 1, "installLocation must produce a Files entry")
		assert.Equal(t, "C:\\Program Files\\Acme", pkg.Files[0].Path,
			"installLocation path must be free of control characters")
	})

	t.Run("vendor + installLocation + name + version stay clean when ALL carry rot", func(t *testing.T) {
		// End-to-end check: a single Add/Remove entry where every
		// registry-derived field is dirty must still produce a clean
		// Package whose every projected field is safe to drop into a
		// JSON object body.
		pkg := createPackage(
			"SomeApp\r\n", "1.2.3\r\n", "windows/app", "x86_64",
			"Acme Corp\r\n", "C:\\Program Files\\Acme\r\n", nil)
		require.NotNil(t, pkg)
		assert.Equal(t, "SomeApp", pkg.Name)
		assert.Equal(t, "1.2.3", pkg.Version)
		assert.Equal(t, "Acme Corp", pkg.Vendor)
		require.Len(t, pkg.Files, 1)
		assert.Equal(t, "C:\\Program Files\\Acme", pkg.Files[0].Path)

		// Final guard: the projected fields together must serialize to a
		// JSON object Go's encoding/json can decode back. That's the
		// shape the server's convertPackages call would see.
		marshalled, err := json.Marshal(map[string]string{
			"name":            pkg.Name,
			"version":         pkg.Version,
			"vendor":          pkg.Vendor,
			"installLocation": pkg.Files[0].Path,
		})
		require.NoError(t, err)
		var roundtrip map[string]string
		require.NoError(t, json.Unmarshal(marshalled, &roundtrip),
			"the SBOM-shape JSON object must decode cleanly")
		assert.Equal(t, "SomeApp", roundtrip["name"])
		assert.Equal(t, "Acme Corp", roundtrip["vendor"])
	})
}

// TestCreatePackagePurlCarriesThePackageArch pins that a Windows package's purl
// reports the architecture of the PACKAGE, not of the host it was found on.
//
// Regression test for https://github.com/mondoohq/mql/issues/10636 (2). The
// purl was built without the per-package arch, so NewPackageURL fell back to
// platform.Arch: a 32-bit application on a 64-bit host was recorded as
// Arch: x86 while its purl claimed ?arch=x86_64. The purl is the field that
// reaches vulnerability matching, so the wrong one was the one that counted.
func TestCreatePackagePurlCarriesThePackageArch(t *testing.T) {
	// 64-bit host, as every modern Windows machine is.
	platform := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.19045",
		Arch:    "x86_64",
		Labels:  map[string]string{"distro-id": "windows"},
	}

	t.Run("32-bit app on a 64-bit host", func(t *testing.T) {
		pkg := createPackage("Legacy Tool", "1.2.3", "windows/app", "x86", "Acme", "", platform)
		require.NotNil(t, pkg)

		assert.Equal(t, "x86", pkg.Arch)
		assert.Contains(t, pkg.PUrl, "arch=x86",
			"the purl must carry the package's own arch")
		assert.NotContains(t, pkg.PUrl, "arch=x86_64",
			"the purl must not fall back to the host arch when the package has its own")
	})

	t.Run("appx package with its own arch", func(t *testing.T) {
		pkg := createPackage("Some.Appx", "2.0.0.0", "windows/appx", "arm64", "Acme", "", platform)
		require.NotNil(t, pkg)

		assert.True(t, strings.HasPrefix(pkg.PUrl, "pkg:appx/"), "got %q", pkg.PUrl)
		assert.Equal(t, pkg.Arch, purlQualifier(t, pkg.PUrl, "arch"),
			"Package.Arch and the purl arch qualifier must agree")
	})

	t.Run("64-bit app on a 64-bit host", func(t *testing.T) {
		pkg := createPackage("Modern Tool", "1.2.3", "windows/app", "x86_64", "Acme", "", platform)
		require.NotNil(t, pkg)

		assert.Equal(t, "x86_64", purlQualifier(t, pkg.PUrl, "arch"))
	})

	t.Run("unknown package arch falls back to the host arch", func(t *testing.T) {
		// An empty arch means the registry path told us nothing. The host arch
		// is then the best available guess, and dropping the qualifier entirely
		// would lose information a match can use.
		pkg := createPackage("Mystery Tool", "1.2.3", "windows/app", "", "Acme", "", platform)
		require.NotNil(t, pkg)

		assert.Equal(t, "x86_64", purlQualifier(t, pkg.PUrl, "arch"),
			"an unknown package arch must still fall back to the platform arch")
	})
}

// purlQualifier returns the value of one qualifier of a purl, failing the test
// if the purl does not parse.
func purlQualifier(t *testing.T, rawPurl, key string) string {
	t.Helper()
	parsed, err := packageurl.FromString(rawPurl)
	require.NoError(t, err, "purl %q must parse", rawPurl)
	value, ok := parsed.Qualifiers.Map()[key]
	require.True(t, ok, "purl %q must carry a %q qualifier", rawPurl, key)
	return value
}

// TestHotFixesToPackages_SanitizesFields pins the analogous fix for the
// Get-HotFix path: Description goes through the same PowerShell→JSON
// pipeline, so any control character there has to be stripped before it
// reaches the Package.
func TestHotFixesToPackages_SanitizesFields(t *testing.T) {
	hotfixes := []PowershellWinHotFix{
		{HotFixId: "KB5005112\r\n", Description: "Security Update\r\n"},
		{HotFixId: "KB5023789", Description: "Update"},
	}
	pkgs := HotFixesToPackages(hotfixes)
	require.Len(t, pkgs, 2)

	assert.Equal(t, "KB5005112", pkgs[0].Name, "hotfix id must be sanitized")
	assert.Equal(t, "Security Update", pkgs[0].Description, "hotfix description must be sanitized")
	assert.NotContains(t, pkgs[0].Name, "\r")
	assert.NotContains(t, pkgs[0].Description, "\n")

	// Clean inputs must pass through unchanged.
	assert.Equal(t, "KB5023789", pkgs[1].Name)
	assert.Equal(t, "Update", pkgs[1].Description)
}

func TestFindAndUpdateMsExchangeSU_en(t *testing.T) {
	// Setup: create a list of packages with Exchange CU and SU
	packages := []Package{
		// This is the version of the latest CU installed on the machine
		{Name: "Microsoft Exchange Server", Version: "15.2.1748.10", PUrl: "pkg:windows/windows/Microsoft%20Exchange%20Server@15.2.1748.10?arch=AMD64"},
		// This is a SU for the CU and updates only the CU version, not the main Exchange Server version
		{Name: "Security Update for Exchange Server 2019 Cumulative Update 15 (KB5063221)", Version: "1", PUrl: "pkg:windows/windows/Security%20Update%20for%20Exchange%20Server%202019%20Cumulative%20Update%2015%20%28KB5063221%29@1?arch=AMD64"},
		// We need this version
		{Name: "Microsoft Exchange Server 2019 Cumulative Update 15", Version: "15.2.1748.36", PUrl: "pkg:windows/windows/Microsoft%20Exchange%20Server%202019%20Cumulative%20Update%2015@15.2.1748.36?arch=AMD64"},
		{Name: "Not a hotfix", Version: "1.0.0", PUrl: "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86"},
	}

	expectedLatestVersion := "15.2.1748.36"
	// Step 1: Find SQL Server hotfixes
	cu := findExchangeCU(packages)
	require.NotNil(t, cu)

	// Step 2: Update SQL Server packages with the latest hotfix version
	updated := updateExchangePackage(packages, *cu)

	// Step 3: Check that the Exchange Server package has the updated version
	pkg := findPkgByName(updated, "Microsoft Exchange Server")
	require.NotNil(t, pkg)
	require.Equal(t, expectedLatestVersion, pkg.Version)
	assert.Equal(t, "pkg:windows/windows/Microsoft%20Exchange%20Server@"+expectedLatestVersion+"?arch=AMD64", pkg.PUrl)

	// Step 5: Ensure non-SQL Server packages are unchanged
	pkg = findPkgByName(updated, "Not a hotfix")
	require.NotNil(t, pkg)
	require.Equal(t, "1.0.0", pkg.Version)
	assert.Equal(t, "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86", pkg.PUrl)
}

func TestFindAndUpdateMsExchangeSU_de(t *testing.T) {
	// Setup: create a list of packages with Exchange CU and SU
	packages := []Package{
		// This is the version of the latest CU installed on the machine
		{Name: "Microsoft Exchange Server", Version: "15.2.1748.10", PUrl: "pkg:windows/windows/Microsoft%20Exchange%20Server@15.2.1748.10?arch=AMD64"},
		// This is a SU for the CU and updates only the CU version, not the main Exchange Server version
		{Name: "Security Update für Exchange Server 2019 Kumulatives Update 15 (KB5063221)", Version: "1", PUrl: "pkg:windows/windows/Security%20Update%20f%C3%BCr%20Exchange%20Server%202019%20Kumulatives%20Update%2015%20%28KB5063221%29@1?arch=AMD64"},
		// We need this version
		{Name: "Microsoft Exchange Server 2019 Kumulatives Update 15", Version: "15.2.1748.36", PUrl: "pkg:windows/windows/Microsoft%20Exchange%20Server%202019%20Kumulatives%20Update%2015@15.2.1748.36?arch=AMD64"},
		{Name: "Not a hotfix", Version: "1.0.0", PUrl: "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86"},
	}

	expectedLatestVersion := "15.2.1748.36"
	// Step 1: Find SQL Server hotfixes
	cu := findExchangeCU(packages)
	require.NotNil(t, cu)

	// Step 2: Update SQL Server packages with the latest hotfix version
	updated := updateExchangePackage(packages, *cu)

	// Step 3: Check that the Exchange Server package has the updated version
	pkg := findPkgByName(updated, "Microsoft Exchange Server")
	require.NotNil(t, pkg)
	require.Equal(t, expectedLatestVersion, pkg.Version)
	assert.Equal(t, "pkg:windows/windows/Microsoft%20Exchange%20Server@"+expectedLatestVersion+"?arch=AMD64", pkg.PUrl)

	// Step 5: Ensure non-SQL Server packages are unchanged
	pkg = findPkgByName(updated, "Not a hotfix")
	require.NotNil(t, pkg)
	require.Equal(t, "1.0.0", pkg.Version)
	assert.Equal(t, "pkg:windows/windows/Not%20a%20hotfix@1.0.0?arch=x86", pkg.PUrl)
}

func TestParseWinInstallDate(t *testing.T) {
	// Happy path: YYYYMMDD as set by MSI installers.
	got := parseWinInstallDate("20240315")
	assert.Equal(t, time.Date(2024, time.March, 15, 0, 0, 0, 0, time.UTC), got)

	// Empty input (most non-MSI publishers omit InstallDate).
	assert.True(t, parseWinInstallDate("").IsZero())

	// Garbage doesn't crash, just returns zero.
	assert.True(t, parseWinInstallDate("not-a-date").IsZero())
	assert.True(t, parseWinInstallDate("2024-03-15").IsZero()) // wrong format
}

func TestWindowsAppPackagesParserInstallDate(t *testing.T) {
	// Two entries: one with InstallDate set, one missing it. Mirrors the
	// real-world mix in the Uninstall registry.
	jsonData := `[
		{"DisplayName":"App With Date","DisplayVersion":"1.0","Publisher":"Acme","EstimatedSize":100,"InstallSource":null,"UninstallString":"uninstall","InstallLocation":"","InstallDate":"20240315","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{abc}"},
		{"DisplayName":"App Without Date","DisplayVersion":"2.0","Publisher":"Acme","EstimatedSize":100,"InstallSource":null,"UninstallString":"uninstall","InstallLocation":"","PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{def}"}
	]`
	pf := &inventory.Platform{
		Name:    "windows",
		Version: "10.0.17763",
		Arch:    "amd64",
		Family:  []string{"windows"},
	}
	pkgs, err := ParseWindowsAppPackages(pf, strings.NewReader(jsonData))
	require.NoError(t, err)
	require.Equal(t, 2, len(pkgs))

	withDate := findPkg(pkgs, "App With Date")
	require.NotNil(t, withDate)
	assert.Equal(t, time.Date(2024, time.March, 15, 0, 0, 0, 0, time.UTC), withDate.InstallDate)

	withoutDate := findPkg(pkgs, "App Without Date")
	require.NotNil(t, withoutDate)
	assert.True(t, withoutDate.InstallDate.IsZero(), "missing InstallDate registry value yields zero time")
}

// regWireValue / regWireItem mirror the JSON shape emitted by the PowerShell
// registry probe (registry.GetRegistryKeyItemScript), so tests can feed
// getDotNetFramework's readRegistryItems realistic payloads.
type regWireValue struct {
	Kind int `json:"kind"`
	Data any `json:"data"`
}

type regWireItem struct {
	Key   string       `json:"key"`
	Value regWireValue `json:"value"`
}

func regItemsJSON(t *testing.T, items ...regWireItem) string {
	t.Helper()
	b, err := json.Marshal(items)
	require.NoError(t, err)
	return string(b)
}

func szItem(key, value string) regWireItem {
	return regWireItem{Key: key, Value: regWireValue{Kind: registry.SZ, Data: value}}
}

func dwordItem(key string, value int) regWireItem {
	return regWireItem{Key: key, Value: regWireValue{Kind: registry.DWORD, Data: value}}
}

func TestGetDotNetFramework(t *testing.T) {
	const (
		v4Key   = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full"
		v35Key  = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5"
		v4Path  = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"
		v35Path = "C:\\Windows\\Microsoft.NET\\Framework64\\v3.5\\"
	)

	// Command keys exactly as getDotNetFramework issues them over the connection.
	v4RegCmd := powershell.Encode(registry.GetRegistryKeyItemScript(v4Key))
	v35RegCmd := powershell.Encode(registry.GetRegistryKeyItemScript(v35Key))
	v4VerCmd := powershell.Encode(fmt.Sprintf(dotNetClrVersionScript, v4Path))
	v35VerCmd := powershell.Encode(dotNetClr2VersionScript)

	v4RegItems := regItemsJSON(t, szItem("InstallPath", v4Path), dwordItem("Release", 528449))
	v4RegNoPath := regItemsJSON(t, dwordItem("Release", 528449))
	v35Installed := regItemsJSON(t, dwordItem("Install", 1), szItem("InstallPath", v35Path))
	v35NotInstalled := regItemsJSON(t, dwordItem("Install", 0), szItem("InstallPath", v35Path))

	// Trailing CRLF verifies runPwshVersion trims the raw stdout.
	v4Ver := snapCommandResult{stdout: "4.8.4795.0\r\n"}
	v35Ver := snapCommandResult{stdout: "2.0.50727.9182\r\n"}

	type wantPkg struct {
		name    string
		version string
	}
	tests := []struct {
		name     string
		commands map[string]snapCommandResult
		want     []wantPkg
	}{
		{
			name: "both 3.5 and 4.x present, reported side by side",
			commands: map[string]snapCommandResult{
				v4RegCmd:  {stdout: v4RegItems},
				v4VerCmd:  v4Ver,
				v35RegCmd: {stdout: v35Installed},
				v35VerCmd: v35Ver,
			},
			want: []wantPkg{
				{"Microsoft .NET Framework", "4.8.4795.0"},
				{"Microsoft .NET Framework", "2.0.50727.9182"},
			},
		},
		{
			name: "only 4.x present (v3.5 key missing)",
			commands: map[string]snapCommandResult{
				v4RegCmd: {stdout: v4RegItems},
				v4VerCmd: v4Ver,
			},
			want: []wantPkg{{"Microsoft .NET Framework", "4.8.4795.0"}},
		},
		{
			name: "only 3.5 present (v4 key missing), sourced from CLR 2.0 build",
			commands: map[string]snapCommandResult{
				v35RegCmd: {stdout: v35Installed},
				v35VerCmd: v35Ver,
			},
			want: []wantPkg{{"Microsoft .NET Framework", "2.0.50727.9182"}},
		},
		{
			name: "3.5 key present but Install=0 is not reported",
			commands: map[string]snapCommandResult{
				v4RegCmd:  {stdout: v4RegItems},
				v4VerCmd:  v4Ver,
				v35RegCmd: {stdout: v35NotInstalled},
				v35VerCmd: v35Ver,
			},
			want: []wantPkg{{"Microsoft .NET Framework", "4.8.4795.0"}},
		},
		{
			name: "4.x key present without InstallPath is skipped",
			commands: map[string]snapCommandResult{
				v4RegCmd: {stdout: v4RegNoPath},
				v4VerCmd: v4Ver,
			},
			want: nil,
		},
		{
			name: "4.x present but clr.dll version blank is skipped",
			commands: map[string]snapCommandResult{
				v4RegCmd: {stdout: v4RegItems},
				v4VerCmd: {stdout: "\r\n"},
			},
			want: nil,
		},
		{
			name:     "neither runtime present",
			commands: map[string]snapCommandResult{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &WinPkgManager{
				conn:     &snapTestConnection{commands: tt.commands},
				platform: &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}},
			}

			pkgs, err := w.getDotNetFramework()
			require.NoError(t, err)
			require.Len(t, pkgs, len(tt.want))
			for i, exp := range tt.want {
				assert.Equal(t, exp.name, pkgs[i].Name, "package %d name", i)
				assert.Equal(t, exp.version, pkgs[i].Version, "package %d version", i)
				assert.Equal(t, "windows/app", pkgs[i].Format, "package %d format", i)
				assert.Equal(t, "amd64", pkgs[i].Arch, "package %d arch", i)
			}
		})
	}
}
