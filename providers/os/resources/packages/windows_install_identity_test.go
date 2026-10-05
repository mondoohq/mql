// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/registry"
)

// Every GUID below was read from a real Windows 11 host: the packed names from
// HKLM\SOFTWARE\Classes\Installer\UpgradeCodes, the braced ones from the
// matching Uninstall key names.
const (
	sevenZipPackedUpgrade = "96F071321C0420720000000040000000"
	sevenZipPackedProduct = "96F071321C0420726230000010000000"
	sevenZipProductKey    = "{23170F69-40C1-2702-2603-000001000000}"

	vcRuntimePackedUpgrade = "24EAB9CDB018A324E9524E70F3C1B700"
	vcRuntimePackedProduct = "DF89D7E19A793EE40BE85FE369FD4319"
	vcRuntimeProductKey    = "{1E7D98FD-97A9-4EE3-B08E-F53E96DF3491}"

	vcBundleKey         = "{f4fca927-ceb7-4549-8782-5835bd91078c}"
	vcBundleUpgradeCode = "{F608407A-6091-42E0-A1BA-B8FFFC21199B}"
)

func TestUnpackMsiGUIDMatchesTheUninstallKey(t *testing.T) {
	// The packed ProductCode under UpgradeCodes and the Uninstall key name are
	// the same GUID in two spellings; unpacking must land on the key exactly.
	assert.Equal(t, normalizeGUID(sevenZipProductKey), unpackMsiGUID(sevenZipPackedProduct))
	assert.Equal(t, normalizeGUID(vcRuntimeProductKey), unpackMsiGUID(vcRuntimePackedProduct))
	assert.Equal(t, "23170F69-40C1-2702-0000-000004000000", unpackMsiGUID(sevenZipPackedUpgrade))

	assert.Equal(t, "", unpackMsiGUID("not-a-packed-guid"))
	assert.Equal(t, "", unpackMsiGUID(strings.Repeat("Z", 32)))
}

func TestNormalizeGUID(t *testing.T) {
	assert.Equal(t, "F4FCA927-CEB7-4549-8782-5835BD91078C", normalizeGUID(vcBundleKey))
	assert.Equal(t, "F4FCA927-CEB7-4549-8782-5835BD91078C", normalizeGUID("f4fca927-ceb7-4549-8782-5835bd91078c"))
	assert.Equal(t, "", normalizeGUID("Notepad3_is1"))
	// The packed form Windows Installer uses in key names is not a GUID spelling
	// this accepts; only unpackMsiGUID turns it into one.
	assert.Equal(t, "", normalizeGUID(sevenZipPackedProduct))
	assert.Equal(t, "", normalizeGUID("23170F6940C127022603000001000000"))
	assert.Equal(t, "", normalizeGUID(""))
}

func TestInstallIdentityQualifiers(t *testing.T) {
	upgradeCodes := map[string]string{
		unpackMsiGUID(sevenZipPackedProduct): unpackMsiGUID(sevenZipPackedUpgrade),
	}
	tests := []struct {
		name string
		id   installIdentity
		want map[string]string
	}{
		{
			name: "MSI entry carries its ProductCode and the product line's UpgradeCode",
			id:   *newInstallIdentity(sevenZipProductKey, true, "", ""),
			want: map[string]string{
				"product_code": "23170F69-40C1-2702-2603-000001000000",
				"upgrade_code": "23170F69-40C1-2702-0000-000004000000",
				"installer":    "msi",
			},
		},
		{
			name: "MSI entry whose UpgradeCode is unknown keeps the ProductCode alone",
			id:   *newInstallIdentity(vcRuntimeProductKey, true, "", ""),
			want: map[string]string{"product_code": "1E7D98FD-97A9-4EE3-B08E-F53E96DF3491", "installer": "msi"},
		},
		{
			name: "Burn bundle: the stable BundleUpgradeCode, not the per-release key",
			id:   *newInstallIdentity(vcBundleKey, false, vcBundleUpgradeCode, ""),
			want: map[string]string{"upgrade_code": "F608407A-6091-42E0-A1BA-B8FFFC21199B", "installer": "burn"},
		},
		{
			name: "Inno Setup: AppId without the _is1 suffix",
			id:   *newInstallIdentity("Notepad3_is1", false, "", ""),
			want: map[string]string{"app_id": "Notepad3", "installer": "inno"},
		},
		{
			name: "Inno Setup with a GUID AppId",
			id:   *newInstallIdentity("{0D7F1B8E-1B0A-4B2C-9F1E-4E6B5F6A7C8D}_is1", false, "", ""),
			want: map[string]string{"app_id": "0D7F1B8E-1B0A-4B2C-9F1E-4E6B5F6A7C8D", "installer": "inno"},
		},
		{
			name: "install4j / NSIS / custom: the key as the installer wrote it",
			id:   *newInstallIdentity("9806-1938-4586-6531", false, "", ""),
			want: map[string]string{"app_id": "9806-1938-4586-6531", "installer": "unknown"},
		},
		{
			name: "a GUID key without WindowsInstaller=1 is an installer-chosen id, not a ProductCode",
			id:   *newInstallIdentity(vcRuntimeProductKey, false, "", ""),
			want: map[string]string{"app_id": "1E7D98FD-97A9-4EE3-B08E-F53E96DF3491", "installer": "unknown"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.id.qualifiers(upgradeCodes))
		})
	}
}

func TestInstallIdentityFromItems(t *testing.T) {
	items := []registry.RegistryKeyItem{
		{Key: "DisplayName", Value: registry.RegistryKeyValue{Kind: registry.SZ, String: "Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.42.34438"}},
		{Key: "BundleUpgradeCode", Value: registry.RegistryKeyValue{Kind: registry.MULTI_SZ, MultiString: []string{vcBundleUpgradeCode}}},
	}
	id := installIdentityFromItems(vcBundleKey, items)
	assert.Equal(t, vcBundleKey, id.uninstallKey)
	assert.False(t, id.windowsInstaller)
	assert.Equal(t, vcBundleUpgradeCode, id.bundleUpgradeCode)

	msi := installIdentityFromItems(sevenZipProductKey, []registry.RegistryKeyItem{
		{Key: "WindowsInstaller", Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: 1}},
	})
	assert.True(t, msi.windowsInstaller)
}

func TestMsiUpgradeCodesFromKeys(t *testing.T) {
	got := msiUpgradeCodesFromKeys(
		func() ([]registry.RegistryKeyChild, error) {
			return []registry.RegistryKeyChild{{Name: sevenZipPackedUpgrade}, {Name: "garbage"}}, nil
		},
		func(child string) ([]registry.RegistryKeyItem, error) {
			return []registry.RegistryKeyItem{{Key: sevenZipPackedProduct}, {Key: ""}}, nil
		},
	)
	assert.Equal(t, map[string]string{
		"23170F69-40C1-2702-2603-000001000000": "23170F69-40C1-2702-0000-000004000000",
	}, got)
}

func TestApplyInstallIdentityKeepsExistingQualifiers(t *testing.T) {
	pf := &inventory.Platform{Name: "windows", Arch: "x86_64", Family: []string{"windows"}}
	pkg := createPackage("7-Zip 26.03 (x64 edition)", "26.03.00.0", "windows/app", "x86_64", "Igor Pavlov", "", pf)
	pkg.installIdentity = newInstallIdentity(sevenZipProductKey, true, "", "")
	pkgs := []Package{*pkg}

	applyInstallIdentityQualifiers(pkgs, map[string]string{
		unpackMsiGUID(sevenZipPackedProduct): unpackMsiGUID(sevenZipPackedUpgrade),
	})

	assert.Equal(t, "x86_64", purlQualifier(t, pkgs[0].PUrl, "arch"), "arch must survive")
	assert.Equal(t, "23170F69-40C1-2702-2603-000001000000", purlQualifier(t, pkgs[0].PUrl, "product_code"))
	assert.Equal(t, "23170F69-40C1-2702-0000-000004000000", purlQualifier(t, pkgs[0].PUrl, "upgrade_code"))
	assert.True(t, strings.HasPrefix(pkgs[0].PUrl, "pkg:windows/windows/7-Zip%2026.03%20%28x64%20edition%29@26.03.00.0?"),
		"the name and version stay exactly what they were: %s", pkgs[0].PUrl)
}

func TestApplyInstallIdentityLeavesOtherFormatsAlone(t *testing.T) {
	pf := &inventory.Platform{Name: "windows", Arch: "x86_64", Family: []string{"windows"}}
	appx := createPackage("Microsoft.WindowsTerminal", "1.20.0.0", "windows/appx", "x86_64", "Microsoft", "", pf)
	appx.installIdentity = newInstallIdentity("Notepad3_is1", false, "", "")
	before := appx.PUrl
	pkgs := []Package{*appx}
	applyInstallIdentityQualifiers(pkgs, nil)
	assert.Equal(t, before, pkgs[0].PUrl)
}

// The two Add/Remove Programs entries of one .NET runtime install (Burn bundle
// + MSI) collapse on their identical purl. Identity is stamped after that
// collapse, so they must still fold into one row, and the row keeps the MSI
// entry's identity whichever of the two arrived first.
func TestCollapseThenIdentityKeepsDotNetPairsFolded(t *testing.T) {
	pf := &inventory.Platform{Name: "windows", Arch: "x86_64", Family: []string{"windows"}}
	bundle := createPackage("Microsoft .NET Runtime - 8.0.21 (x64)", "8.0.21", "windows/app", "x86_64", "Microsoft Corporation", "", pf)
	bundle.installIdentity = newInstallIdentity(vcBundleKey, false, vcBundleUpgradeCode, "")
	msi := createPackage("Microsoft .NET Runtime - 8.0.21 (x64)", "8.0.21", "windows/app", "x86_64", "Microsoft Corporation", "", pf)
	msi.installIdentity = newInstallIdentity(vcRuntimeProductKey, true, "", "")

	for _, order := range [][]Package{{*bundle, *msi}, {*msi, *bundle}} {
		w := &WinPkgManager{}
		out := w.withInstallIdentity(collapsePackages(order))
		require.Len(t, out, 1)
		assert.Equal(t, "1E7D98FD-97A9-4EE3-B08E-F53E96DF3491", purlQualifier(t, out[0].PUrl, "product_code"))
		assert.Equal(t, "msi", purlQualifier(t, out[0].PUrl, "installer"))
	}
}

func TestParseWindowsAppPackagesReadsIdentity(t *testing.T) {
	pf := &inventory.Platform{Name: "windows", Arch: "x86_64", Family: []string{"windows"}}
	data := `[
	  {"DisplayName":"7-Zip 26.03 (x64 edition)","DisplayVersion":"26.03.00.0","Publisher":"Igor Pavlov",
	   "UninstallString":"MsiExec.exe /I{23170F69-40C1-2702-2603-000001000000}",
	   "PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{23170F69-40C1-2702-2603-000001000000}",
	   "WindowsInstaller":1,"BundleUpgradeCode":null},
	  {"DisplayName":"Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.42.34438","DisplayVersion":"14.42.34438.0",
	   "UninstallString":"\"C:\\ProgramData\\Package Cache\\{f4fca927-ceb7-4549-8782-5835bd91078c}\\VC_redist.arm64.exe\" /uninstall",
	   "PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{f4fca927-ceb7-4549-8782-5835bd91078c}",
	   "BundleUpgradeCode":["{F608407A-6091-42E0-A1BA-B8FFFC21199B}"]},
	  {"DisplayName":"Notepad3 (x64) 7.26.602.1","DisplayVersion":"7.26.602.1",
	   "UninstallString":"\"C:\\Program Files\\Notepad3\\unins000.exe\"",
	   "PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Notepad3_is1"},
	  {"DisplayName":"Realtek High Definition Audio Driver","DisplayVersion":"6.0.9235.1",
	   "UninstallString":"\"C:\\Program Files (x86)\\InstallShield Installation Information\\{F132AF7F-7BCA-4EDE-8A7C-958108FE7DBC}\\Setup.exe\" -runfromtemp -l0x0409  -removeonly",
	   "PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{F132AF7F-7BCA-4EDE-8A7C-958108FE7DBC}",
	   "InstallScope":"machine"},
	  {"DisplayName":"Slack","DisplayVersion":"4.41.105",
	   "UninstallString":"\"C:\\Users\\user\\AppData\\Local\\slack\\Update.exe\" --uninstall -s",
	   "PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_USERS\\S-1-5-21-1004336348-1177238915-682003330-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\slack",
	   "InstallScope":"user","InstallUser":"S-1-5-21-1004336348-1177238915-682003330-1001"}
	]`
	pkgs, err := parseWindowsAppPackages(pf, strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, pkgs, 5)

	applyInstallIdentityQualifiers(pkgs, nil)
	assert.Equal(t, "23170F69-40C1-2702-2603-000001000000", purlQualifier(t, pkgs[0].PUrl, "product_code"))
	assert.Equal(t, "F608407A-6091-42E0-A1BA-B8FFFC21199B", purlQualifier(t, pkgs[1].PUrl, "upgrade_code"))
	assert.Equal(t, "Notepad3", purlQualifier(t, pkgs[2].PUrl, "app_id"))

	installers := []string{"msi", "burn", "inno", "installshield", "unknown"}
	for i, want := range installers {
		assert.Equal(t, want, purlQualifier(t, pkgs[i].PUrl, "installer"), pkgs[i].Name)
	}
	assert.Equal(t, "user", purlQualifier(t, pkgs[4].PUrl, "install-scope"))
	for i := range 4 {
		assert.False(t, hasPurlQualifier(t, pkgs[i].PUrl, "install-scope"), pkgs[i].Name)
	}
}

func TestFirstJSONString(t *testing.T) {
	assert.Equal(t, "a", firstJSONString([]byte(`["a","b"]`)))
	assert.Equal(t, "a", firstJSONString([]byte(`"a"`)))
	assert.Equal(t, "", firstJSONString([]byte(`null`)))
	assert.Equal(t, "", firstJSONString(nil))
	assert.Equal(t, "", firstJSONString([]byte(`[]`)))
}

func TestMsiUpgradeCodesFromPowershellOutput(t *testing.T) {
	got := msiUpgradeCodesFromPowershellOutput([]msiUpgradeCodeRow{
		{U: sevenZipPackedUpgrade, P: []string{sevenZipPackedProduct}},
		{U: vcRuntimePackedUpgrade, P: []string{vcRuntimePackedProduct}},
	})
	assert.Equal(t, "23170F69-40C1-2702-0000-000004000000", got["23170F69-40C1-2702-2603-000001000000"])
	assert.Equal(t, unpackMsiGUID(vcRuntimePackedUpgrade), got["1E7D98FD-97A9-4EE3-B08E-F53E96DF3491"])
}

// Windows PowerShell 5.1 emits one element piped into ConvertTo-Json as a bare
// object (verified on a Windows 11 host); both shapes must parse.
func TestParseMsiUpgradeCodeRowsAcceptsArrayAndSingleObject(t *testing.T) {
	array := `[{"U":"` + sevenZipPackedUpgrade + `","P":["` + sevenZipPackedProduct + `"]}]`
	single := `{"U":"` + sevenZipPackedUpgrade + `","P":["` + sevenZipPackedProduct + `"]}`
	for _, in := range []string{array, single} {
		rows, err := parseMsiUpgradeCodeRows([]byte(in))
		require.NoError(t, err, in)
		assert.Equal(t, "23170F69-40C1-2702-0000-000004000000",
			msiUpgradeCodesFromPowershellOutput(rows)["23170F69-40C1-2702-2603-000001000000"], in)
	}
	_, err := parseMsiUpgradeCodeRows([]byte(`"nope"`))
	assert.Error(t, err)
}

// Uninstall entries shaped the way each installer writes them: the key name
// and the values the installer rule reads, for each installer value.
func installerTestEntries() []struct {
	name  string
	key   string
	items []registry.RegistryKeyItem
	want  string
} {
	sz := func(k, v string) registry.RegistryKeyItem {
		return registry.RegistryKeyItem{Key: k, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: v}}
	}
	dword := func(k string, v int64) registry.RegistryKeyItem {
		return registry.RegistryKeyItem{Key: k, Value: registry.RegistryKeyValue{Kind: registry.DWORD, Number: v}}
	}
	return []struct {
		name  string
		key   string
		items []registry.RegistryKeyItem
		want  string
	}{
		{
			name: "MSI: 7-Zip x64",
			key:  sevenZipProductKey,
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "7-Zip 26.03 (x64 edition)"),
				sz("UninstallString", "MsiExec.exe /I{23170F69-40C1-2702-2603-000001000000}"),
				dword("WindowsInstaller", 1),
			},
			want: "msi",
		},
		{
			name: "Burn: Visual C++ redistributable bundle",
			key:  vcBundleKey,
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.42.34438"),
				sz("UninstallString", `"C:\ProgramData\Package Cache\{f4fca927-ceb7-4549-8782-5835bd91078c}\VC_redist.arm64.exe"  /uninstall`),
				sz("BundleCachePath", `C:\ProgramData\Package Cache\{f4fca927-ceb7-4549-8782-5835bd91078c}\VC_redist.arm64.exe`),
				{Key: "BundleUpgradeCode", Value: registry.RegistryKeyValue{Kind: registry.MULTI_SZ, MultiString: []string{vcBundleUpgradeCode}}},
			},
			want: "burn",
		},
		{
			name: "Inno Setup: Notepad3",
			key:  "Notepad3_is1",
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "Notepad3 (x64) 7.26.602.1"),
				sz("UninstallString", `"C:\Program Files\Notepad3\unins000.exe"`),
			},
			want: "inno",
		},
		{
			name: "InstallShield: Realtek audio driver setup",
			key:  "{F132AF7F-7BCA-4EDE-8A7C-958108FE7DBC}",
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "Realtek High Definition Audio Driver"),
				sz("UninstallString", `"C:\Program Files (x86)\InstallShield Installation Information\{F132AF7F-7BCA-4EDE-8A7C-958108FE7DBC}\Setup.exe" -runfromtemp -l0x0409  -removeonly`),
			},
			want: "installshield",
		},
		{
			name: "vendor bootstrapper: Google Chrome's setup.exe",
			key:  "Google Chrome",
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "Google Chrome"),
				sz("UninstallString", `"C:\Program Files\Google\Chrome\Application\129.0.6668.90\Installer\setup.exe" --uninstall --channel=stable --system-level --verbose-logging`),
			},
			want: "unknown",
		},
		{
			name: "Squirrel: per-user Update.exe",
			key:  "slack",
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "Slack"),
				sz("UninstallString", `"C:\Users\user\AppData\Local\slack\Update.exe" --uninstall -s`),
			},
			want: "unknown",
		},
		{
			name: "WindowsInstaller=1 on a key that is not a ProductCode is not msi",
			key:  "ExampleProduct",
			items: []registry.RegistryKeyItem{
				sz("DisplayName", "Example Product"),
				sz("UninstallString", `"C:\Program Files\Example\uninstall.exe"`),
				dword("WindowsInstaller", 1),
			},
			want: "unknown",
		},
	}
}

func TestInstallerQualifier(t *testing.T) {
	for _, tc := range installerTestEntries() {
		t.Run(tc.name, func(t *testing.T) {
			q := installIdentityFromItems(tc.key, tc.items).qualifiers(nil)
			assert.Equal(t, tc.want, q["installer"])
		})
	}
}

// installer=msi is reported exactly when product_code is, and installer=burn
// exactly when the bundle's BundleUpgradeCode becomes upgrade_code.
func TestInstallerQualifierInvariants(t *testing.T) {
	for _, tc := range installerTestEntries() {
		t.Run(tc.name, func(t *testing.T) {
			id := installIdentityFromItems(tc.key, tc.items)
			q := id.qualifiers(nil)
			_, hasProductCode := q["product_code"]
			assert.Equal(t, hasProductCode, q["installer"] == "msi")
			burnBranch := normalizeGUID(id.bundleUpgradeCode) != ""
			assert.Equal(t, burnBranch, q["installer"] == "burn")
			if burnBranch {
				assert.Equal(t, normalizeGUID(id.bundleUpgradeCode), q["upgrade_code"])
			}
		})
	}
}

func TestIsInstallShieldUninstall(t *testing.T) {
	assert.True(t, isInstallShieldUninstall(`"C:\Program Files (x86)\InstallShield Installation Information\{F132AF7F-7BCA-4EDE-8A7C-958108FE7DBC}\Setup.exe" -runfromtemp -l0x0409  -removeonly`))
	assert.True(t, isInstallShieldUninstall(`C:\PROGRAM FILES\INSTALLSHIELD INSTALLATION INFORMATION\{X}\setup.exe`))
	assert.False(t, isInstallShieldUninstall(`"C:\Program Files\Notepad3\unins000.exe"`))
	assert.False(t, isInstallShieldUninstall(""))
}

func TestInstallScopeQualifier(t *testing.T) {
	pf := &inventory.Platform{Name: "windows", Arch: "x86_64", Family: []string{"windows"}}
	user := createPackage("Slack", "4.41.105", "windows/app", "x86_64", "Slack Technologies Inc.", "", pf)
	user.InstallScope = installScopeUser
	user.InstallUser = "S-1-5-21-1004336348-1177238915-682003330-1001"
	user.installIdentity = newInstallIdentity("slack", false, "", `"C:\Users\user\AppData\Local\slack\Update.exe" --uninstall -s`)
	machine := createPackage("7-Zip 26.03 (x64 edition)", "26.03.00.0", "windows/app", "x86_64", "Igor Pavlov", "", pf)
	machine.InstallScope = installScopeMachine
	machine.installIdentity = newInstallIdentity(sevenZipProductKey, true, "", "")
	// No identity (a path that cannot read the Uninstall values): scope still
	// says where the entry was read from, installer stays unreported.
	userNoIdentity := createPackage("Postman x64", "11.2.0", "windows/app", "x86_64", "Postman", "", pf)
	userNoIdentity.InstallScope = installScopeUser
	appx := createPackage("Microsoft.WindowsTerminal", "1.20.0.0", "windows/appx", "x86_64", "Microsoft", "", pf)
	appx.InstallScope = installScopeUser

	pkgs := []Package{*user, *machine, *userNoIdentity, *appx}
	appxBefore := appx.PUrl
	applyInstallIdentityQualifiers(pkgs, nil)

	assert.Equal(t, "user", purlQualifier(t, pkgs[0].PUrl, "install-scope"))
	assert.Equal(t, "unknown", purlQualifier(t, pkgs[0].PUrl, "installer"))
	assert.Equal(t, "slack", purlQualifier(t, pkgs[0].PUrl, "app_id"))

	assert.False(t, hasPurlQualifier(t, pkgs[1].PUrl, "install-scope"), "machine-wide installs carry no install-scope")
	assert.Equal(t, "msi", purlQualifier(t, pkgs[1].PUrl, "installer"))

	assert.Equal(t, "user", purlQualifier(t, pkgs[2].PUrl, "install-scope"))
	assert.False(t, hasPurlQualifier(t, pkgs[2].PUrl, "installer"))

	assert.Equal(t, appxBefore, pkgs[3].PUrl, "Store apps get neither qualifier")
}

func hasPurlQualifier(t *testing.T, rawPurl, key string) bool {
	t.Helper()
	parsed, err := packageurl.FromString(rawPurl)
	require.NoError(t, err, "purl %q must parse", rawPurl)
	_, ok := parsed.Qualifiers.Map()[key]
	return ok
}
