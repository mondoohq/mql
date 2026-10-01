// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"

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
			id:   installIdentity{uninstallKey: sevenZipProductKey, windowsInstaller: true},
			want: map[string]string{
				"product_code": "23170F69-40C1-2702-2603-000001000000",
				"upgrade_code": "23170F69-40C1-2702-0000-000004000000",
			},
		},
		{
			name: "MSI entry whose UpgradeCode is unknown keeps the ProductCode alone",
			id:   installIdentity{uninstallKey: vcRuntimeProductKey, windowsInstaller: true},
			want: map[string]string{"product_code": "1E7D98FD-97A9-4EE3-B08E-F53E96DF3491"},
		},
		{
			name: "Burn bundle: the stable BundleUpgradeCode, not the per-release key",
			id:   installIdentity{uninstallKey: vcBundleKey, bundleUpgradeCode: vcBundleUpgradeCode},
			want: map[string]string{"upgrade_code": "F608407A-6091-42E0-A1BA-B8FFFC21199B"},
		},
		{
			name: "Inno Setup: AppId without the _is1 suffix",
			id:   installIdentity{uninstallKey: "Notepad3_is1"},
			want: map[string]string{"app_id": "Notepad3"},
		},
		{
			name: "Inno Setup with a GUID AppId",
			id:   installIdentity{uninstallKey: "{0D7F1B8E-1B0A-4B2C-9F1E-4E6B5F6A7C8D}_is1"},
			want: map[string]string{"app_id": "0D7F1B8E-1B0A-4B2C-9F1E-4E6B5F6A7C8D"},
		},
		{
			name: "install4j / NSIS / custom: the key as the installer wrote it",
			id:   installIdentity{uninstallKey: "9806-1938-4586-6531"},
			want: map[string]string{"app_id": "9806-1938-4586-6531"},
		},
		{
			name: "a GUID key without WindowsInstaller=1 is an installer-chosen id, not a ProductCode",
			id:   installIdentity{uninstallKey: vcRuntimeProductKey},
			want: map[string]string{"app_id": "1E7D98FD-97A9-4EE3-B08E-F53E96DF3491"},
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
	pkg.installIdentity = &installIdentity{uninstallKey: sevenZipProductKey, windowsInstaller: true}
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
	appx.installIdentity = &installIdentity{uninstallKey: "Notepad3_is1"}
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
	bundle.installIdentity = &installIdentity{uninstallKey: vcBundleKey, bundleUpgradeCode: vcBundleUpgradeCode}
	msi := createPackage("Microsoft .NET Runtime - 8.0.21 (x64)", "8.0.21", "windows/app", "x86_64", "Microsoft Corporation", "", pf)
	msi.installIdentity = &installIdentity{uninstallKey: vcRuntimeProductKey, windowsInstaller: true}

	for _, order := range [][]Package{{*bundle, *msi}, {*msi, *bundle}} {
		w := &WinPkgManager{}
		out := w.withInstallIdentity(collapsePackages(order))
		require.Len(t, out, 1)
		assert.Equal(t, "1E7D98FD-97A9-4EE3-B08E-F53E96DF3491", purlQualifier(t, out[0].PUrl, "product_code"))
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
	   "PSPath":"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Notepad3_is1"}
	]`
	pkgs, err := parseWindowsAppPackages(pf, strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	applyInstallIdentityQualifiers(pkgs, nil)
	assert.Equal(t, "23170F69-40C1-2702-2603-000001000000", purlQualifier(t, pkgs[0].PUrl, "product_code"))
	assert.Equal(t, "F608407A-6091-42E0-A1BA-B8FFFC21199B", purlQualifier(t, pkgs[1].PUrl, "upgrade_code"))
	assert.Equal(t, "Notepad3", purlQualifier(t, pkgs[2].PUrl, "app_id"))
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
