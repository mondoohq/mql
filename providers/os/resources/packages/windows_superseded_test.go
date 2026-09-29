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

func winX64Platform() *inventory.Platform {
	return &inventory.Platform{Name: "windows", Version: "10.0.26100", Arch: "x86_64", Family: []string{"windows"}}
}

const (
	hklmUninstall    = `Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\`
	hklmWowUninstall = `Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\`
)

// sevenZipExe23 is the entry 7-Zip's EXE installer registers under its fixed
// key "Uninstall\7-Zip". DisplayName, DisplayVersion and the directory are
// as observed on a Windows 11 host that was then upgraded with the MSI. The
// UninstallString and DisplayIcon were not captured from that host; they
// follow the shape this installer writes.
const sevenZipExe23 = `{
	"DisplayName": "7-Zip 23.01 (x64)",
	"DisplayVersion": "23.01",
	"Publisher": "Igor Pavlov",
	"UninstallString": "\"C:\\Program Files\\7-Zip\\Uninstall.exe\"",
	"InstallLocation": "C:\\Program Files\\7-Zip\\",
	"DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe",
	"PSPath": "` + hklmUninstall + `7-Zip",
	"InstallScope": "machine",
	"InstallUser": ""
}`

// sevenZipMsi26 is the entry the 7-Zip MSI registers under its product code
// key, on the same host after the upgrade. DisplayName, DisplayVersion and
// directory are as observed; the product code and UninstallString were not
// captured from that host and follow 7-Zip's MSI product-code scheme.
const sevenZipMsi26 = `{
	"DisplayName": "7-Zip 26.03 (x64 edition)",
	"DisplayVersion": "26.03.00.0",
	"Publisher": "Igor Pavlov",
	"UninstallString": "MsiExec.exe /I{23170F69-40C1-2702-2603-000001000000}",
	"InstallLocation": "C:\\Program Files\\7-Zip\\",
	"DisplayIcon": null,
	"PSPath": "` + hklmUninstall + `{23170F69-40C1-2702-2603-000001000000}",
	"InstallScope": "machine",
	"InstallUser": ""
}`

func parseEntries(t *testing.T, entries ...string) []Package {
	t.Helper()
	pkgs, err := ParseWindowsAppPackages(winX64Platform(), strings.NewReader("["+strings.Join(entries, ",")+"]"))
	require.NoError(t, err)
	return pkgs
}

func namesAndVersions(pkgs []Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name+" "+p.Version)
	}
	return out
}

// The observed case: the EXE's 23.01 entry and the MSI's 26.03 entry share
// C:\Program Files\7-Zip\, which holds only the 26.03 files.
func TestSupersededEntries_SevenZipExeToMsiUpgrade(t *testing.T) {
	for _, order := range [][]string{{sevenZipExe23, sevenZipMsi26}, {sevenZipMsi26, sevenZipExe23}} {
		pkgs := parseEntries(t, order...)
		require.Len(t, pkgs, 1, "the stale 23.01 registration must be dropped: %v", namesAndVersions(pkgs))
		assert.Equal(t, "7-Zip 26.03 (x64 edition)", pkgs[0].Name)
		assert.Equal(t, "26.03.00.0", pkgs[0].Version)
		assert.Nil(t, pkgs[0].uninstallEvidence, "path evidence must not outlive the filter")
	}
}

// The MSI entry carries no InstallLocation. Its UninstallString names no
// directory (MsiExec.exe /I{GUID}); DisplayIcon decides.
func TestSupersededEntries_MsiWithoutInstallLocation(t *testing.T) {
	t.Run("icon in the product directory places it there", func(t *testing.T) {
		msi := strings.Replace(sevenZipMsi26, `"InstallLocation": "C:\\Program Files\\7-Zip\\"`, `"InstallLocation": ""`, 1)
		msi = strings.Replace(msi, `"DisplayIcon": null`, `"DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe,0"`, 1)
		pkgs := parseEntries(t, sevenZipExe23, msi)
		require.Len(t, pkgs, 1, namesAndVersions(pkgs))
		assert.Equal(t, "26.03.00.0", pkgs[0].Version)
	})

	t.Run("no icon: no directory, both kept", func(t *testing.T) {
		msi := strings.Replace(sevenZipMsi26, `"InstallLocation": "C:\\Program Files\\7-Zip\\"`, `"InstallLocation": null`, 1)
		pkgs := parseEntries(t, sevenZipExe23, msi)
		assert.ElementsMatch(t, []string{"7-Zip 23.01 (x64) 23.01", "7-Zip 26.03 (x64 edition) 26.03.00.0"}, namesAndVersions(pkgs))
	})

	t.Run("icon cached by Windows Installer: no directory, both kept", func(t *testing.T) {
		msi := strings.Replace(sevenZipMsi26, `"InstallLocation": "C:\\Program Files\\7-Zip\\"`, `"InstallLocation": ""`, 1)
		msi = strings.Replace(msi, `"DisplayIcon": null`, `"DisplayIcon": "C:\\WINDOWS\\Installer\\{23170F69-40C1-2702-2603-000001000000}\\7zFM.exe"`, 1)
		pkgs := parseEntries(t, sevenZipExe23, msi)
		assert.Len(t, pkgs, 2, namesAndVersions(pkgs))
	})

	t.Run("EXE entry without InstallLocation falls back to its uninstaller", func(t *testing.T) {
		exe := strings.Replace(sevenZipExe23, `"InstallLocation": "C:\\Program Files\\7-Zip\\"`, `"InstallLocation": ""`, 1)
		exe = strings.Replace(exe, `"DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe"`, `"DisplayIcon": ""`, 1)
		pkgs := parseEntries(t, exe, sevenZipMsi26)
		require.Len(t, pkgs, 1, namesAndVersions(pkgs))
		assert.Equal(t, "26.03.00.0", pkgs[0].Version)
	})
}

// The same product in two directories is two installs.
func TestSupersededEntries_DifferentDirectoriesKept(t *testing.T) {
	t.Run("x86 build in Program Files (x86), x64 build in Program Files", func(t *testing.T) {
		x86 := `{
			"DisplayName": "7-Zip 23.01",
			"DisplayVersion": "23.01",
			"Publisher": "Igor Pavlov",
			"UninstallString": "\"C:\\Program Files (x86)\\7-Zip\\Uninstall.exe\"",
			"InstallLocation": "C:\\Program Files (x86)\\7-Zip\\",
			"DisplayIcon": "C:\\Program Files (x86)\\7-Zip\\7zFM.exe",
			"PSPath": "` + hklmWowUninstall + `7-Zip",
			"InstallScope": "machine"
		}`
		pkgs := parseEntries(t, x86, sevenZipMsi26)
		assert.ElementsMatch(t, []string{"7-Zip 23.01 23.01", "7-Zip 26.03 (x64 edition) 26.03.00.0"}, namesAndVersions(pkgs))
	})

	t.Run("same architecture, different directory", func(t *testing.T) {
		other := strings.ReplaceAll(sevenZipExe23, `C:\\Program Files\\7-Zip\\`, `D:\\Tools\\7-Zip\\`)
		pkgs := parseEntries(t, other, sevenZipMsi26)
		assert.Len(t, pkgs, 2, namesAndVersions(pkgs))
	})
}

// .NET runtimes install side by side under one dotnet root. The registry
// entries below are the real host shapes from windows_dotnet_hostshapes_test.go;
// none of them may be touched.
func TestSupersededEntries_DotNetUnchanged(t *testing.T) {
	pkgs, err := ParseWindowsAppPackages(winArm64Platform(), strings.NewReader(bundleHost))
	require.NoError(t, err)
	assert.Len(t, pkgs, 4, "every entry of the bundle host survives")

	// Even if the entries named the shared dotnet root, one release does not
	// supersede another. DisplayNames and packed versions are from
	// TestDotNetSideBySideReleases.
	older := `{"DisplayName":"Microsoft .NET Runtime - 8.0.30 (x64)","DisplayVersion":"64.120.56788","Publisher":"Microsoft Corporation",
		"UninstallString":"MsiExec.exe /X{00000001-0000-0000-0000-000000000000}","InstallLocation":"C:\\Program Files\\dotnet\\",
		"PSPath":"` + hklmUninstall + `{00000001-0000-0000-0000-000000000000}","InstallScope":"machine"}`
	newer := `{"DisplayName":"Microsoft .NET Runtime - 10.0.11 (x64)","DisplayVersion":"80.44.56884","Publisher":"Microsoft Corporation",
		"UninstallString":"MsiExec.exe /X{00000002-0000-0000-0000-000000000000}","InstallLocation":"C:\\Program Files\\dotnet\\",
		"PSPath":"` + hklmUninstall + `{00000002-0000-0000-0000-000000000000}","InstallScope":"machine"}`
	pkgs = parseEntries(t, older, newer)
	assert.ElementsMatch(t, []string{
		"Microsoft .NET Runtime - 8.0.30 (x64) 8.0.30",
		"Microsoft .NET Runtime - 10.0.11 (x64) 10.0.11",
	}, namesAndVersions(pkgs))
}

// A version that does not order leaves the whole group alone.
func TestSupersededEntries_UnorderableVersionsKept(t *testing.T) {
	release := `{"DisplayName":"Mozilla Firefox (x64 en-US)","DisplayVersion":"130.0.1","Publisher":"Mozilla",
		"UninstallString":"\"C:\\Program Files\\Mozilla Firefox\\uninstall\\helper.exe\"","InstallLocation":"C:\\Program Files\\Mozilla Firefox",
		"PSPath":"` + hklmUninstall + `Mozilla Firefox 130.0.1 (x64 en-US)","InstallScope":"machine"}`
	beta := `{"DisplayName":"Mozilla Firefox (x64 en-US)","DisplayVersion":"131.0b9","Publisher":"Mozilla",
		"UninstallString":"\"C:\\Program Files\\Mozilla Firefox\\uninstall\\helper.exe\"","InstallLocation":"C:\\Program Files\\Mozilla Firefox",
		"PSPath":"` + hklmUninstall + `Mozilla Firefox 131.0b9 (x64 en-US)","InstallScope":"machine"}`
	pkgs := parseEntries(t, release, beta)
	assert.ElementsMatch(t, []string{"Mozilla Firefox (x64 en-US) 130.0.1", "Mozilla Firefox (x64 en-US) 131.0b9"}, namesAndVersions(pkgs))
}

// Different products in one directory are not merged, and a different
// publisher or install user keeps entries apart.
func TestSupersededEntries_IdentityMustAgree(t *testing.T) {
	t.Run("different product", func(t *testing.T) {
		other := strings.Replace(sevenZipExe23, `"7-Zip 23.01 (x64)"`, `"7-Zip Helper 23.01 (x64)"`, 1)
		assert.Len(t, parseEntries(t, other, sevenZipMsi26), 2)
	})
	t.Run("different publisher", func(t *testing.T) {
		other := strings.Replace(sevenZipExe23, `"Igor Pavlov"`, `"Someone Else"`, 1)
		assert.Len(t, parseEntries(t, other, sevenZipMsi26), 2)
	})
	t.Run("different install user", func(t *testing.T) {
		other := strings.Replace(sevenZipExe23, `"InstallScope": "machine"`, `"InstallScope": "user"`, 1)
		other = strings.Replace(other, `"InstallUser": ""`, `"InstallUser": "S-1-5-21-1-2-3-1001"`, 1)
		assert.Len(t, parseEntries(t, other, sevenZipMsi26), 2)
	})
	t.Run("equal versions are not superseded", func(t *testing.T) {
		same := strings.Replace(sevenZipExe23, `"DisplayVersion": "23.01"`, `"DisplayVersion": "26.03"`, 1)
		same = strings.Replace(same, `"7-Zip 23.01 (x64)"`, `"7-Zip 26.03 (x64)"`, 1)
		assert.Len(t, parseEntries(t, same, sevenZipMsi26), 2)
	})
}

// The local native path reads the same values through the registry API, where
// REG_EXPAND_SZ values arrive unexpanded.
func TestSupersededEntries_NativeRegistryItems(t *testing.T) {
	sz := func(k, v string) registry.RegistryKeyItem {
		return registry.RegistryKeyItem{Key: k, Value: registry.RegistryKeyValue{Kind: registry.SZ, String: v}}
	}
	exeItems := []registry.RegistryKeyItem{
		sz("DisplayName", "7-Zip 23.01 (x64)"),
		sz("DisplayVersion", "23.01"),
		sz("Publisher", "Igor Pavlov"),
		sz("UninstallString", `"%ProgramFiles%\7-Zip\Uninstall.exe"`),
	}
	msiItems := []registry.RegistryKeyItem{
		sz("DisplayName", "7-Zip 26.03 (x64 edition)"),
		sz("DisplayVersion", "26.03.00.0"),
		sz("Publisher", "Igor Pavlov"),
		sz("UninstallString", "MsiExec.exe /I{23170F69-40C1-2702-2603-000001000000}"),
		sz("InstallLocation", `C:\Program Files\7-Zip\`),
	}
	build := func() []Package {
		var pkgs []Package
		for _, items := range [][]registry.RegistryKeyItem{exeItems, msiItems} {
			p, _ := getPackageFromRegistryKeyItems(items, winX64Platform(), "x86_64")
			require.NotNil(t, p)
			p.uninstallEvidence = uninstallEvidenceFromItems(items)
			pkgs = append(pkgs, *p)
		}
		return pkgs
	}

	expand := func(s string) string { return strings.ReplaceAll(s, "%ProgramFiles%", `C:\Program Files`) }
	got := dropSupersededUninstallEntries(build(), expand)
	require.Len(t, got, 1)
	assert.Equal(t, "26.03.00.0", got[0].Version)

	// Without an expansion the %ProgramFiles% path is unresolved: no
	// directory, so nothing is dropped.
	assert.Len(t, dropSupersededUninstallEntries(build(), nil), 2)
}

func TestExpandMachineEnvFromProcess(t *testing.T) {
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("LOCALAPPDATA", `C:\Users\scanner\AppData\Local`)
	assert.Equal(t, `C:\Program Files\7-Zip`, expandMachineEnvFromProcess(`%ProgramFiles%\7-Zip`))
	assert.Equal(t, `%LOCALAPPDATA%\Programs\App`, expandMachineEnvFromProcess(`%LOCALAPPDATA%\Programs\App`),
		"a per-user variable would resolve against the scanning identity, not the entry's owner")
}

func TestUninstallEntryDir(t *testing.T) {
	for _, tc := range []struct {
		desc string
		ev   uninstallEvidence
		want string
	}{
		{"install location, trailing backslash and case folded", uninstallEvidence{installLocation: `C:\Program Files\7-Zip\`}, `c:\program files\7-zip`},
		{"install location quoted", uninstallEvidence{installLocation: `"C:\Program Files\7-Zip"`}, `c:\program files\7-zip`},
		{"forward slashes and doubled separators", uninstallEvidence{installLocation: `C:/Program Files//7-Zip/`}, `c:\program files\7-zip`},
		{"quoted uninstaller with arguments", uninstallEvidence{uninstallString: `"C:\Program Files\Notepad++\uninstall.exe" /S`}, `c:\program files\notepad++`},
		{"unquoted uninstaller with arguments", uninstallEvidence{uninstallString: `C:\Program Files\VideoLAN\VLC\uninstall.exe /S`}, `c:\program files\videolan\vlc`},
		{"MsiExec names no directory", uninstallEvidence{uninstallString: `MsiExec.exe /X{23170F69-40C1-2702-2603-000001000000}`}, ``},
		{"MsiExec falls through to the icon", uninstallEvidence{uninstallString: `MsiExec.exe /X{23170F69-40C1-2702-2603-000001000000}`, displayIcon: `"C:\Program Files\7-Zip\7zFM.exe",0`}, `c:\program files\7-zip`},
		{"rundll32 in the Windows directory", uninstallEvidence{uninstallString: `C:\WINDOWS\system32\rundll32.exe shell32.dll`}, ``},
		{"shared root is no evidence", uninstallEvidence{installLocation: `C:\Program Files\`}, ``},
		{"drive root is no evidence", uninstallEvidence{installLocation: `C:\`}, ``},
		{"per-user programs root is no evidence", uninstallEvidence{installLocation: `C:\Users\alice\AppData\Local\Programs`}, ``},
		{"per-user app directory", uninstallEvidence{installLocation: `C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\`}, `c:\users\alice\appdata\local\programs\microsoft vs code`},
		{"unexpanded variable", uninstallEvidence{installLocation: `%ProgramFiles%\7-Zip`}, ``},
		{"relative path", uninstallEvidence{installLocation: `7-Zip`}, ``},
		{"invalid location falls through to the uninstaller", uninstallEvidence{installLocation: `C:\`, uninstallString: `"C:\Program Files\7-Zip\Uninstall.exe"`}, `c:\program files\7-zip`},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.want, uninstallEntryDir(&tc.ev, nil))
		})
	}
}

func TestProductIdentity(t *testing.T) {
	for _, tc := range []struct{ name, version, want string }{
		{"7-Zip 23.01 (x64)", "23.01", "7-zip"},
		{"7-Zip 26.03 (x64 edition)", "26.03.00.0", "7-zip"},
		// The installer packs the patch into the build field, so "3.12.4" is not
		// a leading run of 3.12.4150.0 and stays in the name.
		{"Python 3.12.4 (64-bit)", "3.12.4150.0", "python 3.12.4"},
		{"Python 3.12.4 (64-bit)", "3.12.4", "python"},
		// "381" is not a leading run of 8.0.3810.9, and a single number is
		// never treated as a version.
		{"Java 8 Update 381 (64-bit)", "8.0.3810.9", "java 8 update 381"},
		// A number that is not the entry's own version stays in the name.
		{"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130", "14.38.33130.0", "microsoft visual c++ 2015-2022 redistributable (x64) -"},
		{"Notepad++ (64-bit x64)", "8.6.4", "notepad++ (64-bit x64)"},
		{"App 1.2", "1.2-beta", "app 1.2"},
	} {
		assert.Equal(t, tc.want, productIdentity(tc.name, tc.version), tc.name)
	}
}

func TestWindowsNumericVersion(t *testing.T) {
	a, ok := windowsNumericVersion("23.01")
	require.True(t, ok)
	b, ok := windowsNumericVersion("26.03.00.0")
	require.True(t, ok)
	assert.Equal(t, -1, compareWindowsNumericVersions(a, b))
	assert.Equal(t, 1, compareWindowsNumericVersions(b, a))

	c, _ := windowsNumericVersion("23.1.0.0")
	assert.Equal(t, 0, compareWindowsNumericVersions(a, c), "missing trailing components are zero")

	for _, v := range []string{"", "131.0b9", "1.0-beta", "2024 R2", "99999999999999999999999"} {
		_, ok := windowsNumericVersion(v)
		assert.False(t, ok, v)
	}
}
