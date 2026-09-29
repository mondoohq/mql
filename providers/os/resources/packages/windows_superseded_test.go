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

// The two Uninstall entries captured from a Windows 11 host after 7-Zip was
// upgraded from its EXE installer (23.01) to its MSI (26.03). The files in
// C:\Program Files\7-Zip on that host: 7z.exe, 7zFM.exe and 7zG.exe at
// 26.03, Uninstall.exe at 23.01.

// sevenZipExe23 is the EXE installer's entry, under its fixed key "7-Zip".
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

// sevenZipMsi26 is the MSI's entry, under its product code. It has an empty
// InstallLocation and no DisplayIcon value at all, so nothing in it names a
// directory.
const sevenZipMsi26 = `{
	"DisplayName": "7-Zip 26.03 (x64 edition)",
	"DisplayVersion": "26.03.00.0",
	"Publisher": "Igor Pavlov",
	"UninstallString": "MsiExec.exe /I{23170F69-40C1-2702-2603-000001000000}",
	"InstallLocation": "",
	"PSPath": "` + hklmUninstall + `{23170F69-40C1-2702-2603-000001000000}",
	"InstallScope": "machine",
	"InstallUser": ""
}`

const sevenZipFM = `C:\Program Files\7-Zip\7zFM.exe`

// sevenZipMsi26InDir is a variant of the captured MSI entry that DOES name
// the directory, for exercising the directory rule on its own.
var sevenZipMsi26InDir = strings.Replace(sevenZipMsi26, `"InstallLocation": ""`, `"InstallLocation": "C:\\Program Files\\7-Zip\\"`, 1)

func parseEntries(t *testing.T, entries ...string) []Package {
	t.Helper()
	pkgs, err := ParseWindowsAppPackages(winX64Platform(), strings.NewReader("["+strings.Join(entries, ",")+"]"))
	require.NoError(t, err)
	return pkgs
}

// dropWithFileVersions runs the full filter, both rules, over the entries
// with the given file versions on the target. It records which files the
// filter asked for.
func dropWithFileVersions(t *testing.T, files map[string]string, entries ...string) (pkgs []Package, asked []string) {
	t.Helper()
	raw, err := parseWindowsAppPackages(winX64Platform(), strings.NewReader("["+strings.Join(entries, ",")+"]"))
	require.NoError(t, err)
	reader := func(paths []string) map[string][]uint64 {
		asked = append(asked, paths...)
		out := map[string][]uint64{}
		for _, p := range paths {
			if v, ok := files[p]; ok {
				parsed, ok := windowsNumericVersion(v)
				require.True(t, ok, v)
				out[p] = parsed
			}
		}
		return out
	}
	return dropSupersededUninstallEntries(raw, nil, reader), asked
}

func namesAndVersions(pkgs []Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name+" "+p.Version)
	}
	return out
}

// The captured pair: the MSI entry names no directory, so the directory rule
// alone can't decide and both entries stay.
func TestSupersededEntries_SevenZipDirectoryRuleAloneDoesNotFire(t *testing.T) {
	pkgs := parseEntries(t, sevenZipExe23, sevenZipMsi26)
	assert.ElementsMatch(t, []string{"7-Zip 23.01 (x64) 23.01", "7-Zip 26.03 (x64 edition) 26.03.00.0"}, namesAndVersions(pkgs))
}

// The captured pair with the captured files: 7zFM.exe, the EXE entry's
// DisplayIcon, is at 26.03, above the entry's own 23.01 and equal to the MSI
// entry's version. The EXE registration is stale.
func TestSupersededEntries_SevenZipFileVersionRule(t *testing.T) {
	files := map[string]string{
		sevenZipFM:                             "26.3.0.0",
		`C:\Program Files\7-Zip\Uninstall.exe`: "23.1.0.0",
	}
	for _, order := range [][]string{{sevenZipExe23, sevenZipMsi26}, {sevenZipMsi26, sevenZipExe23}} {
		pkgs, asked := dropWithFileVersions(t, files, order...)
		require.Len(t, pkgs, 1, "the stale 23.01 registration must be dropped: %v", namesAndVersions(pkgs))
		assert.Equal(t, "7-Zip 26.03 (x64 edition)", pkgs[0].Name)
		assert.Equal(t, "26.03.00.0", pkgs[0].Version)
		assert.Nil(t, pkgs[0].uninstallEvidence, "path evidence must not outlive the filter")
		assert.Equal(t, []string{sevenZipFM}, asked, "only the main executable is read, never the uninstaller")
	}
}

func TestSupersededEntries_FileVersionRuleKeepsBoth(t *testing.T) {
	both := []string{"7-Zip 23.01 (x64) 23.01", "7-Zip 26.03 (x64 edition) 26.03.00.0"}

	t.Run("file version equals the entry's own version", func(t *testing.T) {
		pkgs, _ := dropWithFileVersions(t, map[string]string{sevenZipFM: "23.1.0.0"}, sevenZipExe23, sevenZipMsi26)
		assert.ElementsMatch(t, both, namesAndVersions(pkgs))
	})
	t.Run("file version lines up with the other entry but is not above the entry's own", func(t *testing.T) {
		// 26.3 is a leading run of 26.03.2, but below the entry's own 26.03.1.
		exe := strings.Replace(sevenZipExe23, `"DisplayVersion": "23.01"`, `"DisplayVersion": "26.03.1"`, 1)
		exe = strings.Replace(exe, `"7-Zip 23.01 (x64)"`, `"7-Zip 26.03.1 (x64)"`, 1)
		msi := strings.Replace(sevenZipMsi26, `"DisplayVersion": "26.03.00.0"`, `"DisplayVersion": "26.03.2"`, 1)
		pkgs, asked := dropWithFileVersions(t, map[string]string{sevenZipFM: "26.3"}, exe, msi)
		assert.Len(t, pkgs, 2, namesAndVersions(pkgs))
		assert.Equal(t, []string{sevenZipFM}, asked)
	})
	t.Run("file can't be read", func(t *testing.T) {
		pkgs, asked := dropWithFileVersions(t, map[string]string{}, sevenZipExe23, sevenZipMsi26)
		assert.ElementsMatch(t, both, namesAndVersions(pkgs))
		assert.Equal(t, []string{sevenZipFM}, asked)
	})
	t.Run("file version matches neither entry", func(t *testing.T) {
		pkgs, _ := dropWithFileVersions(t, map[string]string{sevenZipFM: "25.1.0.0"}, sevenZipExe23, sevenZipMsi26)
		assert.ElementsMatch(t, both, namesAndVersions(pkgs))
	})
	t.Run("file version above the other entry", func(t *testing.T) {
		pkgs, _ := dropWithFileVersions(t, map[string]string{sevenZipFM: "26.4.0.0"}, sevenZipExe23, sevenZipMsi26)
		assert.ElementsMatch(t, both, namesAndVersions(pkgs))
	})
	t.Run("DisplayIcon is the uninstaller", func(t *testing.T) {
		exe := strings.Replace(sevenZipExe23, `"DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe"`, `"DisplayIcon": "C:\\Program Files\\7-Zip\\Uninstall.exe,0"`, 1)
		pkgs, asked := dropWithFileVersions(t, map[string]string{`C:\Program Files\7-Zip\Uninstall.exe`: "26.3.0.0"}, exe, sevenZipMsi26)
		assert.ElementsMatch(t, both, namesAndVersions(pkgs))
		assert.Empty(t, asked)
	})
	t.Run("no DisplayIcon on the entry with a directory", func(t *testing.T) {
		exe := strings.Replace(sevenZipExe23, `"DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe",`, ``, 1)
		pkgs, asked := dropWithFileVersions(t, map[string]string{sevenZipFM: "26.3.0.0"}, exe, sevenZipMsi26)
		assert.ElementsMatch(t, both, namesAndVersions(pkgs))
		assert.Empty(t, asked)
	})
	t.Run("different product", func(t *testing.T) {
		msi := strings.Replace(sevenZipMsi26, `"7-Zip 26.03 (x64 edition)"`, `"7-Zip Extra 26.03 (x64 edition)"`, 1)
		pkgs, asked := dropWithFileVersions(t, map[string]string{sevenZipFM: "26.3.0.0"}, sevenZipExe23, msi)
		assert.Len(t, pkgs, 2)
		assert.Empty(t, asked)
	})
}

// The directory rule, on variants of the captured entries that name the
// directory. No file is read when the directory rule decides.
func TestSupersededEntries_DirectoryRule(t *testing.T) {
	t.Run("MSI entry naming the directory", func(t *testing.T) {
		for _, order := range [][]string{{sevenZipExe23, sevenZipMsi26InDir}, {sevenZipMsi26InDir, sevenZipExe23}} {
			pkgs, asked := dropWithFileVersions(t, map[string]string{sevenZipFM: "26.3.0.0"}, order...)
			require.Len(t, pkgs, 1, namesAndVersions(pkgs))
			assert.Equal(t, "26.03.00.0", pkgs[0].Version)
			assert.Empty(t, asked)
		}
	})

	t.Run("MSI icon in the product directory places it there", func(t *testing.T) {
		msi := strings.Replace(sevenZipMsi26, `"InstallLocation": "",`, `"InstallLocation": "", "DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe,0",`, 1)
		pkgs := parseEntries(t, sevenZipExe23, msi)
		require.Len(t, pkgs, 1, namesAndVersions(pkgs))
		assert.Equal(t, "26.03.00.0", pkgs[0].Version)
	})

	t.Run("MSI icon cached by Windows Installer names no directory", func(t *testing.T) {
		msi := strings.Replace(sevenZipMsi26, `"InstallLocation": "",`, `"InstallLocation": "", "DisplayIcon": "C:\\WINDOWS\\Installer\\{23170F69-40C1-2702-2603-000001000000}\\7zFM.exe",`, 1)
		pkgs := parseEntries(t, sevenZipExe23, msi)
		assert.Len(t, pkgs, 2, namesAndVersions(pkgs))
	})

	t.Run("EXE entry without InstallLocation falls back to its uninstaller's directory", func(t *testing.T) {
		exe := strings.Replace(sevenZipExe23, `"InstallLocation": "C:\\Program Files\\7-Zip\\"`, `"InstallLocation": ""`, 1)
		exe = strings.Replace(exe, `"DisplayIcon": "C:\\Program Files\\7-Zip\\7zFM.exe"`, `"DisplayIcon": ""`, 1)
		pkgs := parseEntries(t, exe, sevenZipMsi26InDir)
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
		pkgs := parseEntries(t, x86, sevenZipMsi26InDir)
		assert.ElementsMatch(t, []string{"7-Zip 23.01 23.01", "7-Zip 26.03 (x64 edition) 26.03.00.0"}, namesAndVersions(pkgs))
	})

	t.Run("same architecture, different directory", func(t *testing.T) {
		other := strings.ReplaceAll(sevenZipExe23, `C:\\Program Files\\7-Zip\\`, `D:\\Tools\\7-Zip\\`)
		pkgs := parseEntries(t, other, sevenZipMsi26InDir)
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

// The file-version rule never reads a file for .NET entries or for
// side-by-side installs, and leaves them as they are.
func TestSupersededEntries_FileVersionRuleLeavesDotNetAndSideBySide(t *testing.T) {
	// The bundle host's MSI entries name no directory; its bundle entry's
	// uninstaller is in the Package Cache. Nothing changes and nothing is read.
	pkgs, asked := dropWithFileVersions(t, map[string]string{}, strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(bundleHost), "["), "]"))
	assert.Len(t, pkgs, 4)
	assert.Empty(t, asked)

	// An x86 7-Zip in Program Files (x86) next to the x64 MSI: different
	// architecture, so not the same product entry, and no file is read.
	x86 := `{"DisplayName":"7-Zip 23.01","DisplayVersion":"23.01","Publisher":"Igor Pavlov",
		"UninstallString":"\"C:\\Program Files (x86)\\7-Zip\\Uninstall.exe\"","InstallLocation":"C:\\Program Files (x86)\\7-Zip\\",
		"DisplayIcon":"C:\\Program Files (x86)\\7-Zip\\7zFM.exe",
		"PSPath":"` + hklmWowUninstall + `7-Zip","InstallScope":"machine"}`
	pkgs, asked = dropWithFileVersions(t, map[string]string{`C:\Program Files (x86)\7-Zip\7zFM.exe`: "26.3.0.0"}, x86, sevenZipMsi26)
	assert.Len(t, pkgs, 2, namesAndVersions(pkgs))
	assert.Empty(t, asked)
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
		assert.Len(t, parseEntries(t, other, sevenZipMsi26InDir), 2)
	})
	t.Run("different publisher", func(t *testing.T) {
		other := strings.Replace(sevenZipExe23, `"Igor Pavlov"`, `"Someone Else"`, 1)
		assert.Len(t, parseEntries(t, other, sevenZipMsi26InDir), 2)
	})
	t.Run("different install user", func(t *testing.T) {
		other := strings.Replace(sevenZipExe23, `"InstallScope": "machine"`, `"InstallScope": "user"`, 1)
		other = strings.Replace(other, `"InstallUser": ""`, `"InstallUser": "S-1-5-21-1-2-3-1001"`, 1)
		assert.Len(t, parseEntries(t, other, sevenZipMsi26InDir), 2)
	})
	t.Run("equal versions are not superseded", func(t *testing.T) {
		same := strings.Replace(sevenZipExe23, `"DisplayVersion": "23.01"`, `"DisplayVersion": "26.03"`, 1)
		same = strings.Replace(same, `"7-Zip 23.01 (x64)"`, `"7-Zip 26.03 (x64)"`, 1)
		assert.Len(t, parseEntries(t, same, sevenZipMsi26InDir), 2)
	})
}

// The local native path reads the registry API, where REG_EXPAND_SZ values
// arrive unexpanded. A variant of the captured entries: the EXE's uninstaller
// written with %ProgramFiles%, the MSI naming the directory.
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
	got := dropSupersededUninstallEntries(build(), expand, nil)
	require.Len(t, got, 1)
	assert.Equal(t, "26.03.00.0", got[0].Version)

	// Without an expansion the %ProgramFiles% path is unresolved: no
	// directory, so nothing is dropped.
	assert.Len(t, dropSupersededUninstallEntries(build(), nil, nil), 2)
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
