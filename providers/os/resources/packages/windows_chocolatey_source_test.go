// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/chocolatey/records holds the package records of a Chocolatey 2.7.5
// install (installed as SYSTEM) on a Windows 11 Enterprise 23H2 (22631) VM,
// 2026-11-27: the ".registry" and ".sourceInstalledFrom" files of
// <root>\.chocolatey\<id>.<version>\. ".arguments" (encrypted install
// arguments) and the other files were left out. vlc.3.0.24 is the meta package
// of vlc.install and has no ".registry".
const (
	chocolateyFixtures = "testdata/chocolatey/records"
	chocolateyFeed     = "https://community.chocolatey.org/api/v2"
	chocolateyDefault  = "ProgramData/chocolatey/.chocolatey/"
)

// chocolateyRecordTimes is when each record was written, from the host
// (LastWriteTimeUtc of the record's ".files"; the ".registry" is written in
// the same step, so it stands in for it).
var chocolateyRecordTimes = map[string]string{
	"7zip.install.25.1.0":  "2026-11-27T12:34:55Z",
	"7zip.install.26.6.0":  "2026-11-27T12:35:12Z",
	"git.install.2.56.1":   "2026-11-27T12:31:56Z",
	"putty.install.0.85.0": "2026-11-27T12:31:03Z",
	"vlc.3.0.24":           "2026-11-27T12:32:29Z",
	"vlc.install.3.0.24":   "2026-11-27T12:32:29Z",
}

// chocolateyFixtureFS is an offline Windows volume holding the measured
// records, and the SYSTEM winget catalog measured on the same host after the
// Chocolatey steps.
func chocolateyFixtureFS(t *testing.T) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	dirs, err := os.ReadDir(chocolateyFixtures)
	require.NoError(t, err)
	for _, d := range dirs {
		files, err := os.ReadDir(path.Join(chocolateyFixtures, d.Name()))
		require.NoError(t, err)
		for _, f := range files {
			data, err := os.ReadFile(path.Join(chocolateyFixtures, d.Name(), f.Name()))
			require.NoError(t, err)
			p := chocolateyDefault + d.Name() + "/" + f.Name()
			writeWingetFile(t, fs, p, data)
			at, err := time.Parse(time.RFC3339, chocolateyRecordTimes[d.Name()])
			require.NoError(t, err)
			require.NoError(t, fs.Chtimes(p, at, at))
		}
	}
	writeWingetFile(t, fs, wingetSystemDir+wingetCommunity+"/installed.db", wingetFixture(t, "system-after-chocolatey.db"))
	return fs
}

func chocolateySource(id, url string) Source {
	return Source{OSProvided: osProvided(false), Channel: ChannelChocolatey, Name: id, URL: url}
}

// chocolateyRecordFile writes a synthetic ".registry" with the given keys,
// each as {keyPath, displayVersion}, under <root>\.chocolatey\<folder>.
func chocolateyRecordFile(t *testing.T, fs afero.Fs, dir, folder, user string, written time.Time, keys ...[2]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><registrySnapshot><user>` + user + `</user><keys>`)
	for _, k := range keys {
		b.WriteString(`<key installerType="Unknown" displayVersion="` + k[1] + `"><KeyPath>` + k[0] + `</KeyPath></key>`)
	}
	b.WriteString(`</keys></registrySnapshot>`)
	p := dir + folder + "/.registry"
	writeWingetFile(t, fs, p, []byte(b.String()))
	require.NoError(t, fs.Chtimes(p, written, written))
}

const uninstallRoot = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`

func TestChocolateySources(t *testing.T) {
	fs := chocolateyFixtureFS(t)
	facts := windowsSourceFacts{
		winget:     readWingetCatalogs(fs, mountedSystemDrivePath),
		chocolatey: readChocolateyRecords(fs, mountedSystemDrivePath, ""),
	}

	// Measured: every machine Uninstall entry of the host (arp.txt) as
	// Chocolatey 2.7.5, winget and the installers left it. The keys are spelled
	// as Windows spells them.
	chocolatey := []struct {
		name string
		pkg  Package
		want Source
	}{
		// InnoSetup, the package that ran the installer is git.install
		{"Git", uninstallEntry("Git", "2.56.1", "Git_is1"), chocolateySource("git.install", chocolateyFeed)},
		// Msi
		{"PuTTY", uninstallEntry("PuTTY release 0.85 (64-bit)", "0.85.0.0", "{3B0346D3-155D-43E5-9561-B9BE51CF2EB6}"), chocolateySource("putty.install", chocolateyFeed)},
		// Unknown installer type, a key name with spaces
		{"VLC", uninstallEntry("VLC media player", "3.0.24", "VLC media player"), chocolateySource("vlc.install", chocolateyFeed)},
		// upgraded 25.01 to 26.06 by Chocolatey after winget installed 26.03:
		// the 26.6.0 record is for the installed version, the upgrade left no
		// ".sourceInstalledFrom"
		{"7-Zip", uninstallEntry("7-Zip 26.06 (x64)", "26.06", "7-Zip"), chocolateySource("7zip.install", "")},
	}
	for _, tc := range chocolatey {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, windowsPackageSource(tc.pkg, facts))
		})
	}

	// Measured: not Chocolatey's, so unchanged by it
	other := []struct {
		name string
		pkg  Package
		want Source
	}{
		{"Notepad++", uninstallEntry("Notepad++ (x64)", "8.9.9.1", "{A23B657D-838B-4C9B-8F9D-386E50C1A76B}"), wingetSource("Notepad++.Notepad++")},
		{"Chrome", uninstallEntry("Google Chrome", "154.0.8037.58", "{C8B3A0BF-0F75-32C9-B05B-BE6FE9F5ED90}"), wingetSource("Google.Chrome")},
		{"Acrobat Reader", uninstallEntry("Adobe Acrobat Reader MUI", "26.002.21931", "{AC76BA86-7AD7-FFFF-7B44-AC0F074E4100}"), wingetSource("Adobe.Acrobat.Reader.32-bit")},
		// installed by winget (winget install Chocolatey.Chocolatey), not by a
		// Chocolatey package: Chocolatey has no record of itself
		{"Chocolatey", uninstallEntry("Chocolatey (Install Only)", "2.7.5.0", "{E4690459-5686-4055-BA8A-649D0C067B52}"), wingetSource("Chocolatey.Chocolatey")},
	}
	for _, tc := range other {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, windowsPackageSource(tc.pkg, facts))
		})
	}
	for name, pkg := range map[string]Package{
		"Zoom":     uninstallEntry("Zoom (64-bit)", "5.16.22807", "{130C5F26-7D81-4285-9F6C-C18D91503887}"),
		"JRE":      uninstallEntry("AdoptOpenJDK JRE with Hotspot 8.0.202.08 (x64)", "8.0.202.08", "{D2650BF0-7D9E-44C0-B706-2FED855DC6D9}"),
		"Mondoo":   uninstallEntry("Mondoo", "14.14.0", "{5ED59D41-D10F-44D5-A407-99118C2D2F01}"),
		"VC++ min": uninstallEntry("Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33816", "14.40.33816", "{560D2DA4-096E-4868-B22A-DA6418FDE6FB}"),
		"VC++ add": uninstallEntry("Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33816", "14.40.33816", "{5904914B-9FC8-44C2-AE48-5C7F30A603EC}"),
		"VC++ red": uninstallEntry("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33816", "14.40.33816.0", "{77169412-f642-45e7-b533-0c6f48de12f9}"),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, ChannelInstaller, windowsPackageSource(pkg, facts).Channel)
		})
	}
}

func TestChocolateyRecordName(t *testing.T) {
	// Measured: the record folders of the host
	for folder, want := range map[string][2]string{
		"7zip.install.25.1.0":                      {"7zip.install", "25.1.0"},
		"git.install.2.56.1":                       {"git.install", "2.56.1"},
		"vlc.3.0.24":                               {"vlc", "3.0.24"},
		"Wget.1.25.0":                              {"Wget", "1.25.0"},
		"chocolatey-core.extension.1.4.0":          {"chocolatey-core.extension", "1.4.0"},
		"chocolatey-compatibility.extension.1.0.0": {"chocolatey-compatibility.extension", "1.0.0"},
	} {
		m := chocolateyRecordName.FindStringSubmatch(folder)
		require.NotNil(t, m, folder)
		assert.Equal(t, want, [2]string{m[1], m[2]}, folder)
	}
	// Synthetic: a pre-release version and four numeric parts; no target showed these.
	m := chocolateyRecordName.FindStringSubmatch("example.tool.1.2.3.4-beta1")
	require.NotNil(t, m)
	assert.Equal(t, [2]string{"example.tool", "1.2.3.4-beta1"}, [2]string{m[1], m[2]})
	// Synthetic: a name without a version is no record
	assert.Nil(t, chocolateyRecordName.FindStringSubmatch("lib-bad"))
}

func TestChocolateyUpgradeResidue(t *testing.T) {
	// Measured: 7zip.install 25.1.0 was upgraded to 26.6.0 and its record stayed;
	// both name the Uninstall key "7-Zip".
	fs := chocolateyFixtureFS(t)
	facts := windowsSourceFacts{chocolatey: readChocolateyRecords(fs, mountedSystemDrivePath, "")}
	require.Len(t, facts.chocolatey["7-zip"], 2)

	// Measured: the entry shows 26.06, the record of 26.6.0 has no feed
	assert.Equal(t, chocolateySource("7zip.install", ""), windowsPackageSource(uninstallEntry("7-Zip", "26.06", "7-Zip"), facts))

	// Synthetic: the entry still shows 25.01 while both records exist; the
	// record of that version wins over the newer one, and its feed is its own.
	assert.Equal(t, chocolateySource("7zip.install", chocolateyFeed), windowsPackageSource(uninstallEntry("7-Zip", "25.01", "7-Zip"), facts))

	// Synthetic: the entry shows a version no record has; the newer version
	// wins even when the older record was written later.
	older := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, fs.Chtimes(chocolateyDefault+"7zip.install.25.1.0/.registry", older, older))
	facts.chocolatey = readChocolateyRecords(fs, mountedSystemDrivePath, "")
	assert.Equal(t, chocolateySource("7zip.install", ""), windowsPackageSource(uninstallEntry("7-Zip", "99.0", "7-Zip"), facts))

	// Synthetic: versions that do not order ("1.0-beta") fall back to the
	// record written last.
	fs = afero.NewMemMapFs()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	chocolateyRecordFile(t, fs, chocolateyDefault, "tool.1.0-beta", "S-1-5-18", t0, [2]string{uninstallRoot + "Tool", "1"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "tool.2.0-beta", "S-1-5-18", t0.Add(time.Hour), [2]string{uninstallRoot + "Tool", "2"})
	facts.chocolatey = readChocolateyRecords(fs, mountedSystemDrivePath, "")
	r, ok := facts.chocolatey.best(uninstallEntry("Tool", "3", "Tool"))
	require.True(t, ok)
	assert.Equal(t, "2.0-beta", r.version)
}

func TestChocolateyScope(t *testing.T) {
	const sid, other = "S-1-5-21-1111111111-2222222222-3333333333-1001", "S-1-5-21-1111111111-2222222222-3333333333-1002"
	fs := afero.NewMemMapFs()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Synthetic: an HKLM record and a per-user record for the same key name;
	// no target showed this.
	chocolateyRecordFile(t, fs, chocolateyDefault, "machine.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Tool", "1.0"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "peruser.tool.1.0.0", sid, t0, [2]string{`HKEY_USERS\` + sid + `\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool`, "1.0"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "hkcu.tool.1.0.0", other, t0, [2]string{`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool`, "1.0"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "hkcu.system.1.0.0", "S-1-5-18", t0, [2]string{`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sys`, "1.0"})
	idx := readChocolateyRecords(fs, mountedSystemDrivePath, "")

	machine := uninstallEntry("Tool", "1.0", "Tool")
	machine.InstallScope = installScopeMachine
	r, ok := idx.best(machine)
	require.True(t, ok)
	assert.Equal(t, "machine.tool", r.id, "a machine entry takes the HKLM record")

	user := uninstallEntry("Tool", "1.0", "Tool")
	user.InstallScope, user.InstallUser = installScopeUser, sid
	r, ok = idx.best(user)
	require.True(t, ok)
	assert.Equal(t, "peruser.tool", r.id, "a user's entry takes the record of that user")

	otherUser := uninstallEntry("Tool", "1.0", "Tool")
	otherUser.InstallScope, otherUser.InstallUser = installScopeUser, other
	r, ok = idx.best(otherUser)
	require.True(t, ok)
	assert.Equal(t, "hkcu.tool", r.id, "HKCU is the hive of the account that ran choco")

	third := uninstallEntry("Tool", "1.0", "Tool")
	third.InstallScope, third.InstallUser = installScopeUser, "S-1-5-21-1111111111-2222222222-3333333333-1003"
	_, ok = idx.best(third)
	assert.False(t, ok, "a third user's entry matches no record")

	// the HKLM record alone must not claim a user's entry of the same name
	onlyMachine := readChocolateyRecords(afero.NewMemMapFs(), mountedSystemDrivePath, "")
	assert.Empty(t, onlyMachine)
	fs2 := afero.NewMemMapFs()
	chocolateyRecordFile(t, fs2, chocolateyDefault, "machine.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Tool", "1.0"})
	onlyMachine = readChocolateyRecords(fs2, mountedSystemDrivePath, "")
	_, ok = onlyMachine.best(user)
	assert.False(t, ok, "an HKLM record does not match a user-scope entry")
	assert.Equal(t, Source{Channel: ChannelInstaller}, windowsPackageSource(user, windowsSourceFacts{chocolatey: onlyMachine}))

	// SYSTEM's own HKCU is machine scope, as the package listing reports it
	sys := uninstallEntry("Sys", "1.0", "Sys")
	sys.InstallScope = installScopeMachine
	r, ok = idx.best(sys)
	require.True(t, ok)
	assert.Equal(t, "hkcu.system", r.id)
}

func TestChocolateyFeedURL(t *testing.T) {
	// Synthetic: a private feed with credentials and a query; no target showed this.
	fs := afero.NewMemMapFs()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	chocolateyRecordFile(t, fs, chocolateyDefault, "internal.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Tool", "1.0"})
	writeWingetFile(t, fs, chocolateyDefault+"internal.tool.1.0.0/.sourceInstalledFrom", []byte("https://user:secret@choco.example.com/nuget/internal/?token=abc\r\n"))
	// Synthetic: a registry file with a byte order mark, which the measured ones do not have
	writeWingetFile(t, fs, chocolateyDefault+"bom.tool.1.0.0/.registry", []byte("\xef\xbb\xbf<registrySnapshot><user>S-1-5-18</user><keys><key displayVersion=\"1.0\"><KeyPath>"+uninstallRoot+"Bom</KeyPath></key></keys></registrySnapshot>"))
	chocolateyRecordFile(t, fs, chocolateyDefault, "local.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Local", "1.0"})
	writeWingetFile(t, fs, chocolateyDefault+"local.tool.1.0.0/.sourceInstalledFrom", []byte(`C:\packages`))
	facts := windowsSourceFacts{chocolatey: readChocolateyRecords(fs, mountedSystemDrivePath, "")}

	got := windowsPackageSource(uninstallEntry("Tool", "1.0", "Tool"), facts)
	assert.Equal(t, chocolateySource("internal.tool", "https://choco.example.com/nuget/internal"), got)
	assert.NotContains(t, got.URL, "secret")
	assert.Contains(t, facts.chocolatey, "bom")
	// a local folder feed has no host to report
	assert.Equal(t, chocolateySource("local.tool", ""), windowsPackageSource(uninstallEntry("Local", "1.0", "Local"), facts))
}

func TestChocolateyBadRecordsAreSkipped(t *testing.T) {
	fs := afero.NewMemMapFs()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Synthetic: a malformed record, an oversized one, a record without a
	// version in its name and a key path without a key name; none of them hides
	// the good record.
	writeWingetFile(t, fs, chocolateyDefault+"broken.tool.1.0.0/.registry", []byte("<registrySnapshot><keys><key"))
	writeWingetFile(t, fs, chocolateyDefault+"huge.tool.1.0.0/.registry", []byte(`<registrySnapshot><keys><key displayVersion="1"><KeyPath>`+uninstallRoot+`Huge</KeyPath></key>`+strings.Repeat(" ", chocolateyMaxRegistryBytes)+`</keys></registrySnapshot>`))
	chocolateyRecordFile(t, fs, chocolateyDefault, "noversion", "S-1-5-18", t0, [2]string{uninstallRoot + "NoVersion", "1"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "emptykey.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot, "1"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "good.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Good", "1.0"})
	// a file where a record folder should be
	writeWingetFile(t, fs, chocolateyDefault+"stray.file", []byte("x"))

	idx := readChocolateyRecords(fs, mountedSystemDrivePath, "")
	require.Len(t, idx, 1)
	require.Contains(t, idx, "good")
	assert.Equal(t, "good.tool", idx["good"][0].id)

	// Synthetic: no Chocolatey on the volume
	assert.Empty(t, readChocolateyRecords(afero.NewMemMapFs(), mountedSystemDrivePath, ""))
}

func TestChocolateyCustomInstallRoot(t *testing.T) {
	fs := afero.NewMemMapFs()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Synthetic: ChocolateyInstall points away from the default; no target showed this.
	chocolateyRecordFile(t, fs, "tools/choco/.chocolatey/", "custom.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Custom", "1.0"})
	chocolateyRecordFile(t, fs, chocolateyDefault, "default.tool.1.0.0", "S-1-5-18", t0, [2]string{uninstallRoot + "Default", "1.0"})

	// the variable's root is read, with a trailing separator tolerated
	idx := readChocolateyRecords(fs, mountedSystemDrivePath, `C:\tools\choco\`)
	assert.Contains(t, idx, "custom")
	assert.NotContains(t, idx, "default", "the default location is not read when the variable's root has records")

	// the default root is the fallback when the variable names an empty directory
	idx = readChocolateyRecords(fs, mountedSystemDrivePath, `C:\nowhere`)
	assert.Contains(t, idx, "default")

	// and when it is unknown
	assert.Contains(t, readChocolateyRecords(fs, mountedSystemDrivePath, ""), "default")
}
