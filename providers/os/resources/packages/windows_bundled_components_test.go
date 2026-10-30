// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// The PE images in this file are synthesized (no vendor binaries are shipped)
// from version resources measured on a real host:
// Azure Windows Server 2022, XAMPP 7.3.2 / php.net 7.3.33 TS and 8.4.27 NTS
// zips, 2026-10-26.

type fakeBin struct {
	path    string
	file    [4]uint16
	strs    []string
	machine uint16
}

func (b fakeBin) write(t *testing.T, fs afero.Fs) {
	t.Helper()
	m := b.machine
	if m == 0 {
		m = pe.IMAGE_FILE_MACHINE_AMD64
	}
	require.NoError(t, afero.WriteFile(fs, b.path, buildPEMachine(t, m, b.file, b.file, b.strs, true), 0o644))
}

func writeStub(t *testing.T, fs afero.Fs, paths ...string) {
	t.Helper()
	for _, p := range paths {
		require.NoError(t, afero.WriteFile(fs, p, []byte("stub"), 0o644))
	}
}

func phpBin(path, version string, file [4]uint16) fakeBin {
	return fakeBin{path: path, file: file, strs: []string{"FileVersion", version, "ProductVersion", version, "ProductName", "PHP", "CompanyName", "The PHP Group"}}
}

func httpdBin(path string) fakeBin {
	return fakeBin{path: path, file: [4]uint16{2, 4, 38, 0}, strs: []string{"FileVersion", "2.4.38", "ProductVersion", "2.4.38", "ProductName", "Apache HTTP Server", "CompanyName", "Apache Software Foundation"}}
}

func sslBin(path string) fakeBin {
	return fakeBin{path: path, file: [4]uint16{1, 1, 1, 1}, strs: []string{"FileVersion", "1.1.1a", "ProductVersion", "1.1.1a", "ProductName", "The OpenSSL Toolkit", "CompanyName", "The OpenSSL Project, https://www.openssl.org/"}}
}

func unnamedBin(path string, file [4]uint16) fakeBin {
	v := fmt.Sprintf("%d.%d.%d.%d", file[0], file[1], file[2], file[3])
	return fakeBin{path: path, file: file, strs: []string{"FileVersion", v, "ProductVersion", v}}
}

func appPkg(name, dir string) Package {
	return Package{Name: name, Version: "1", Format: "windows/app", Files: []FileRecord{{Path: dir}}}
}

// summary renders the identity of each package for comparison.
func summary(pkgs []Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		dirs := make([]string, 0, len(p.Files))
		for _, f := range p.Files {
			dirs = append(dirs, f.Path)
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|origin=%s|%s", p.Name, p.Version, p.Arch, p.Vendor, p.Origin, strings.Join(dirs, ",")))
	}
	return out
}

func find(fs afero.Fs, pkgs []Package, hints componentHints) []Package {
	return findBundledComponents(fsComponentSource{fs: fs, toFsPath: mountedSystemDrivePath}, pkgs, hints, winX64Platform())
}

func TestFindBundledComponentsXampp(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Measured: XAMPP 7.3.2 x64 installer in C:\xampp.
	phpFile := [4]uint16{7, 3, 2, 0}
	phpBin(`xampp/php/php.exe`, "7.3.2", phpFile).write(t, fs)
	phpBin(`xampp/php/php-cgi.exe`, "7.3.2", phpFile).write(t, fs)
	writeStub(t, fs, `xampp/php/php7ts.dll`, `xampp/php/php7apache2_4.dll`, `xampp/php/php7phpdbg.dll`)
	httpdBin(`xampp/apache/bin/httpd.exe`).write(t, fs)
	unnamedBin(`xampp/mysql/bin/mysqld.exe`, [4]uint16{10, 1, 38, 0}).write(t, fs)
	unnamedBin(`xampp/mysql/bin/mysql.exe`, [4]uint16{10, 1, 38, 0}).write(t, fs)
	sslBin(`xampp/apache/bin/openssl.exe`).write(t, fs)
	sslBin(`xampp/apache/bin/libssl-1_1-x64.dll`).write(t, fs)
	sslBin(`xampp/apache/bin/libcrypto-1_1-x64.dll`).write(t, fs)
	// Measured: php.net 7.3.33 TS zip in C:\php (on the machine PATH) and
	// 8.4.27 NTS zip in C:\tools\php84, which has php8.dll but no php8ts.dll.
	phpBin(`php/php.exe`, "7.3.33", [4]uint16{7, 3, 33, 0}).write(t, fs)
	writeStub(t, fs, `php/php7ts.dll`)
	phpBin(`tools/php84/php.exe`, "8.4.27", [4]uint16{8, 4, 27, 0}).write(t, fs)
	writeStub(t, fs, `tools/php84/php8.dll`)

	pkgs := []Package{appPkg("XAMPP", `C:\xampp`)}
	hints := componentHints{
		MachinePath: `C:\Windows\system32;C:\Windows;C:\php;`,
		Services: []string{
			`"C:\xampp\apache\bin\httpd.exe" -k runservice`,
			`C:\xampp\mysql\bin\mysqld.exe --defaults-file=C:\xampp\mysql\bin\my.ini mysql`,
			`\SystemRoot\System32\drivers\null.sys`,
		},
	}
	got := find(fs, pkgs, hints)
	assert.Equal(t, []string{
		`PHP|7.3.2|x86_64|The PHP Group|origin=XAMPP|C:\xampp\php`,
		`Apache HTTP Server|2.4.38|x86_64|Apache Software Foundation|origin=XAMPP|C:\xampp\apache\bin`,
		`OpenSSL|1.1.1a|x86_64|The OpenSSL Project|origin=XAMPP|C:\xampp\apache\bin\libssl-1_1-x64.dll`,
		`MariaDB|10.1.38.0|x86_64|MariaDB|origin=XAMPP|C:\xampp\mysql\bin`,
		`PHP|7.3.33|x86_64|The PHP Group|origin=|C:\php`,
		`PHP|8.4.27|x86_64|The PHP Group|origin=|C:\tools\php84`,
	}, summary(got))

	php := got[0]
	assert.Equal(t, "windows/app", php.Format)
	assert.Contains(t, php.PUrl, "PHP@7.3.2")
	assert.Contains(t, php.PUrl, "arch=x86_64")
	assert.NotEmpty(t, php.CPEs)
	assert.Equal(t, installScopeMachine, php.InstallScope)
}

func TestFindBundledComponentsLayouts(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Synthetic: WampServer and Laragon directory layouts as their docs
	// describe them; no such host was scanned.
	phpBin(`wamp64/bin/php/php8.2.0/php.exe`, "8.2.0", [4]uint16{8, 2, 0, 0}).write(t, fs)
	writeStub(t, fs, `wamp64/bin/php/php8.2.0/php8ts.dll`)
	httpdBin(`wamp64/bin/apache/apache2.4.54/bin/httpd.exe`).write(t, fs)
	fakeBin{path: `wamp64/bin/mariadb/mariadb10.10.2/bin/mariadbd.exe`, file: [4]uint16{10, 10, 2, 0}, strs: []string{"ProductVersion", "10.10.2"}}.write(t, fs)
	phpBin(`laragon/bin/php/php-8.1.10-Win32-vs16-x64/php.exe`, "8.1.10", [4]uint16{8, 1, 10, 0}).write(t, fs)
	writeStub(t, fs, `laragon/bin/php/php-8.1.10-Win32-vs16-x64/php8ts.dll`)
	fakeBin{path: `laragon/bin/mysql/mysql-8.0.30-winx64/bin/mysqld.exe`, file: [4]uint16{8, 0, 30, 0}, strs: []string{"ProductVersion", "8.0.30", "ProductName", "MySQL Server"}}.write(t, fs)

	got := find(fs, []Package{appPkg("WampServer", `C:\wamp64`), appPkg("Laragon", `C:\laragon`)}, componentHints{})
	assert.ElementsMatch(t, []string{
		`PHP|8.2.0|x86_64|The PHP Group|origin=WampServer|C:\wamp64\bin\php\php8.2.0`,
		`Apache HTTP Server|2.4.38|x86_64|Apache Software Foundation|origin=WampServer|C:\wamp64\bin\apache\apache2.4.54\bin`,
		`MariaDB|10.10.2|x86_64|MariaDB|origin=WampServer|C:\wamp64\bin\mariadb\mariadb10.10.2\bin`,
		`PHP|8.1.10|x86_64|The PHP Group|origin=Laragon|C:\laragon\bin\php\php-8.1.10-Win32-vs16-x64`,
		`MySQL Server|8.0.30|x86_64|Oracle Corporation|origin=Laragon|C:\laragon\bin\mysql\mysql-8.0.30-winx64\bin`,
	}, summary(got))
}

func TestFindBundledComponentsConfirmation(t *testing.T) {
	// Synthetic: look-alike directories that must not produce a package.
	cases := []struct {
		name  string
		setup func(t *testing.T, fs afero.Fs)
		want  []string
	}{
		{"php.exe without a core DLL", func(t *testing.T, fs afero.Fs) {
			phpBin(`php/php.exe`, "7.3.33", [4]uint16{7, 3, 33, 0}).write(t, fs)
			writeStub(t, fs, `php/php7apache2_4.dll`, `php/php7phpdbg.dll`)
		}, nil},
		{"php.exe of another product", func(t *testing.T, fs afero.Fs) {
			unnamedBin(`php/php.exe`, [4]uint16{7, 3, 33, 0}).write(t, fs)
			writeStub(t, fs, `php/php7ts.dll`)
		}, nil},
		{"mysqld 5.5 without a name is ambiguous", func(t *testing.T, fs afero.Fs) {
			unnamedBin(`php/mysqld.exe`, [4]uint16{5, 5, 62, 0}).write(t, fs)
		}, nil},
		{"httpd.exe of another product", func(t *testing.T, fs afero.Fs) {
			unnamedBin(`php/httpd.exe`, [4]uint16{2, 4, 38, 0}).write(t, fs)
		}, nil},
		{"libssl of another product", func(t *testing.T, fs afero.Fs) {
			unnamedBin(`php/libssl-3-x64.dll`, [4]uint16{3, 0, 0, 0}).write(t, fs)
		}, nil},
		{"a file that is not a PE image", func(t *testing.T, fs afero.Fs) {
			writeStub(t, fs, `php/php.exe`, `php/php7ts.dll`)
		}, nil},
		{"upper-case file names, as an image mounted on a POSIX scanner shows them", func(t *testing.T, fs afero.Fs) {
			phpBin(`php/PHP.EXE`, "7.3.33", [4]uint16{7, 3, 33, 0}).write(t, fs)
			writeStub(t, fs, `php/PHP7TS.DLL`)
		}, []string{`PHP|7.3.33|x86_64|The PHP Group|origin=|C:\php`}},
		{"x86 binary", func(t *testing.T, fs afero.Fs) {
			b := phpBin(`php/php.exe`, "5.6.40", [4]uint16{5, 6, 40, 0})
			b.machine = pe.IMAGE_FILE_MACHINE_I386
			b.write(t, fs)
			writeStub(t, fs, `php/php5ts.dll`)
		}, []string{`PHP|5.6.40|x86|The PHP Group|origin=|C:\php`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			tc.setup(t, fs)
			got := find(fs, nil, componentHints{})
			if tc.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tc.want, summary(got))
			}
		})
	}
}

func TestMysqlFlavor(t *testing.T) {
	cases := []struct {
		name, product, version string
		mariadbd               bool
		want                   string
	}{
		// Measured: XAMPP 7.3.2 ships MariaDB 10.1.38 as mysqld.exe with no names.
		{"XAMPP mysqld 10.1.38.0", "", "10.1.38.0", false, "MariaDB"},
		// Synthetic: versions and names no host showed.
		{"mariadbd.exe sibling", "", "11.4.2", true, "MariaDB"},
		{"name says MariaDB", "MariaDB Server", "5.5.68", false, "MariaDB"},
		{"name says MySQL", "MySQL Server", "10.0.0", false, "MySQL Server"},
		{"MySQL 5.7", "", "5.7.44", false, "MySQL Server"},
		{"MySQL 8.0", "", "8.0.30", false, "MySQL Server"},
		{"MySQL 9", "", "9.1.0", false, "MySQL Server"},
		{"5.5 without a name is ambiguous", "", "5.5.62", false, ""},
		{"6 matches neither", "", "6.0.1", false, ""},
		{"no digits", "", "x", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mysqlFlavor(tc.product, tc.version, tc.mariadbd))
		})
	}
}

func TestFindBundledComponentsDedup(t *testing.T) {
	setup := func(t *testing.T) afero.Fs {
		fs := afero.NewMemMapFs()
		fakeBin{path: `Program Files/MariaDB 10.6/bin/mariadbd.exe`, file: [4]uint16{10, 6, 12, 0}, strs: []string{"ProductVersion", "10.6.12"}}.write(t, fs)
		return fs
	}
	// Synthetic: an MSI install of MariaDB with its own entry, pointed at by
	// its service.
	hints := componentHints{Services: []string{`"C:\Program Files\MariaDB 10.6\bin\mariadbd.exe" "--defaults-file=C:\Program Files\MariaDB 10.6\data\my.ini" "MariaDB"`}}

	t.Run("covered by a package of that name at the parent directory", func(t *testing.T) {
		got := find(setup(t), []Package{appPkg("MariaDB 10.6 (x64)", `C:\Program Files\MariaDB 10.6\`)}, hints)
		assert.Empty(t, got)
	})
	t.Run("a package of another name does not cover it", func(t *testing.T) {
		got := find(setup(t), []Package{appPkg("Some Tool", `C:\Program Files\MariaDB 10.6`)}, hints)
		assert.Equal(t, []string{`MariaDB|10.6.12|x86_64|MariaDB|origin=Some Tool|C:\Program Files\MariaDB 10.6\bin`}, summary(got))
	})
	t.Run("a package of that name elsewhere does not cover it", func(t *testing.T) {
		got := find(setup(t), []Package{appPkg("MariaDB 10.5", `C:\Program Files\MariaDB 10.5`)}, hints)
		// Not inside the 10.5 directory, so no origin either.
		assert.Equal(t, []string{`MariaDB|10.6.12|x86_64|MariaDB|origin=|C:\Program Files\MariaDB 10.6\bin`}, summary(got))
	})
	t.Run("the same directory from two sources is one package", func(t *testing.T) {
		h := componentHints{
			MachinePath: `C:\Program Files\MariaDB 10.6\bin`,
			Services:    hints.Services,
		}
		assert.Equal(t, []string{`MariaDB|10.6.12|x86_64|MariaDB|origin=|C:\Program Files\MariaDB 10.6\bin`}, summary(find(setup(t), nil, h)))
	})
}

func TestFindBundledComponentsBroadRoots(t *testing.T) {
	// Synthetic: a package registered at Program Files itself says nothing
	// about which product's files are there; probing below it would find
	// whatever any product put in a "php" folder.
	fs := afero.NewMemMapFs()
	phpBin(`Program Files/php/php.exe`, "7.3.33", [4]uint16{7, 3, 33, 0}).write(t, fs)
	writeStub(t, fs, `Program Files/php/php7ts.dll`)
	assert.Empty(t, find(fs, []Package{appPkg("Broken Installer", `C:\Program Files`)}, componentHints{}))
	// A PATH entry naming the broad root is ignored the same way.
	assert.Empty(t, find(fs, nil, componentHints{MachinePath: `C:\Program Files;C:\Windows\system32`}))
}

func TestFindBundledComponentsSameVersionTwice(t *testing.T) {
	// Synthetic: two copies of one PHP build. They are one row in the package
	// list, the second directory is kept as evidence.
	fs := afero.NewMemMapFs()
	for _, d := range []string{"php", "tools/php74"} {
		phpBin(d+`/php.exe`, "7.4.33", [4]uint16{7, 4, 33, 0}).write(t, fs)
		writeStub(t, fs, d+`/php7ts.dll`)
	}
	got := find(fs, nil, componentHints{})
	assert.Equal(t, []string{`PHP|7.4.33|x86_64|The PHP Group|origin=|C:\php,C:\tools\php74`}, summary(got))
}

func TestFindBundledComponentsScoop(t *testing.T) {
	// Synthetic: scoop's layout, a junction named current beside the versioned
	// directory.
	mk := func(t *testing.T, dirs ...string) afero.Fs {
		fs := afero.NewMemMapFs()
		for _, d := range dirs {
			phpBin(d+`/php.exe`, "8.3.1", [4]uint16{8, 3, 1, 0}).write(t, fs)
			writeStub(t, fs, d+`/php8ts.dll`)
		}
		return fs
	}
	hints := componentHints{Profiles: []componentProfile{{Dir: `C:\Users\alice`}}}
	t.Run("current is skipped beside a versioned directory", func(t *testing.T) {
		got := find(mk(t, `Users/alice/scoop/apps/php/8.3.1`, `Users/alice/scoop/apps/php/current`), nil, hints)
		assert.Equal(t, []string{`PHP|8.3.1|x86_64|The PHP Group|origin=|C:\Users\alice\scoop\apps\php\8.3.1`}, summary(got))
	})
	t.Run("current alone is kept", func(t *testing.T) {
		got := find(mk(t, `Users/alice/scoop/apps/php/current`), nil, hints)
		assert.Equal(t, []string{`PHP|8.3.1|x86_64|The PHP Group|origin=|C:\Users\alice\scoop\apps\php\current`}, summary(got))
	})
}

func TestFindBundledComponentsNoFilesystem(t *testing.T) {
	assert.Nil(t, findBundledComponents(nil, nil, componentHints{}, winX64Platform()))
	// An empty filesystem yields nothing and does not fail.
	assert.Empty(t, find(afero.NewMemMapFs(), []Package{appPkg("XAMPP", `C:\xampp`)}, componentHints{MachinePath: `C:\php`}))
}

func TestComponentHintsCandidateDirs(t *testing.T) {
	// Synthetic: PATH and ImagePath shapes; no host showed these.
	h := componentHints{
		MachinePath: `%SystemRoot%\system32;"C:\Tools\bin\";D:\apps;%UNKNOWN%\x;;C:\php/`,
		Services:    []string{`"C:\xampp\apache\bin\httpd.exe" -k runservice`, `C:\xampp\mysql\bin\mysqld.exe --x`, `svchost.exe -k netsvcs`, `\SystemRoot\x.sys`},
		Profiles:    []componentProfile{{Dir: `C:\Users\alice`, Path: `%USERPROFILE%\bin;%USERPROFILE%\AppData\Local\Microsoft\WindowsApps`}},
	}
	assert.Equal(t, []string{
		`C:\Tools\bin`, `D:\apps`, `C:\php`,
		`C:\xampp\apache\bin`, `C:\xampp\mysql\bin`,
		`C:\Users\alice\bin`, `C:\Users\alice\AppData\Local\Microsoft\WindowsApps`,
	}, h.candidateDirs())
}

func TestComponentSearchSkipsUNCPaths(t *testing.T) {
	// Synthetic: listing a UNC path waits on SMB timeouts when the server is
	// unreachable, so none is a candidate, wherever it comes from.
	h := componentHints{
		MachinePath: `\\fileserver\tools\php;C:\php`,
		Services:    []string{`\\fileserver\svc\httpd.exe -k run`, `"C:\xampp\apache\bin\httpd.exe" -k runservice`},
		Profiles: []componentProfile{
			{Dir: `C:\Users\alice`, Path: `//fileserver/tools/bin;%USERPROFILE%\bin`},
			{Dir: `\\fileserver\home\bob`, Path: `\\fileserver\home\bob\bin`},
		},
	}
	assert.Equal(t, []string{`C:\php`, `C:\xampp\apache\bin`, `C:\Users\alice\bin`}, h.candidateDirs())

	bundles := appInstallDirs([]Package{appPkg("Remote App", `\\fileserver\apps\remote`), appPkg("XAMPP", `C:\xampp`)})
	assert.Equal(t, []bundleDir{{"XAMPP", `C:\xampp`}}, bundles)

	for _, s := range componentProbeSpecs(bundles, h) {
		assert.False(t, strings.HasPrefix(s.base, `\\`), "probe spec for %q", s.base)
	}
	script, ok := componentProbeScript(componentProbePlan(bundles, h))
	require.True(t, ok)
	assert.NotContains(t, script, "fileserver")
	// A normal directory next to them is still searched.
	assert.Contains(t, script, `'0|C:\php'`)

	// Through the finder: only the local directory is read.
	fs := afero.NewMemMapFs()
	phpBin(`php/php.exe`, "8.2.0", [4]uint16{8, 2, 0, 0}).write(t, fs)
	writeStub(t, fs, `php/php8ts.dll`)
	assert.Equal(t, []string{`PHP|8.2.0|x86_64|The PHP Group|origin=|C:\php`}, summary(find(fs, nil, h)))
}

func TestParseComponentHints(t *testing.T) {
	// Synthetic: the JSON shapes Windows PowerShell 5.1 and PowerShell 7
	// write for arrays of zero, one and several elements.
	cases := []struct {
		name, in string
		want     componentHints
	}{
		{"arrays", `{"MachinePath":"C:\\php;C:\\x","Services":["a.exe","b.exe"],"Profiles":[{"Dir":"C:\\Users\\a","Path":"%USERPROFILE%\\bin"},{"Dir":"C:\\Users\\b","Path":""}]}`,
			componentHints{MachinePath: `C:\php;C:\x`, Services: []string{"a.exe", "b.exe"}, Profiles: []componentProfile{{`C:\Users\a`, `%USERPROFILE%\bin`}, {`C:\Users\b`, ""}}}},
		{"single elements", `{"MachinePath":"C:\\php","Services":"a.exe","Profiles":{"Dir":"C:\\Users\\a","Path":null}}`,
			componentHints{MachinePath: `C:\php`, Services: []string{"a.exe"}, Profiles: []componentProfile{{Dir: `C:\Users\a`}}}},
		{"empty", `{"MachinePath":"","Services":{},"Profiles":null}`, componentHints{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseComponentHints(strings.NewReader(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	_, err := parseComponentHints(strings.NewReader("not json"))
	assert.Error(t, err)
}

type fakeComponentRegistry struct {
	items    map[string][]registry.RegistryKeyItem
	children map[string][]registry.RegistryKeyChild
	userEnv  map[string][]registry.RegistryKeyItem
	loaded   []string
}

func (f *fakeComponentRegistry) GetNativeRegistryKeyItems(id, path string) ([]registry.RegistryKeyItem, error) {
	if v, ok := f.items[id+`\`+path]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("no key %s", path)
}

func (f *fakeComponentRegistry) GetNativeRegistryKeyChildren(id, path string) ([]registry.RegistryKeyChild, error) {
	if v, ok := f.children[id+`\`+path]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("no key %s", path)
}

func (f *fakeComponentRegistry) LoadUserHive(sid, filepath string) error {
	if _, ok := f.userEnv[sid]; !ok {
		return fmt.Errorf("cannot load %s", filepath)
	}
	f.loaded = append(f.loaded, sid)
	return nil
}

func (f *fakeComponentRegistry) GetUserHiveKeyItems(sid, path string) ([]registry.RegistryKeyItem, error) {
	return f.userEnv[sid], nil
}

func strItem(k, v string) registry.RegistryKeyItem {
	return registry.RegistryKeyItem{Key: k, Value: registry.RegistryKeyValue{String: v}}
}

func TestOfflineComponentHints(t *testing.T) {
	// Synthetic: hive contents as the documented key layout; the fake stands
	// in for a loaded SYSTEM and SOFTWARE hive.
	const alice = "S-1-5-21-1-2-3-1001"
	const bob = "S-1-5-21-1-2-3-1002"
	reg := &fakeComponentRegistry{
		items: map[string][]registry.RegistryKeyItem{
			`SYSTEM\Select`: {{Key: "Current", Value: registry.RegistryKeyValue{Number: 2}}},
			`SYSTEM\ControlSet002\Control\Session Manager\Environment`:          {strItem("Path", `%SystemRoot%\system32;C:\php`)},
			`SYSTEM\ControlSet002\Services\Apache2.4`:                           {strItem("ImagePath", `"C:\xampp\apache\bin\httpd.exe" -k runservice`)},
			`SYSTEM\ControlSet002\Services\NoImage`:                             {strItem("Start", "3")},
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\` + alice: {strItem("ProfileImagePath", `%SystemDrive%\Users\alice`)},
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\` + bob:   {strItem("ProfileImagePath", `C:\Users\bob`)},
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18`: {strItem("ProfileImagePath", `C:\Windows\system32\config\systemprofile`)},
		},
		children: map[string][]registry.RegistryKeyChild{
			`SYSTEM\ControlSet002\Services`:                            {{Name: "Apache2.4"}, {Name: "NoImage"}},
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`: {{Name: alice}, {Name: bob}, {Name: "S-1-5-18"}},
		},
		userEnv: map[string][]registry.RegistryKeyItem{alice: {strItem("Path", `%USERPROFILE%\php`)}},
	}
	h := offlineComponentHints(reg, func(dir string) (string, bool) { return dir + `\NTUSER.DAT`, true })
	assert.Equal(t, componentHints{
		MachinePath: `%SystemRoot%\system32;C:\php`,
		Services:    []string{`"C:\xampp\apache\bin\httpd.exe" -k runservice`},
		Profiles: []componentProfile{
			{Dir: `C:\Users\alice`, Path: `%USERPROFILE%\php`},
			{Dir: `C:\Users\bob`}, // hive can't be loaded: no user PATH, profile kept for scoop
		},
	}, h)
	assert.Equal(t, []string{alice}, reg.loaded)
	assert.Contains(t, h.candidateDirs(), `C:\Users\alice\php`)

	// Nothing readable: no hints and no panic.
	assert.Equal(t, componentHints{}, offlineComponentHints(&fakeComponentRegistry{}, func(string) (string, bool) { return "", false }))
}

func TestExpandComponentEnv(t *testing.T) {
	// Synthetic: variable spellings.
	assert.Equal(t, `C:\Windows\system32`, expandComponentEnv(`%SystemRoot%\system32`, ""))
	assert.Equal(t, `C:\Users\a\bin`, expandComponentEnv(`%USERPROFILE%\bin`, `C:\Users\a`))
	assert.Equal(t, `%USERPROFILE%\bin`, expandComponentEnv(`%USERPROFILE%\bin`, ""), "no profile: left for the caller to reject")
	assert.Equal(t, `C:\Program Files (x86)\x`, expandComponentEnv(`%ProgramFiles(x86)%\x`, ""))
}

func TestFindBundledComponentsOpenSSLNeedsAComponent(t *testing.T) {
	// Synthetic: unrelated products ship their own libssl next to a service
	// executable or into a PATH directory. Those copies are out of scope, only
	// a libssl beside PHP, Apache or MariaDB/MySQL is reported.
	fs := afero.NewMemMapFs()
	sslBin(`vendor/svc/libssl-3-x64.dll`).write(t, fs)
	writeStub(t, fs, `vendor/svc/agent.exe`)
	sslBin(`tools/bin/libssl-3-x64.dll`).write(t, fs)
	hints := componentHints{
		MachinePath: `C:\tools\bin`,
		Services:    []string{`"C:\vendor\svc\agent.exe" --run`},
	}
	assert.Empty(t, find(fs, nil, hints))

	// The same library next to a php.exe is reported.
	phpBin(`tools/bin/php.exe`, "8.2.0", [4]uint16{8, 2, 0, 0}).write(t, fs)
	writeStub(t, fs, `tools/bin/php8.dll`)
	assert.Equal(t, []string{
		`PHP|8.2.0|x86_64|The PHP Group|origin=|C:\tools\bin`,
		`OpenSSL|1.1.1a|x86_64|The OpenSSL Project|origin=|C:\tools\bin\libssl-3-x64.dll`,
	}, summary(find(fs, nil, hints)))
}

func TestComponentArch(t *testing.T) {
	// Synthetic: platform spellings; Windows app packages carry the platform's
	// own architecture string for the host's family and "x86" for 32-bit.
	x64 := winX64Platform()
	arm := winX64Platform()
	arm.Arch = "arm64"
	x86Host := winX64Platform()
	x86Host.Arch = "x86"
	assert.Equal(t, "x86_64", componentArch("x64", x64))
	assert.Equal(t, "x86", componentArch("x86", x64))
	assert.Equal(t, "arm64", componentArch("arm64", arm))
	assert.Equal(t, "x64", componentArch("x64", arm), "emulated x64 on an arm64 host")
	assert.Equal(t, "x86", componentArch("x86", x86Host))
	assert.Equal(t, "x64", componentArch("x64", nil))
	assert.Equal(t, "", componentArch("", x64))
}

func TestComponentProbeScript(t *testing.T) {
	// Synthetic: specs that must and must not reach the script.
	script, ok := componentProbeScript(probePlan{
		bundles: []string{`C:\xampp`, `C:\it's`, "C:\\a\u2019b", "C:\\a\nb", `C:\a|b`},
		direct: []probeSpec{
			{base: `C:\wamp`, segments: []string{"apache", "bin"}},
			{base: `C:\Users\alice\scoop\apps\php`, segments: []string{"*"}, skipCurrent: true},
			{base: `C:\it's`},
			{base: "C:\\a\u2019b"},
			{base: "C:\\a\nb"},
			{base: `C:\a|b`},
			{base: `C:\ok`, segments: []string{"x'y"}},
		},
	})
	require.True(t, ok)
	assert.Contains(t, script, `@('C:\xampp')`, "a bundle directory is listed once")
	assert.Contains(t, script, `'0|C:\wamp|apache|bin'`)
	assert.Contains(t, script, `'1|C:\Users\alice\scoop\apps\php|*'`)
	assert.NotContains(t, script, "it's")
	assert.NotContains(t, script, "\u2019")
	assert.NotContains(t, script, `a|b`)
	assert.NotContains(t, script, `x'y`)

	_, ok = componentProbeScript(probePlan{direct: []probeSpec{{base: `C:\it's`}}, bundles: []string{`C:\it's`}})
	assert.False(t, ok)
	_, ok = componentProbeScript(probePlan{})
	assert.False(t, ok)
}

// remoteProbeFixture is componentProbeScript's output for a XAMPP host,
// shaped as Windows PowerShell 5.1 might write it: a single Infos element is
// an object and not an array, a string without a value is null or {}.
// Machine 34404 is IMAGE_FILE_MACHINE_AMD64.
//
// Synthetic: written by hand to cover the single-element and null shapes that
// the measured output (testdata/windows_component_probe_xampp.json) does not
// contain; the version resources in it are the measured values.
const remoteProbeFixture = `[
 {"Path":"C:\\xampp\\php","Files":["php.exe","php7ts.dll","php7apache2_4.dll"],"Dirs":[],
  "Infos":{"Name":"php.exe","ProductName":"PHP","CompanyName":"The PHP Group","ProductVersion":"7.3.2","File":"7.3.2.0","Machine":34404}},
 {"Path":"C:\\xampp\\apache\\bin","Files":["httpd.exe","libssl-1_1-x64.dll"],"Dirs":{},
  "Infos":[
   {"Name":"httpd.exe","ProductName":"Apache HTTP Server","CompanyName":"Apache Software Foundation","ProductVersion":"2.4.38","File":"2.4.38.0","Machine":34404},
   {"Name":"libssl-1_1-x64.dll","ProductName":"The OpenSSL Toolkit","CompanyName":"The OpenSSL Project, https://www.openssl.org/","ProductVersion":"1.1.1a","File":"1.1.1.1","Machine":34404}]},
 {"Path":"C:\\xampp\\mysql\\bin","Files":"mysqld.exe","Dirs":null,
  "Infos":{"Name":"mysqld.exe","ProductName":{},"CompanyName":null,"ProductVersion":"10.1.38.0","File":"10.1.38.0","Machine":34404}},
 {"Path":"C:\\Users\\alice\\scoop\\apps\\php","Files":[],"Dirs":["8.3.1","current"],"Infos":[]},
 {"Path":"C:\\Users\\alice\\scoop\\apps\\php\\8.3.1","Files":["php.exe","php8ts.dll"],"Dirs":[],
  "Infos":{"Name":"php.exe","ProductName":"PHP","CompanyName":"The PHP Group","ProductVersion":"8.3.1","File":"8.3.1.0","Machine":332}},
 {"Path":"C:\\Users\\alice\\scoop\\apps\\php\\current","Files":["php.exe","php8ts.dll"],"Dirs":[],
  "Infos":{"Name":"php.exe","ProductName":"PHP","CompanyName":"The PHP Group","ProductVersion":"8.3.1","File":"8.3.1.0","Machine":332}}
]`

func TestParseComponentProbe(t *testing.T) {
	src, err := parseComponentProbe(strings.NewReader(remoteProbeFixture))
	require.NoError(t, err)

	files, dirs, ok := src.list(`C:\XAMPP\PHP`)
	assert.True(t, ok, "directory names compare case-insensitively")
	assert.Equal(t, []string{"php.exe", "php7ts.dll", "php7apache2_4.dll"}, files)
	assert.Empty(t, dirs)

	files, _, ok = src.list(`C:\xampp\mysql\bin`)
	assert.True(t, ok)
	assert.Equal(t, []string{"mysqld.exe"}, files, "a single string, not an array")

	_, _, ok = src.list(`C:\nowhere`)
	assert.False(t, ok)

	info, ok := src.info(`C:\xampp\mysql\bin`, "MYSQLD.EXE")
	require.True(t, ok)
	assert.Equal(t, peInfo{File: []uint64{10, 1, 38, 0}, ProductVersion: "10.1.38.0", Machine: "x64"}, info, "null and {} names are empty")

	info, ok = src.info(`C:\xampp\apache\bin`, "libssl-1_1-x64.dll")
	require.True(t, ok)
	assert.Equal(t, "1.1.1a", info.ProductVersion)
	assert.Equal(t, []uint64{1, 1, 1, 1}, info.File)

	_, ok = src.info(`C:\xampp\php`, "httpd.exe")
	assert.False(t, ok)

	// Empty output is a failed script, not an empty result: the script
	// silences its errors and exits 0, and prints "[]" when nothing is there.
	_, err = parseComponentProbe(strings.NewReader("  "))
	assert.ErrorIs(t, err, errEmptyProbeOutput)
	empty, err := parseComponentProbe(strings.NewReader("[]"))
	require.NoError(t, err)
	_, _, ok = empty.list(`C:\xampp\php`)
	assert.False(t, ok)

	_, err = parseComponentProbe(strings.NewReader("not json"))
	assert.Error(t, err)
}

// stagingTestConnection records the commands run on it and keeps staged files
// on an in-memory filesystem, which Stage writes through.
type stagingTestConnection struct {
	plugin.Connection
	asset    *inventory.Asset
	fs       afero.Fs
	commands []string
	// seen is the staged file's content at the time the command ran.
	seen map[string]string
	// stdout is what every command prints.
	stdout string
}

func newStagingTestConnection() *stagingTestConnection {
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}}}
	return &stagingTestConnection{Connection: plugin.NewConnection(1, asset), asset: asset, fs: afero.NewMemMapFs(), seen: map[string]string{}, stdout: "[]"}
}

func (c *stagingTestConnection) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	if path, ok := strings.CutPrefix(command, powershell.StagedCommand("")); ok {
		if b, err := afero.ReadFile(c.fs, path); err == nil {
			c.seen[path] = string(b)
		}
	}
	return &shared.Command{Command: command, Stdout: bytes.NewBufferString(c.stdout), Stderr: bytes.NewBufferString(""), ExitStatus: 0}, nil
}
func (c *stagingTestConnection) FileInfo(string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, os.ErrNotExist
}
func (c *stagingTestConnection) FileSystem() afero.Fs               { return c.fs }
func (c *stagingTestConnection) Name() string                       { return "staging-test" }
func (c *stagingTestConnection) Type() shared.ConnectionType        { return shared.Type_Winrm }
func (c *stagingTestConnection) Asset() *inventory.Asset            { return c.asset }
func (c *stagingTestConnection) UpdateAsset(asset *inventory.Asset) { c.asset = asset }
func (c *stagingTestConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand | shared.Capability_File
}

func TestComponentProbeScriptSizeScalesWithBaseDirs(t *testing.T) {
	// Synthetic: install directories of a realistic length. Every directory is
	// sent once, not once per layout, so each one adds its path and the quotes
	// and comma around it, and nothing else.
	mk := func(n int) string {
		var bundles []string
		for i := 0; i < n; i++ {
			bundles = append(bundles, fmt.Sprintf(`C:\Program Files\Vendor%03d\Product Suite %03d\runtime`, i, i))
		}
		script, ok := componentProbeScript(probePlan{bundles: bundles})
		require.True(t, ok)
		return script
	}
	one, many := mk(1), mk(300)
	pathLen := len(`C:\Program Files\Vendor000\Product Suite 000\runtime`)
	assert.Equal(t, 299*(pathLen+3), len(many)-len(one), "300 directories add one quoted path and a comma each")
	// With ten layouts per directory the old shape was about 10 times larger.
	assert.Less(t, len(many), len(one)+300*(pathLen+3))
	assert.Less(t, len(many), 30000)
}

func TestComponentProbeScriptHasTheGoLayouts(t *testing.T) {
	// The script applies the layouts to each bundle itself, so the layouts the
	// Go finder expands must be the ones in the script, in the same notation.
	script, ok := componentProbeScript(probePlan{bundles: []string{`C:\xampp`}})
	require.True(t, ok)
	var want []string
	for _, l := range bundledComponentLayouts {
		want = append(want, "'"+strings.Join(l, "|")+"'")
	}
	assert.Contains(t, script, "$layouts = @("+strings.Join(want, ",")+")")

	// And the plan, expanded as the Go finder does, is the layouts applied to
	// each bundle then the direct directories.
	plan := probePlan{bundles: []string{`C:\a`, `C:\b`}, direct: []probeSpec{{base: `C:\php`}}}
	specs := plan.specs()
	require.Len(t, specs, 2*len(bundledComponentLayouts)+1)
	assert.Equal(t, probeSpec{base: `C:\a`, segments: bundledComponentLayouts[0]}, specs[0])
	assert.Equal(t, probeSpec{base: `C:\b`, segments: bundledComponentLayouts[0]}, specs[len(bundledComponentLayouts)])
	assert.Equal(t, probeSpec{base: `C:\php`}, specs[len(specs)-1])
}

func TestComponentScriptsFitOrAreStaged(t *testing.T) {
	// The hints script carries no data from the target, so its size is fixed.
	assert.True(t, powershell.FitsCommandLine(componentHintsScript), "the hints script must fit an encoded command on WinRM")

	// Synthetic: a host with a bundle and a few PATH and service entries. The
	// probe script lists every path to probe, so it grows with the host.
	bundles := []bundleDir{{"XAMPP", `C:\xampp`}, {"WampServer", `C:\wamp64`}}
	hints := componentHints{
		MachinePath: `C:\php;C:\Tools\bin;C:\Program Files\Git\cmd`,
		Services:    []string{`"C:\xampp\apache\bin\httpd.exe" -k runservice`},
		Profiles:    []componentProfile{{Dir: `C:\Users\alice`}},
	}
	script, ok := componentProbeScript(componentProbePlan(bundles, hints))
	require.True(t, ok)
	// The fixed body alone is past the encoded limit, so even a host with
	// nothing installed goes through staging. If this starts to fit, the
	// staging test below no longer covers anything.
	require.False(t, powershell.FitsCommandLine(script))

	t.Run("a long script is staged and run with -File", func(t *testing.T) {
		conn := newStagingTestConnection()
		cmd, err := runComponentScript(conn, "components", script)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		path := powershell.StagedWindowsPath("components", script)
		require.NotEmpty(t, conn.commands)
		run := conn.commands[len(conn.commands)-1]
		assert.Equal(t, powershell.StagedCommand(path), run)
		assert.NotContains(t, run, "EncodedCommand")
		assert.Equal(t, script, conn.seen[path], "the file holds the script when the command runs")
		for _, c := range conn.commands {
			assert.LessOrEqual(t, len(c), powershell.MaxCommandLength, "no command may exceed the WinRM limit")
		}
		exists, err := afero.Exists(conn.fs, path)
		require.NoError(t, err)
		assert.False(t, exists, "the staged file is removed")
	})

	t.Run("a short script is an encoded command", func(t *testing.T) {
		conn := newStagingTestConnection()
		_, err := runComponentScript(conn, "componenthints", componentHintsScript)
		require.NoError(t, err)
		assert.Equal(t, []string{powershell.Encode(componentHintsScript)}, conn.commands)
	})

	t.Run("no way to stage is an error and not a truncated command", func(t *testing.T) {
		conn := &noRunConnection{newStagingTestConnection()}
		_, err := runComponentScript(conn, "components", script)
		assert.Error(t, err)
	})
}

// noRunConnection cannot run commands.
type noRunConnection struct{ *stagingTestConnection }

func (noRunConnection) Capabilities() shared.Capabilities { return shared.Capability_File }

func TestFindBundledComponentsRemote(t *testing.T) {
	// Measured: Azure Windows Server 2022, Windows PowerShell 5.1, XAMPP 7.3.2 /
	// php.net 7.3.33 TS and 8.4.27 NTS zips, 2026-10-26, output of
	// componentProbeScript. The machine PATH held C:\php and C:\tools\php84 was
	// found through the C:\tools\php* fixed folder.
	f, err := os.Open("testdata/windows_component_probe_xampp.json")
	require.NoError(t, err)
	defer f.Close()
	src, err := parseComponentProbe(f)
	require.NoError(t, err)

	hints := componentHints{MachinePath: `C:\Program Files\dotnet;C:\php;C:\Users\mqladmin\AppData\Local\Microsoft\WindowsApps`}
	got := findBundledComponents(src, []Package{appPkg("XAMPP", `C:\xampp`)}, hints, winX64Platform())
	assert.Equal(t, []string{
		`PHP|7.3.2|x86_64|The PHP Group|origin=XAMPP|C:\xampp\php`,
		// The same libssl sits in XAMPP's php and apache\bin: one package, two locations.
		`OpenSSL|1.1.1a|x86_64|The OpenSSL Project|origin=XAMPP|C:\xampp\php\libssl-1_1-x64.dll,C:\xampp\apache\bin\libssl-1_1-x64.dll`,
		`Apache HTTP Server|2.4.38|x86_64|Apache Software Foundation|origin=XAMPP|C:\xampp\apache\bin`,
		`MariaDB|10.1.38.0|x86_64|MariaDB|origin=XAMPP|C:\xampp\mysql\bin`,
		`PHP|7.3.33|x86_64|The PHP Group|origin=|C:\php`,
		`OpenSSL|1.1.1l|x86_64|The OpenSSL Project|origin=|C:\php\libssl-1_1-x64.dll`,
		`PHP|8.4.27|x86_64|The PHP Group|origin=|C:\tools\php84`,
		`OpenSSL|3.0.22|x86_64|The OpenSSL Project|origin=|C:\tools\php84\libssl-3-x64.dll`,
	}, summary(got))
}

func TestRemoteComponentSourceEmptyOutputIsAFailure(t *testing.T) {
	// Synthetic: a probe script that failed inside PowerShell prints nothing
	// and exits 0; that must read as a failure (no source), while "[]" is a
	// host with nothing to find.
	pkgs := []Package{appPkg("XAMPP", `C:\xampp`)}
	for _, tc := range []struct {
		stdout string
		usable bool
	}{{"", false}, {"  \r\n", false}, {"not json", false}, {"[]", true}} {
		conn := newStagingTestConnection()
		conn.stdout = tc.stdout
		w := &WinPkgManager{conn: conn, platform: winX64Platform()}
		src := w.remoteComponentSource(pkgs, componentHints{})
		assert.Equal(t, tc.usable, src != nil, "stdout %q", tc.stdout)
	}
}
