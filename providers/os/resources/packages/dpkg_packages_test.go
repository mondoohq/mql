// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestDpkgParser(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "ubuntu",
		Version: "18.04",
		Arch:    "x86_64",
		Family:  []string{"debian", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "ubuntu",
		},
	}

	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_dpkg.toml"))
	require.NoError(t, err)
	f, err := mock.FileSystem().Open("/var/lib/dpkg/status")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseDpkgPackages(pf, f)
	require.NoError(t, err)
	assert.Equal(t, 10, len(m), "detected the right amount of packages")

	p := Package{
		Name:    "fdisk",
		Version: "2.31.1-0.4ubuntu3.1",
		Arch:    "amd64",
		Status:  "install ok installed",
		Origin:  "util-linux",
		Description: `collection of partitioning utilities
This package contains the classic fdisk, sfdisk and cfdisk partitioning
utilities from the util-linux suite.
.
The utilities included in this package allow you to partition
your hard disk. The utilities supports both modern and legacy
partition tables (eg. GPT, MBR, etc).
.
The fdisk utility is the classical text-mode utility.
The cfdisk utility gives a more userfriendly curses based interface.
The sfdisk utility is mostly for automation and scripting uses.`,
		PUrl: "pkg:deb/ubuntu/fdisk@2.31.1-0.4ubuntu3.1?arch=amd64&distro=ubuntu-18.04",
		CPEs: []string{
			"cpe:2.3:a:fdisk:fdisk:2.31.1-0.4ubuntu3.1:*:*:*:*:*:amd64:*",
			"cpe:2.3:a:fdisk:fdisk:2.31.1-0.4ubuntu3.1:*:*:*:*:*:*:*",
		},
		Format: "deb",
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:    "libaudit1",
		Version: "1:2.4-1+b1",
		// The version dpkg writes carries the epoch, and Epoch carries it on
		// its own too, the same pairing the rpm reader produces. It reaches
		// the epoch qualifier of the purl and the update component of the CPE.
		Epoch:  "1",
		Arch:   "amd64",
		Status: "install ok installed",
		Origin: "audit (1:2.4-1)",
		Description: `Dynamic library for security auditing
The audit-libs package contains the dynamic libraries needed for
applications to use the audit framework. It is used to monitor systems for
security related events.`,
		PUrl: "pkg:deb/ubuntu/libaudit1@1:2.4-1%2Bb1?arch=amd64&distro=ubuntu-18.04&epoch=1",
		CPEs: []string{
			"cpe:2.3:a:libaudit1:libaudit1:2.4-1\\+b1:1:*:*:*:*:amd64:*",
			"cpe:2.3:a:libaudit1:libaudit1:2.4-1\\+b1:1:*:*:*:*:*:*",
		},
		Format:         "deb",
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:    "libss2",
		Version: "1.44.1-1",
		Arch:    "amd64",
		Status:  "install ok installed",
		Origin:  "e2fsprogs",
		Description: `command-line interface parsing library
libss provides a simple command-line interface parser which will
accept input from the user, parse the command into an argv argument
vector, and then dispatch it to a handler function.
.
It was originally inspired by the Multics SubSystem library.`,
		PUrl: "pkg:deb/ubuntu/libss2@1.44.1-1?arch=amd64&distro=ubuntu-18.04",
		CPEs: []string{
			"cpe:2.3:a:libss2:libss2:1.44.1-1:*:*:*:*:*:amd64:*",
			"cpe:2.3:a:libss2:libss2:1.44.1-1:*:*:*:*:*:*:*",
		},
		Format:         "deb",
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	// fetch package files
	mgr := &DebPkgManager{
		conn:     mock,
		platform: pf,
	}
	pkgFiles, err := mgr.Files(p.Name, p.Version, p.Arch)
	require.NoError(t, err)
	assert.Equal(t, 1, len(pkgFiles), "detected the right amount of package files")
	assert.Contains(t, pkgFiles, FileRecord{Path: "/var/lib/dpkg/info/libss2:amd64.list"})
}

func TestDpkgParserStatusD(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "ubuntu",
		Version: "18.04",
		Arch:    "x86_64",
		Family:  []string{"debian", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "ubuntu",
		},
	}

	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_dpkg_statusd.toml"))
	require.NoError(t, err)
	f, err := mock.FileSystem().Open("/var/lib/dpkg/status.d/base")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseDpkgPackages(pf, f)
	require.NoError(t, err)
	assert.Equal(t, 1, len(m), "detected the right amount of packages")

	p := Package{
		Name:    "base-files",
		Version: "9.9+deb9u11",
		Arch:    "amd64",
		Description: `Debian base system miscellaneous files
This package contains the basic filesystem hierarchy of a Debian system, and
several important miscellaneous files, such as /etc/debian_version,
/etc/host.conf, /etc/issue, /etc/motd, /etc/profile, and others,
and the text of several common licenses in use on Debian systems.`,
		PUrl: "pkg:deb/ubuntu/base-files@9.9%2Bdeb9u11?arch=amd64&distro=ubuntu-18.04",
		CPEs: []string{
			"cpe:2.3:a:base-files:base-files:9.9\\+deb9u11:*:*:*:*:*:amd64:*",
			"cpe:2.3:a:base-files:base-files:9.9\\+deb9u11:*:*:*:*:*:*:*",
		},
		Format: "deb",
	}
	assert.Contains(t, m, p, "fdisk detected")
}

func TestDpkgUpdateParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/updates_dpkg.toml"))
	require.NoError(t, err)
	c, err := mock.RunCommand("DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run")
	require.NoError(t, err)
	assert.Nil(t, err)

	m, err := ParseDpkgUpdates(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 13, len(m), "detected the right amount of package updates")

	update := m["base-files"]
	assert.Equal(t, "base-files", update.Name, "pkg name detected")
	assert.Equal(t, "10.1ubuntu2", update.Version, "pkg version detected")
	assert.Equal(t, "10.1ubuntu2.1", update.Available, "pkg available version detected")

	update = m["ncurses-bin"]
	assert.Equal(t, "ncurses-bin", update.Name, "pkg name detected")
	assert.Equal(t, "6.1-1ubuntu1", update.Version, "pkg version detected")
	assert.Equal(t, "6.1-1ubuntu1.18.04", update.Available, "pkg available version detected")
}

func TestParseDpkgCopyrightLicense(t *testing.T) {
	fs := afero.NewMemMapFs()

	// DEP-5 copyright with header License: (rare but valid).
	const headerOnly = `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: bash
Source: https://www.gnu.org/software/bash/
License: GPL-3+
`
	require.NoError(t, afero.WriteFile(fs, "/usr/share/doc/bash/copyright", []byte(headerOnly), 0o644))

	// DEP-5 with License: only in the first Files: paragraph — the
	// common case for Debian/Ubuntu packages like apt and base-files.
	const filesParagraph = `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: apt
Source: https://salsa.debian.org/apt-team/apt

Files: *
Copyright: 1997, 1998, 1999, Jason Gilmore <jgg@debian.org>
License: GPL-2+
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License...
`
	require.NoError(t, afero.WriteFile(fs, "/usr/share/doc/apt/copyright", []byte(filesParagraph), 0o644))

	// Free-form copyright (older packages) with no License: field at
	// all — just a pointer to common-licenses.
	const freeform = `This package was debianized by John Doe <john@example.org>.
See /usr/share/common-licenses/GPL-2 for the full license text.
`
	require.NoError(t, afero.WriteFile(fs, "/usr/share/doc/legacy/copyright", []byte(freeform), 0o644))

	assert.Equal(t, "GPL-3+", ParseDpkgCopyrightLicense(fs, "bash"))
	assert.Equal(t, "GPL-2+", ParseDpkgCopyrightLicense(fs, "apt"),
		"License: in the first Files: paragraph (typical Ubuntu/Debian shape) must be surfaced")
	assert.Equal(t, "", ParseDpkgCopyrightLicense(fs, "legacy"))
	assert.Equal(t, "", ParseDpkgCopyrightLicense(fs, "missing"))
	assert.Equal(t, "", ParseDpkgCopyrightLicense(fs, ""))
	assert.Equal(t, "", ParseDpkgCopyrightLicense(nil, "bash"))
}

// A line longer than bufio.Scanner's 64KB default used to end the scan, and
// every package behind it was dropped while the parser still reported success.
func TestDpkgLongLineDoesNotTruncate(t *testing.T) {
	pf := &inventory.Platform{Name: "ubuntu", Version: "24.04", Arch: "amd64"}

	var buf bytes.Buffer
	buf.WriteString("Package: first\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n")
	buf.WriteString("Package: huge\nStatus: install ok installed\nVersion: 2.0\nArchitecture: amd64\n")
	buf.WriteString("Depends: " + strings.Repeat("libfoo (>= 1.0), ", 6000) + "libbar\n\n")
	buf.WriteString("Package: last\nStatus: install ok installed\nVersion: 3.0\nArchitecture: amd64\n\n")

	pkgs, err := ParseDpkgPackages(pf, bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	names := make([]string, len(pkgs))
	for i := range pkgs {
		names[i] = pkgs[i].Name
	}
	assert.Equal(t, []string{"first", "huge", "last"}, names)
}

// Past the raised cap the read still stops, and a short package list must not
// be handed back as a successful parse.
func TestDpkgOverlongLineIsAnError(t *testing.T) {
	pf := &inventory.Platform{Name: "ubuntu", Version: "24.04", Arch: "amd64"}

	var buf bytes.Buffer
	buf.WriteString("Package: first\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n")
	buf.WriteString("Package: huge\nDepends: " + strings.Repeat("x", dpkgMaxLine+1) + "\n\n")
	buf.WriteString("Package: last\nStatus: install ok installed\nVersion: 3.0\nArchitecture: amd64\n\n")

	pkgs, err := ParseDpkgPackages(pf, bytes.NewReader(buf.Bytes()))
	require.Error(t, err)
	assert.Nil(t, pkgs, "a partial inventory must not be reported as a complete one")
	assert.Contains(t, err.Error(), "could not read the dpkg status stream to its end")
}

// The trailing add() is guarded now, which must not cost the last package of a
// stream that ends without an empty line.
func TestDpkgLastPackage(t *testing.T) {
	pf := &inventory.Platform{Name: "ubuntu", Version: "24.04", Arch: "amd64"}
	status := "Package: first\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n" +
		"Package: last\nStatus: install ok installed\nVersion: 2.0\nArchitecture: amd64\n"

	pkgs, err := ParseDpkgPackages(pf, bytes.NewReader([]byte(status)))
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "last", pkgs[1].Name)

	// and the same stream closed with an empty line
	pkgs, err = ParseDpkgPackages(pf, bytes.NewReader([]byte(status+"\n")))
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "last", pkgs[1].Name)
}

// The trailing add() used to run on an empty package for every stream that
// ends with an empty line, which is every healthy host, and logged it as
// ignored. Nothing was lost, but the debug log said otherwise once per parse.
func TestDpkgNoSpuriousIgnoreLog(t *testing.T) {
	pf := &inventory.Platform{Name: "ubuntu", Version: "24.04", Arch: "amd64"}
	status := "Package: first\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n"

	// The parser logs through the process-wide zerolog logger, so observing
	// what it writes means swapping that logger for the duration of this test.
	// No test in this package runs in parallel and the parser logs from the
	// calling goroutine only, so nothing else can read the logger while it is
	// swapped. If a parallel test is ever added here, this has to move to a
	// logger passed into the parser rather than the global one.
	var out bytes.Buffer
	origLogger := log.Logger
	log.Logger = zerolog.New(&out)
	defer func() { log.Logger = origLogger }()

	pkgs, err := ParseDpkgPackages(pf, bytes.NewReader([]byte(status)))
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.NotContains(t, out.String(), "ignored deb packages since information is missing")
}

// Both shapes that used to cost a package its description, in the form they
// appear on a real host: libc6 carries a colon in its summary, and
// gpg-wks-client carries one in a continuation line.
func TestDpkgParserDescriptionWithColons(t *testing.T) {
	pf := &inventory.Platform{Name: "ubuntu", Version: "24.04", Arch: "amd64"}

	status := `Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.39-0ubuntu8.6
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system. This package includes shared versions of the standard C library
 and the standard math library, as well as many others.

Package: gpg-wks-client
Status: install ok installed
Architecture: amd64
Version: 2.4.4-2ubuntu17
Description: GNU privacy guard - Web Key Service client
 GnuPG is GNU's tool for secure communication and data storage.
 For more information see: https://wiki.gnupg.org/WKS
 It is a tool to provide digital encryption.
`

	pkgs, err := ParseDpkgPackages(pf, bytes.NewReader([]byte(status)))
	require.NoError(t, err)
	require.Len(t, pkgs, 2)

	// The summary keeps the colon that used to be read as the separator, and
	// the continuation lines that used to be dropped with it are still here.
	assert.Equal(t, `GNU C Library: Shared libraries
Contains the standard libraries that are used by nearly all programs on
the system. This package includes shared versions of the standard C library
and the standard math library, as well as many others.`, pkgs[0].Description)

	// A continuation line is a continuation whatever it contains, so the
	// description does not end at the colon in the middle of it.
	assert.Equal(t, `GNU privacy guard - Web Key Service client
GnuPG is GNU's tool for secure communication and data storage.
For more information see: https://wiki.gnupg.org/WKS
It is a tool to provide digital encryption.`, pkgs[1].Description)
}

func TestDpkgControlField(t *testing.T) {
	// A field name carries neither space nor colon, so the first colon ends it,
	// and a line starting with a space or a tab continues the field above it.
	tests := []struct {
		line  string
		key   string
		value string
		ok    bool
	}{
		{"Package: bash", "Package", "bash", true},
		// the epoch colon has no whitespace after it, so it is not a split point
		{"Version: 2:5.2-2ubuntu1", "Version", "2:5.2-2ubuntu1", true},
		{"Depends: libc6 (>= 2.34), libtinfo6", "Depends", "libc6 (>= 2.34), libtinfo6", true},
		// A colon inside the value is part of the value. Reading the last one
		// as the separator is what used to leave every package whose summary
		// carries a colon -- libc6 among them -- with no description at all.
		{"Description: the GNU shell: a thing", "Description", "the GNU shell: a thing", true},
		{"Description: GNU C Library: Shared libraries", "Description", "GNU C Library: Shared libraries", true},
		{"Field:\tvalue", "Field", "value", true},
		{"Field:  padded", "Field", " padded", true},
		// no whitespace after the colon
		{"a:b", "", "", false},
		// nothing after the whitespace
		{"a: ", "", "", false},
		// nothing before the colon
		{": b", "", "", false},
		// continuation lines carry no field, whatever they contain
		{" /etc/bash.bashrc 1234", "", "", false},
		{" For more information see: https://wiki.gnupg.org/WKS", "", "", false},
		{"\tindented continuation: with a colon", "", "", false},
		{"Conffiles:", "", "", false},
		{"", "", "", false},
		// multi-byte runes around the split point
		{"Maintainer: Ubuntu Developers <foo@example.org>", "Maintainer", "Ubuntu Developers <foo@example.org>", true},
		{"Nameé: valué", "Nameé", "valué", true},
	}
	for _, test := range tests {
		key, value, ok := dpkgControlField([]byte(test.line))
		assert.Equal(t, test.ok, ok, "match for %q", test.line)
		assert.Equal(t, test.key, string(key), "key for %q", test.line)
		assert.Equal(t, test.value, string(value), "value for %q", test.line)
	}
}

// dpkgBenchStatus builds a status stream in the shape of /var/lib/dpkg/status.
func dpkgBenchStatus(pkgCount int) []byte {
	var buf bytes.Buffer
	for i := 0; i < pkgCount; i++ {
		name := "package-" + strconv.Itoa(i)
		buf.WriteString("Package: " + name + "\n")
		buf.WriteString("Status: install ok installed\n")
		buf.WriteString("Priority: optional\n")
		buf.WriteString("Section: utils\n")
		buf.WriteString("Installed-Size: " + strconv.Itoa(100+i) + "\n")
		buf.WriteString("Maintainer: Ubuntu Developers <foo@example.org>\n")
		buf.WriteString("Architecture: amd64\n")
		buf.WriteString("Source: " + name + "-src\n")
		buf.WriteString("Version: 1." + strconv.Itoa(i) + "-2ubuntu1\n")
		buf.WriteString("Depends: libc6 (>= 2.34), libtinfo6 (>= 6), libselinux1 (>= 3.1)\n")
		buf.WriteString("Description: short summary for " + name + "\n")
		for j := 0; j < 6; j++ {
			buf.WriteString(" continuation line " + strconv.Itoa(j) + " of the long description\n")
		}
		buf.WriteString("Original-Maintainer: Debian Developers <bar@example.org>\n")
		buf.WriteString("Homepage: https://example.org/" + name + "\n")
		buf.WriteString("\n")
	}
	return buf.Bytes()
}

func BenchmarkParseDpkgPackages(b *testing.B) {
	data := dpkgBenchStatus(1600)
	pf := &inventory.Platform{Name: "ubuntu", Version: "24.04", Arch: "amd64"}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkgs, err := ParseDpkgPackages(pf, bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}
		if len(pkgs) != 1600 {
			b.Fatalf("expected 1600 packages, got %d", len(pkgs))
		}
	}
}

// TestParseDpkgUpdatesArch reads `apt-get upgrade --dry-run` captured from a
// live Ubuntu 24.04 host on 2026-09-18, where apt listed 31 upgradable
// packages and mql reported `outdated` 0.
//
// The cause was the missing Arch: packages.list keys available updates by
// "<name>/<arch>", so an update parsed without one is looked up as
// "libc6/amd64" against a map holding "libc6/" and never matches.
func TestParseDpkgUpdatesArch(t *testing.T) {
	f, err := os.Open("./testdata/apt-ubuntu2404.txt")
	require.NoError(t, err)
	defer f.Close()

	m, err := ParseDpkgUpdates(f)
	require.NoError(t, err)
	assert.Len(t, m, 31, "apt printed 31 Inst lines")

	libc, ok := m["libc6"]
	require.True(t, ok)
	assert.Equal(t, "2.39-0ubuntu8.8", libc.Version)
	assert.Equal(t, "2.39-0ubuntu8.9", libc.Available)
	assert.Equal(t, "amd64", libc.Arch)

	// an Architecture: all package reports "all", which is what dpkg records
	// for it too, so the join key still matches
	mnc, ok := m["motd-news-config"]
	require.True(t, ok)
	assert.Equal(t, "all", mnc.Arch)

	// every entry must carry an arch, or its join silently fails
	for name, u := range m {
		assert.NotEmpty(t, u.Arch, "package %s has no arch", name)
	}
}

func TestParseDpkgUpdatesLineShapes(t *testing.T) {
	in := strings.Join([]string{
		// trailing "because of" group must not be read as the arch
		`Inst libperl5.38t64 [5.38.2-3.2ubuntu0.4] (5.38.2-3.2ubuntu0.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) [perl:amd64 ]`,
		// single origin, no trailing group
		`Inst liblzma5 [5.4.1-1+deb12u1] (5.4.1-1+deb12u2 Debian-Security:12/oldstable-security [amd64])`,
		// an epoch in both versions: the enumerated character classes this
		// regex replaced had no ':' and dropped the line entirely
		`Inst tar [1:1.34+dfsg-1] (1:1.34+dfsg-1.1 Debian:12/stable [amd64])`,
		// Conf lines are not upgrades
		`Conf liblzma5 (5.4.1-1+deb12u2 Debian-Security:12/oldstable-security [amd64])`,
		`Reading package lists...`,
	}, "\n")

	m, err := ParseDpkgUpdates(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, m, 3)

	assert.Equal(t, "amd64", m["libperl5.38t64"].Arch)
	assert.Equal(t, "5.38.2-3.2ubuntu0.6", m["libperl5.38t64"].Available)
	assert.Equal(t, "amd64", m["liblzma5"].Arch)
	assert.Equal(t, "1:1.34+dfsg-1", m["tar"].Version)
	assert.Equal(t, "1:1.34+dfsg-1.1", m["tar"].Available)
	_, isConf := m["Conf"]
	assert.False(t, isConf)
}

func TestEpochFromVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
		why     string
	}{
		{"1:2.38.1-5+deb12u3", "1", "bsdutils on debian 12"},
		{"2:6.2.1+dfsg1-1.1", "2", "libgmp10 on debian 12"},
		{"1:4.13+dfsg1-1+deb12u2", "1", "login on debian 12"},
		{"10:1.0-1", "10", "epoch is not limited to one digit"},
		{"3.134", "", "no epoch"},
		{"5.2.15-2+b13", "", "no epoch"},
		{"0:1.0-1", "", "an explicit zero epoch is no epoch, as for rpm"},
		{"00:1.0-1", "", "still zero"},
		{"", "", "empty version"},
		{":1.0-1", "", "nothing before the colon is not an epoch"},
		// An upstream_version may contain a colon only when an epoch is
		// present, so a non-numeric run before the first colon is part of the
		// version rather than an epoch.
		{"1.0:beta-1", "", "non-numeric before the colon"},
		{"abc:1.0-1", "", "non-numeric before the colon"},
		{"1a:1.0-1", "", "not all digits before the colon"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, epochFromVersion(tt.version), "%s (%s)", tt.version, tt.why)
	}
}

// TestDpkgParserEpoch pins that an epoch-bearing deb package reports the epoch
// on its own field, keeps the epoch inside version the way rpm does, and
// carries the epoch qualifier on its purl. Removing the epochFromVersion call
// in ParseDpkgPackages makes every assertion but the version one fail.
func TestDpkgParserEpoch(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "debian",
		Version: "12",
		Arch:    "arm64",
		Family:  []string{"debian", "linux", "unix", "os"},
		Labels:  map[string]string{"distro-id": "debian"},
	}

	// Real stanzas from a debian:12 container.
	status := strings.Join([]string{
		"Package: bsdutils",
		"Status: install ok installed",
		"Architecture: arm64",
		"Version: 1:2.38.1-5+deb12u3",
		"",
		"Package: adduser",
		"Status: install ok installed",
		"Architecture: all",
		"Version: 3.134",
		"",
	}, "\n")

	m, err := ParseDpkgPackages(pf, strings.NewReader(status))
	require.NoError(t, err)
	require.Len(t, m, 2)

	assert.Equal(t, "bsdutils", m[0].Name)
	assert.Equal(t, "1", m[0].Epoch)
	assert.Equal(t, "1:2.38.1-5+deb12u3", m[0].Version, "version keeps the epoch, as it does for rpm")
	assert.Contains(t, m[0].PUrl, "epoch=1")

	assert.Equal(t, "adduser", m[1].Name)
	assert.Empty(t, m[1].Epoch)
	assert.NotContains(t, m[1].PUrl, "epoch=")
}
