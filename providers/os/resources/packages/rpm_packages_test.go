// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
)

func TestRedhat8Parser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_redhat8.toml"))
	if err != nil {
		t.Fatal(err)
	}

	pf := &inventory.Platform{
		Name:    "redhat",
		Version: "8.4",
		Arch:    "x86_64",
		Family:  []string{"redhat", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "rhel",
		},
	}

	c, err := mock.RunCommand("rpm -qa --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}\\n'")
	if err != nil {
		t.Fatal(err)
	}

	m := ParseRpmPackages(pf, c.Stdout)
	assert.Equal(t, 192, len(m), "detected the right amount of packages")

	p := Package{
		Name:        "ncurses-base",
		Version:     "6.1-7.20180224.el8",
		Vendor:      "Red Hat, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "noarch",
		Description: "Descriptions of common terminals",
		PUrl:        "pkg:rpm/redhat/ncurses-base@6.1-7.20180224.el8?arch=noarch&distro=rhel-8.4",
		CPEs: []string{
			"cpe:2.3:a:red_hat\\,_inc.:ncurses-base:6.1-7.20180224.el8:*:*:*:*:*:noarch:*",
			"cpe:2.3:a:red_hat\\,_inc.:ncurses-base:6.1-7.20180224.el8:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:        "libstdc++",
		Version:     "8.4.1-1.el8",
		Vendor:      "Red Hat, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "x86_64",
		Description: "GNU Standard C++ Library",
		PUrl:        "pkg:rpm/redhat/libstdc%2B%2B@8.4.1-1.el8?arch=x86_64&distro=rhel-8.4",
		CPEs: []string{
			"cpe:2.3:a:red_hat\\,_inc.:libstdc\\+\\+:8.4.1-1.el8:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:libstdc\\+\\+:8.4.1-1.el8:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:        "iptables-libs",
		Version:     "1.8.4-17.el8_4.1",
		Vendor:      "Red Hat, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "x86_64",
		Description: "iptables libraries",
		PUrl:        "pkg:rpm/redhat/iptables-libs@1.8.4-17.el8_4.1?arch=x86_64&distro=rhel-8.4",
		CPEs: []string{
			"cpe:2.3:a:red_hat\\,_inc.:iptables-libs:1.8.4-17.el8_4.1:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:iptables-libs:1.8.4-17.el8_4.1:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:        "openssl-libs",
		Version:     "1:1.1.1g-15.el8_3",
		Vendor:      "Red Hat, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Epoch:       "1",
		Arch:        "x86_64",
		Description: "A general purpose cryptography library with TLS implementation",
		PUrl:        "pkg:rpm/redhat/openssl-libs@1:1.1.1g-15.el8_3?arch=x86_64&distro=rhel-8.4&epoch=1",
		CPEs: []string{
			"cpe:2.3:a:red_hat\\,_inc.:openssl-libs:1.1.1g-15.el8_3:1:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:        "dbus-libs",
		Version:     "1:1.12.8-12.el8_4.2",
		Vendor:      "Red Hat, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Epoch:       "1",
		Arch:        "x86_64",
		Description: "Libraries for accessing D-BUS",
		PUrl:        "pkg:rpm/redhat/dbus-libs@1:1.12.8-12.el8_4.2?arch=x86_64&distro=rhel-8.4&epoch=1",
		CPEs: []string{
			"cpe:2.3:a:red_hat\\,_inc.:dbus-libs:1.12.8-12.el8_4.2:1:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:dbus-libs:1.12.8-12.el8_4.2:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:dbus-libs:1.12.8-12.el8_4.2:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	// Package with (none) vendor and arch
	p = Package{
		Name:           "gpg-pubkey",
		Version:        "d4082792-5b32db75",
		Vendor:         "(none)",
		Description:    "gpg(Red Hat, Inc. (auxiliary key) <security@redhat.com>)",
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
		PUrl:           "pkg:rpm/redhat/gpg-pubkey@d4082792-5b32db75?distro=rhel-8.4",
		CPEs: []string{
			"cpe:2.3:a:\\(none\\):gpg-pubkey:d4082792-5b32db75:*:*:*:*:*:*:*",
			"cpe:2.3:a:\\(none\\):gpg-pubkey:d4082792-5b32db75:*:*:*:*:*:*:*",
		},
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	// fetch package files
	p = Package{
		Name:        "which",
		Version:     "2.21-12.el8",
		Vendor:      "Red Hat, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Epoch:       "",
		Arch:        "x86_64",
		Description: "Displays where a particular program in your path is located",
		PUrl:        "pkg:rpm/redhat/which@2.21-12.el8?arch=x86_64&distro=rhel-8.4",
		CPEs: []string{
			"cpe:2.3:a:red_hat\\,_inc.:which:2.21-12.el8:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:red_hat\\,_inc.:which:2.21-12.el8:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	mgr := &RpmPkgManager{
		conn:     mock,
		platform: pf,
	}
	pkgFiles, err := mgr.Files(p.Name, p.Version, p.Arch)
	require.NoError(t, err)
	assert.Equal(t, 1, len(pkgFiles), "detected the right amount of package files")
	assert.Contains(t, pkgFiles, FileRecord{Path: "/var/lib/rpm/rpmdb.sqlite"})
}

func TestPhoton4ImageParser(t *testing.T) {
	// To get this data, run the following command on a Photon 4 system:
	// tdnf info ncurses-libs bash sqlite-libs

	epoch := int(0)
	pkgList := []*rpmdb.PackageInfo{
		{
			Name:        "ncurses-libs",
			Epoch:       &epoch,
			Version:     "6.2",
			Release:     "6.ph4",
			Arch:        "x86_64",
			Vendor:      "VMware, Inc.",
			License:     "GPLv3+",
			InstallTime: 1704067200, // 2024-01-01T00:00:00Z
			Summary:     "Ncurses Libraries",
		},
		{
			Name:        "bash",
			Epoch:       &epoch,
			Version:     "5.0",
			Release:     "4.ph4",
			Arch:        "x86_64",
			Vendor:      "VMware, Inc.",
			License:     "GPLv3+",
			InstallTime: 1704067200, // 2024-01-01T00:00:00Z
			Summary:     "Bourne-Again SHell",
		},
		{
			Name:        "sqlite-libs",
			Epoch:       &epoch,
			Version:     "3.38.5",
			Release:     "4.ph4",
			Arch:        "x86_64",
			Vendor:      "VMware, Inc.",
			License:     "GPLv3+",
			InstallTime: 1704067200, // 2024-01-01T00:00:00Z
			Summary:     "sqlite3 library",
		},
	}

	var packageList bytes.Buffer
	for _, pkg := range pkgList {
		fmt.Fprintf(&packageList, "%s %d:%s-%s %s__%s__%s__%s__%d\n", pkg.Name, pkg.EpochNum(), pkg.Version, pkg.Release, pkg.Arch, pkg.Vendor, pkg.Summary, pkg.License, pkg.InstallTime)
	}

	pf := &inventory.Platform{
		Name:    "photon",
		Version: "4.0",
		Arch:    "x86_64",
		Family:  []string{"linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "photon",
		},
	}

	m := ParseRpmPackages(pf, &packageList)
	assert.Equal(t, 3, len(m), "detected the right amount of packages")

	p := Package{
		Name:        "ncurses-libs",
		Version:     "6.2-6.ph4",
		Vendor:      "VMware, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "x86_64",
		Description: "Ncurses Libraries",
		PUrl:        "pkg:rpm/photon%20os/ncurses-libs@6.2-6.ph4?arch=x86_64&distro=photon-4.0",
		CPEs: []string{
			"cpe:2.3:a:vmware\\,_inc.:ncurses-libs:6.2-6.ph4:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:vmware\\,_inc.:ncurses-libs:6.2-6.ph4:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:        "bash",
		Version:     "5.0-4.ph4",
		Vendor:      "VMware, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "x86_64",
		Description: "Bourne-Again SHell",
		PUrl:        "pkg:rpm/photon%20os/bash@5.0-4.ph4?arch=x86_64&distro=photon-4.0",
		CPEs: []string{
			"cpe:2.3:a:vmware\\,_inc.:bash:5.0-4.ph4:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:vmware\\,_inc.:bash:5.0-4.ph4:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)

	p = Package{
		Name:        "sqlite-libs",
		Version:     "3.38.5-4.ph4",
		Vendor:      "VMware, Inc.",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "x86_64",
		Description: "sqlite3 library",
		PUrl:        "pkg:rpm/photon%20os/sqlite-libs@3.38.5-4.ph4?arch=x86_64&distro=photon-4.0",
		CPEs: []string{
			"cpe:2.3:a:vmware\\,_inc.:sqlite-libs:3.38.5-4.ph4:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:vmware\\,_inc.:sqlite-libs:3.38.5-4.ph4:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, findPkg(m, p.Name), p.Name)
}

// ensure that the tag in the SuSE vendor name is parsed correctly
func TestSuSEParser(t *testing.T) {
	epoch := int(0)
	pkgList := []*rpmdb.PackageInfo{
		{
			Name:        "grep",
			Epoch:       &epoch,
			Version:     "3.1",
			Release:     "150000.4.6.1",
			Arch:        "x86_64",
			Vendor:      "SUSE LLC <https://www.suse.com/>",
			License:     "GPLv3+",
			InstallTime: 1704067200, // 2024-01-01T00:00:00Z
			Summary:     "Print lines matching a pattern",
		},
	}

	var packageList bytes.Buffer
	for _, pkg := range pkgList {
		fmt.Fprintf(&packageList, "%s %d:%s-%s %s__%s__%s__%s__%d\n", pkg.Name, pkg.EpochNum(), pkg.Version, pkg.Release, pkg.Arch, pkg.Vendor, pkg.Summary, pkg.License, pkg.InstallTime)
	}

	pf := &inventory.Platform{
		Name:    "suse",
		Version: "15.6",
		Arch:    "x86_64",
		Family:  []string{"linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "suse",
		},
	}

	m := ParseRpmPackages(pf, &packageList)
	assert.Equal(t, 1, len(m), "detected the right amount of packages")

	p := Package{
		Name:    "grep",
		Version: "3.1-150000.4.6.1",
		// Note that the tag <https://suse.com/> has been removed.
		Vendor:      "SUSE LLC",
		License:     "GPLv3+",
		InstallDate: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		Arch:        "x86_64",
		Description: "Print lines matching a pattern",
		PUrl:        "pkg:rpm/suse/grep@3.1-150000.4.6.1?arch=x86_64&distro=suse-15.6",
		CPEs: []string{
			"cpe:2.3:a:suse_llc:grep:3.1-150000.4.6.1:*:*:*:*:*:x86_64:*",
			"cpe:2.3:a:suse_llc:grep:3.1-150000.4.6.1:*:*:*:*:*:*:*",
		},
		Format:         RpmPkgFormat,
		FilesAvailable: PkgFilesAsync,
	}
	assert.Equal(t, p, m[0], p.Name)
}

func TestVendorNameCleanup(t *testing.T) {
	vendorFromRpm := "SUSE LLC"
	actual := cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)

	vendorFromRpm = "SUSE LLC<https://suse.com/>"
	actual = cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)

	vendorFromRpm = "SUSE LLC <https://suse.com/>"
	actual = cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)

	vendorFromRpm = "SUSE LLC     <https://suse.com/>"
	actual = cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)

	vendorFromRpm = "SUSE LLC <abc><def>"
	actual = cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)

	vendorFromRpm = "SUSE LLC <>"
	actual = cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)

	vendorFromRpm = "SUSE LLC <<>>"
	actual = cleanupVendorName(vendorFromRpm)
	require.Equal(t, "SUSE LLC", actual)
}

func TestOracleParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_oracle.toml"))
	if err != nil {
		t.Fatal(err)
	}

	pf := &inventory.Platform{
		Name:    "oraclelinux",
		Version: "9",
		Arch:    "x86_64",
		Family:  []string{"redhat", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "oraclelinux",
		},
	}

	c, err := mock.RunCommand("rpm -qa --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}__%{MODULARITYLABEL}\\n'")
	if err != nil {
		t.Fatal(err)
	}

	m := ParseRpmPackages(pf, c.Stdout)
	assert.Equal(t, 4, len(m), "detected the right amount of packages")

	p := Package{
		Name: "ruby",
		PUrl: "pkg:rpm/oraclelinux/ruby@3.1.7-146.module%2Bel9.5.0%2B90564%2B273a1edd?arch=x86_64&distro=oraclelinux-9&rpmmod=ruby:3.1:9050020250506050702:2e2f0e1c",
	}
	fPkg := findPkg(m, p.Name)
	assert.Equal(t, p.PUrl, fPkg.PUrl)

	p = Package{
		Name: "adcli",
		PUrl: "pkg:rpm/oraclelinux/adcli@0.9.2-1.el9?arch=x86_64&distro=oraclelinux-9",
	}
	fPkg = findPkg(m, p.Name)
	assert.Equal(t, p.PUrl, fPkg.PUrl)
}

func TestAlmaLinuxParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_almalinux.toml"))
	if err != nil {
		t.Fatal(err)
	}

	pf := &inventory.Platform{
		Name:    "almalinux",
		Version: "8.10",
		Arch:    "x86_64",
		Family:  []string{"redhat", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "almalinux",
		},
	}

	c, err := mock.RunCommand("rpm -qa --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}__%{MODULARITYLABEL}\\n'")
	if err != nil {
		t.Fatal(err)
	}

	m := ParseRpmPackages(pf, c.Stdout)
	require.Equal(t, 6, len(m))

	p := Package{
		Name: "php-cli",
		PUrl: "pkg:rpm/almalinux/php-cli@7.4.33-2.module_el8.10.0%2B3935%2B28808425?arch=aarch64&distro=almalinux-8.10&rpmmod=php:7.4:8100020241212065510:eb0869e2",
	}
	fPkg := findPkg(m, p.Name)
	assert.Equal(t, p.PUrl, fPkg.PUrl)
}

func TestRedHatModularParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_redhat8_modular.toml"))
	if err != nil {
		t.Fatal(err)
	}

	pf := &inventory.Platform{
		Name:    "redhat",
		Version: "8.10",
		Arch:    "aarch64",
		Family:  []string{"redhat", "linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "rhel",
		},
	}

	c, err := mock.RunCommand("rpm -qa --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}__%{MODULARITYLABEL}\\n'")
	if err != nil {
		t.Fatal(err)
	}

	m := ParseRpmPackages(pf, c.Stdout)
	require.Equal(t, 4, len(m))

	// Verify modular package has rpmmod qualifier
	p := Package{
		Name: "php-cli",
		PUrl: "pkg:rpm/redhat/php-cli@7.4.33-3.module%2Bel8.10.0%2B23902%2Bd3c8dd8f?arch=aarch64&distro=rhel-8.10&rpmmod=php:7.4:8100020260119075152:f7998665",
	}
	fPkg := findPkg(m, p.Name)
	assert.Equal(t, p.PUrl, fPkg.PUrl)

	// Verify non-modular package does not have rpmmod qualifier
	p = Package{
		Name: "bash",
		PUrl: "pkg:rpm/redhat/bash@4.4.20-1.el8_4?arch=x86_64&distro=rhel-8.10",
	}
	fPkg = findPkg(m, p.Name)
	assert.Equal(t, p.PUrl, fPkg.PUrl)
}

// TestModularitySupportedByPlatform pins the version window in which the
// %{MODULARITYLABEL} queryformat tag may be requested: modularity arrived in
// RHEL 8 and was removed again in RHEL 10, so only 8.x and 9.x qualify.
//
// The version-7 rows guard a regression that silently emptied the package
// inventory. The guard used to carry only the upper bound, so RHEL, CentOS and
// Oracle Linux 7 were handed the tag. Their rpm is 4.11, which does not know
// it: rpm printed "error: incorrect format: unknown tag" per package, wrote
// nothing at all to stdout, and still exited 0 - so `packages` came back as an
// empty list, with no error, on a host with a fully populated rpm database.
func TestModularitySupportedByPlatform(t *testing.T) {
	// every distro name the modularity switch knows about
	modularDistros := []string{"oraclelinux", "almalinux", "redhat", "centos", "rocky"}

	versions := []struct {
		version string
		want    bool
	}{
		{"7", false}, // rpm 4.11 has no %{MODULARITYLABEL}
		{"7.9", false},
		{"8", true},
		{"8.10", true},
		{"9", true},
		{"9.4", true},
		{"10", false}, // modularity removed in RHEL 10
		{"10.1", false},
		{"", false}, // unparseable version must not enable the tag
		{"unknown", false},
	}

	for _, distro := range modularDistros {
		for _, v := range versions {
			t.Run(fmt.Sprintf("%s/%q", distro, v.version), func(t *testing.T) {
				pf := &inventory.Platform{Name: distro, Version: v.version, Arch: "x86_64"}
				require.Equal(t, v.want, modularitySupportedByPlatform(pf))
			})
		}
	}

	// Names outside the switch never get the tag, at any version. Amazon Linux 2
	// also ships rpm 4.11 and reported its packages correctly throughout,
	// precisely because it is not listed here.
	for _, distro := range []string{"amazonlinux", "fedora", "sles", "opensuse", "photon"} {
		for _, version := range []string{"2", "7", "8", "9", "10", ""} {
			t.Run(fmt.Sprintf("unlisted/%s/%q", distro, version), func(t *testing.T) {
				pf := &inventory.Platform{Name: distro, Version: version, Arch: "x86_64"}
				require.False(t, modularitySupportedByPlatform(pf))
			})
		}
	}
}

// renderRpmQueryFormat models how rpm renders a --queryformat string so we can
// check the round-trip without a real rpm binary. rpm interprets only the
// named C escapes (\a \b \f \n \r \t \v); for ANY other backslash sequence it
// drops the backslash and keeps the following byte(s) literally. Crucially,
// rpm's queryformat does NOT support \NNN octal or \xNN hex escapes — `\036`
// renders to the literal string "036", and `\x1e` to "x1e". (Confirmed against
// rpm 4.20.1: `rpm -q --qf 'A\tB\036C\x1eD\n'` emits "A<TAB>B036Cx1eD<LF>".)
// %{TAG} tokens contain no backslash, so escape processing leaves them intact;
// we substitute them afterwards with literal sample values.
func renderRpmQueryFormat(format string, fields map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] == '\\' && i+1 < len(format) {
			switch format[i+1] {
			case 'a':
				b.WriteByte('\a')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'v':
				b.WriteByte('\v')
			default:
				// unknown escape (incl. \NNN and \xNN): backslash dropped, byte kept
				b.WriteByte(format[i+1])
			}
			i++
			continue
		}
		b.WriteByte(format[i])
	}
	rendered := b.String()
	for tag, val := range fields {
		rendered = strings.ReplaceAll(rendered, "%{"+tag+"}", val)
	}
	return rendered
}

// TestRpmQueryFormatRoundTrip guards the queryformat field separator against
// the class of bug that caused the #7818 incident (reverted in #7963): the
// separator emitted by queryFormat() must be something rpm can actually render
// AND something RPM_REGEX can split on. #7818 switched the separator to `\036`
// (intending ASCII RS, 0x1E), but rpm's queryformat has no octal escape, so it
// emitted the literal "036"; RPM_REGEX expected the 0x1E byte, matched nothing,
// and every rpm asset reported zero packages.
//
// This renders the real queryFormat() output exactly the way rpm does, then
// feeds it back through ParseRpmPackages. Any separator rpm can't emit (or that
// the regex can't split on) fails here — deterministically, with no rpm binary,
// container, or VM.
func TestRpmQueryFormatRoundTrip(t *testing.T) {
	fields := map[string]string{
		"NAME":            "glibc",
		"EPOCH":           "0",
		"EPOCHNUM":        "0",
		"VERSION":         "2.34",
		"RELEASE":         "100.el8",
		"ARCH":            "x86_64",
		"VENDOR":          "Red Hat, Inc.",
		"SUMMARY":         "The GNU libc libraries",
		"LICENSE":         "LGPLv2+",
		"INSTALLTIME":     "1700000000",
		"MODULARITYLABEL": "(none)", // rpm emits "(none)" for non-modular packages
	}

	// Cover both queryFormat() variants: EPOCHNUM + modularity (redhat/centos 7+)
	// and EPOCH without modularity (suse).
	platforms := []*inventory.Platform{
		// redhat with a plain-integer version >=7 takes the EPOCHNUM branch in
		// queryFormat() (ParseInt rejects "8.10", so "8" is required to hit it).
		{Name: "redhat", Version: "8", Arch: "x86_64"},
		{Name: "oraclelinux", Version: "9", Arch: "x86_64"},
		{Name: "suse", Version: "15.6", Arch: "x86_64"},
	}

	for _, pf := range platforms {
		t.Run(pf.Name, func(t *testing.T) {
			mgr := &RpmPkgManager{platform: pf}
			format := mgr.queryFormat()

			output := renderRpmQueryFormat(format, fields)

			pkgs := ParseRpmPackages(pf, strings.NewReader(output))
			require.Lenf(t, pkgs, 1,
				"queryFormat() output is not parseable by RPM_REGEX — the field separator is not something rpm emits (octal/hex escape?). format=%q rendered=%q",
				format, output)

			p := pkgs[0]
			assert.Equal(t, "glibc", p.Name)
			assert.Equal(t, "2.34-100.el8", p.Version)
			assert.Equal(t, "x86_64", p.Arch)
			assert.Equal(t, "Red Hat, Inc.", p.Vendor)
			assert.Equal(t, "The GNU libc libraries", p.Description)
			assert.Equal(t, "LGPLv2+", p.License)
		})
	}
}

func TestNormalizeRpmEpoch(t *testing.T) {
	tests := []struct {
		epoch    string
		expected string
	}{
		// rpm's three spellings of "no epoch"
		{"0", ""},
		{"(none)", ""},
		{" (none) ", ""},
		{"", ""},
		// a real epoch survives
		{"1", "1"},
		{"2", "2"},
		{"10", "10"},
	}

	for _, test := range tests {
		t.Run(test.epoch, func(t *testing.T) {
			assert.Equal(t, test.expected, normalizeRpmEpoch(test.epoch))
		})
	}
}

// The rpmdb path (container images, filesystem scans) and the rpm command path
// (live hosts) must render identical versions and purls for the same package.
//
// They did not: the rpmdb path prefixed the epoch unconditionally, so a package
// with no epoch — the overwhelming majority — came out as "0:3.9.25-7.el9_8.2"
// from an image and "3.9.25-7.el9_8.2" from a live host. The purl differed with
// it, so the same package looked like two different packages depending on how
// the asset was scanned. Consumers that match a version by prefix rather than
// by rpm version comparison found nothing at all for rpm images.
//
// Verified against registry.access.redhat.com/ubi9/ubi:latest, scanned both as
// `docker image` (rpmdb) and `docker container` (rpm command).
func TestRpmEpochParityAcrossCollectionPaths(t *testing.T) {
	pf := &inventory.Platform{
		Name:    "redhat",
		Version: "9",
		Arch:    "aarch64",
		Family:  []string{"linux", "unix", "os"},
		Labels: map[string]string{
			"distro-id": "rhel",
		},
	}

	zero, one := 0, 1
	tests := []struct {
		name            string
		pkg             *rpmdb.PackageInfo
		expectedVersion string
	}{
		{
			name: "no epoch",
			pkg: &rpmdb.PackageInfo{
				Name: "python3", Epoch: &zero, Version: "3.9.25", Release: "7.el9_8.2",
				Arch: "aarch64", Vendor: "Red Hat, Inc.", License: "Python-2.0.1",
				Summary: "Python 3 interpreter",
			},
			expectedVersion: "3.9.25-7.el9_8.2",
		},
		{
			// Epoch is a nil pointer when rpm never recorded one at all;
			// EpochNum() reports 0 for it, same as an explicit zero.
			name: "epoch absent entirely",
			pkg: &rpmdb.PackageInfo{
				Name: "glibc", Epoch: nil, Version: "2.34", Release: "274.el9_8",
				Arch: "aarch64", Vendor: "Red Hat, Inc.", License: "LGPLv2+",
				Summary: "The GNU libc libraries",
			},
			expectedVersion: "2.34-274.el9_8",
		},
		{
			// A real epoch belongs in the version, and both paths already agreed here.
			name: "non-zero epoch",
			pkg: &rpmdb.PackageInfo{
				Name: "gmp", Epoch: &one, Version: "6.1.2", Release: "11.el8",
				Arch: "aarch64", Vendor: "Red Hat, Inc.", License: "LGPLv3+",
				Summary: "A GNU arbitrary precision library",
			},
			expectedVersion: "1:6.1.2-11.el8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fromDB := newRpmPackageFromDB(pf, test.pkg, "/var/lib/rpm/rpmdb.sqlite")

			// Render the same package the way `rpm -qa --queryformat` would,
			// then read it back through the command path.
			var out bytes.Buffer
			fmt.Fprintf(&out, "%s %d:%s-%s %s__%s__%s__%s__%d\n",
				test.pkg.Name, test.pkg.EpochNum(), test.pkg.Version, test.pkg.Release,
				test.pkg.Arch, test.pkg.Vendor, test.pkg.Summary, test.pkg.License, 0)
			fromCmd := ParseRpmPackages(pf, &out)
			require.Len(t, fromCmd, 1)

			assert.Equal(t, test.expectedVersion, fromDB.Version, "rpmdb path version")
			assert.Equal(t, test.expectedVersion, fromCmd[0].Version, "command path version")
			assert.Equal(t, fromCmd[0].Version, fromDB.Version, "versions must agree across paths")
			assert.Equal(t, fromCmd[0].PUrl, fromDB.PUrl, "purls must agree across paths")
			assert.Equal(t, fromCmd[0].Epoch, fromDB.Epoch, "epochs must agree across paths")
			assert.Equal(t, fromCmd[0].CPEs, fromDB.CPEs, "cpes must agree across paths")

			// The rpmdb path additionally carries the database as evidence.
			assert.Equal(t, PkgFilesIncluded, fromDB.FilesAvailable)
			assert.Equal(t, []FileRecord{{Path: "/var/lib/rpm/rpmdb.sqlite"}}, fromDB.Files)
		})
	}
}
