// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

var rpmCharsetPlatform = &inventory.Platform{
	Name:    "redhat",
	Version: "9",
	Arch:    "x86_64",
	Family:  []string{"redhat", "linux"},
}

// A package the regex cannot match is dropped from the inventory with no
// error, and an absent package is exactly what a vulnerability scan cannot
// report on. The name class used to be `[\w-+]`, which excluded the dot, so
// every RPM whose name contains one went missing from live-host scans.
func TestParseRpmPackages_NameCharacters(t *testing.T) {
	tests := []struct {
		name string
		line string
		want Package
	}{
		{
			name: "dots and hyphens in the name",
			line: `java-1.8.0-openjdk 1:1.8.0.402.b06-2.el8 x86_64__Red Hat, Inc.__OpenJDK 8 Runtime__ASL 2.0__1704067200__(none)`,
			want: Package{Name: "java-1.8.0-openjdk", Version: "1:1.8.0.402.b06-2.el8", Epoch: "1", Arch: "x86_64", Vendor: "Red Hat, Inc.", License: "ASL 2.0"},
		},
		{
			name: "dot in the name",
			line: `python3.11 0:3.11.5-1.el9 x86_64__Red Hat, Inc.__Python 3.11__Python-2.0__1704067200__(none)`,
			want: Package{Name: "python3.11", Version: "3.11.5-1.el9", Arch: "x86_64", Vendor: "Red Hat, Inc.", License: "Python-2.0"},
		},
		{
			name: "dot in a hyphenated name",
			line: `dotnet-sdk-8.0 0:8.0.1-1 x86_64__Microsoft__dotnet sdk__MIT__1704067200__(none)`,
			want: Package{Name: "dotnet-sdk-8.0", Version: "8.0.1-1", Arch: "x86_64", Vendor: "Microsoft", License: "MIT"},
		},
		{
			name: "plus signs in the name",
			line: `libstdc++ 0:14.2.1-3.el9 x86_64__Red Hat, Inc.__GNU Standard C++ Library__GPLv3+__1704067200__(none)`,
			want: Package{Name: "libstdc++", Version: "14.2.1-3.el9", Arch: "x86_64", Vendor: "Red Hat, Inc.", License: "GPLv3+"},
		},
		{
			name: "plus signs after a hyphen",
			line: `gcc-c++ 0:11.5.0-2.el9 x86_64__Red Hat, Inc.__C++ support for GCC__GPLv3+__1704067200__(none)`,
			want: Package{Name: "gcc-c++", Version: "11.5.0-2.el9", Arch: "x86_64", Vendor: "Red Hat, Inc.", License: "GPLv3+"},
		},
		{
			name: "leading digits in the name",
			line: `389-ds-base 0:2.4.5-1.el9 x86_64__Red Hat, Inc.__389 Directory Server__GPLv3+__1704067200__(none)`,
			want: Package{Name: "389-ds-base", Version: "2.4.5-1.el9", Arch: "x86_64", Vendor: "Red Hat, Inc.", License: "GPLv3+"},
		},
		{
			name: "name that is digits then letters",
			line: `2ping 0:4.5.1-2.el9 noarch__Fedora Project__Ping utility__GPLv2+__1704067200__(none)`,
			want: Package{Name: "2ping", Version: "4.5.1-2.el9", Arch: "noarch", Vendor: "Fedora Project", License: "GPLv2+"},
		},
		{
			name: "mixed case name",
			line: `NetworkManager-config-server 1:1.46.0-1.el9 noarch__Red Hat, Inc.__NM config__GPLv2+__1704067200__(none)`,
			want: Package{Name: "NetworkManager-config-server", Version: "1:1.46.0-1.el9", Epoch: "1", Arch: "noarch", Vendor: "Red Hat, Inc.", License: "GPLv2+"},
		},
		{
			name: "underscore in the name",
			line: `perl_bootstrap 0:1.0-1.el9 noarch__Red Hat, Inc.__bootstrap__GPLv2+__1704067200__(none)`,
			want: Package{Name: "perl_bootstrap", Version: "1.0-1.el9", Arch: "noarch", Vendor: "Red Hat, Inc.", License: "GPLv2+"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(tc.line+"\n"))
			require.Len(t, pkgs, 1, "package was dropped by RPM_REGEX")

			p := pkgs[0]
			assert.Equal(t, tc.want.Name, p.Name)
			assert.Equal(t, tc.want.Version, p.Version)
			assert.Equal(t, tc.want.Epoch, p.Epoch)
			assert.Equal(t, tc.want.Arch, p.Arch)
			assert.Equal(t, tc.want.Vendor, p.Vendor)
			assert.Equal(t, tc.want.License, p.License)
		})
	}
}

// rpm accepts `~` in a version since 4.10 and `^` since 4.15; both sort
// specially and both appear in real releases.
func TestParseRpmPackages_VersionCharacters(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantVersion string
	}{
		{
			name:        "tilde pre-release",
			line:        `foo 0:1.0~rc1-1.el8 x86_64__Red Hat, Inc.__foo__MIT__1704067200__(none)`,
			wantVersion: "1.0~rc1-1.el8",
		},
		{
			name:        "caret post-release snapshot",
			line:        `bar 0:2.0^20230101git-1.el9 x86_64__Red Hat, Inc.__bar__MIT__1704067200__(none)`,
			wantVersion: "2.0^20230101git-1.el9",
		},
		{
			name:        "underscore in the release",
			line:        `baz 0:1.0-1.module_el8+123+abc x86_64__Red Hat, Inc.__baz__MIT__1704067200__(none)`,
			wantVersion: "1.0-1.module_el8+123+abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(tc.line+"\n"))
			require.Len(t, pkgs, 1, "package was dropped by RPM_REGEX")
			assert.Equal(t, tc.wantVersion, pkgs[0].Version)
		})
	}
}

// The vendor class excluded `-`, so anything shipped by a vendor with a
// hyphenated name was dropped.
func TestParseRpmPackages_VendorCharacters(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantVendor string
	}{
		{
			name:       "hyphenated vendor",
			line:       `hpsa 0:1.0-1.el9 x86_64__Hewlett-Packard__driver__GPLv2+__1704067200__(none)`,
			wantVendor: "Hewlett-Packard",
		},
		{
			// The regex must capture the whole vendor including the bracketed
			// URL; cleanupVendorName then strips the brackets, deliberately,
			// because they break CPE generation.
			name:       "vendor with a bracketed URL is captured then cleaned",
			line:       `aaa_base 0:84.87-5.1 x86_64__SUSE LLC <https://www.suse.com/>__base__GPL-2.0+__1704067200__(none)`,
			wantVendor: "SUSE LLC",
		},
		{
			name:       "vendor with an ampersand",
			line:       `acme 0:1.0-1 noarch__Smith & Sons, Ltd.__thing__MIT__1704067200__(none)`,
			wantVendor: "Smith & Sons, Ltd.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(tc.line+"\n"))
			require.Len(t, pkgs, 1, "package was dropped by RPM_REGEX")
			assert.Equal(t, tc.wantVendor, pkgs[0].Vendor)
		})
	}

	// Assert the raw capture separately, so a regression in the vendor class
	// is distinguishable from a change in cleanupVendorName.
	t.Run("raw vendor capture keeps the bracketed URL", func(t *testing.T) {
		m := RPM_REGEX.FindStringSubmatch(`aaa_base 0:84.87-5.1 x86_64__SUSE LLC <https://www.suse.com/>__base__GPL-2.0+__1704067200__(none)`)
		require.NotNil(t, m)
		assert.Equal(t, "SUSE LLC <https://www.suse.com/>", m[5])
	})
}

// The field order must not shift. Arch contains underscores, so a greedy arch
// match spans the `__` separator and silently moves every later field down by
// one — producing, for example, a license of "1704067200".
func TestRpmRegex_FieldAlignment(t *testing.T) {
	m := RPM_REGEX.FindStringSubmatch(`dotnet-sdk-8.0 0:8.0.1-1 x86_64__Microsoft__dotnet sdk__MIT__1704067200__rhel8-module`)
	require.NotNil(t, m)

	assert.Equal(t, "dotnet-sdk-8.0", m[1], "name")
	assert.Equal(t, "0", m[2], "epoch")
	assert.Equal(t, "8.0.1-1", m[3], "version-release")
	assert.Equal(t, "x86_64", m[4], "arch")
	assert.Equal(t, "Microsoft", m[5], "vendor")
	assert.Equal(t, "dotnet sdk", m[6], "summary")
	assert.Equal(t, "MIT", m[7], "license")
	assert.Equal(t, "1704067200", m[8], "installtime")
	assert.Equal(t, "rhel8-module", m[9], "modularity label")
}

func TestParseRpmPackages_ArchAndSentinels(t *testing.T) {
	for _, arch := range []string{"x86_64", "noarch", "i686", "aarch64", "ppc64le", "s390x", "armv7hl"} {
		t.Run(arch, func(t *testing.T) {
			line := `glibc 0:2.34-100.el8 ` + arch + `__Red Hat, Inc.__libc__LGPLv2+__1700000000__(none)`
			pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
			require.Len(t, pkgs, 1)
			assert.Equal(t, arch, pkgs[0].Arch)
		})
	}

	t.Run("(none) arch is normalized to empty", func(t *testing.T) {
		line := `gpg-pubkey 0:fd431d51-4ae0493b (none)__(none)__gpg key__pubkey__(none)`
		pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
		require.Len(t, pkgs, 1)
		assert.Equal(t, "gpg-pubkey", pkgs[0].Name)
		assert.Empty(t, pkgs[0].Arch)
	})

	t.Run("(none) epoch is dropped from the version", func(t *testing.T) {
		line := `foo (none):1.0-1.el9 x86_64__Red Hat, Inc.__foo__MIT__1704067200__(none)`
		pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
		require.Len(t, pkgs, 1)
		assert.Equal(t, "1.0-1.el9", pkgs[0].Version)
		assert.Empty(t, pkgs[0].Epoch)
	})

	t.Run("empty epoch is dropped from the version", func(t *testing.T) {
		// %{EPOCH} on some rpm builds renders an unset epoch as empty rather
		// than "(none)"; the version must not come back as ":1.0-1.el9".
		line := `foo :1.0-1.el9 x86_64__Red Hat, Inc.__foo__MIT__1704067200__(none)`
		pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
		require.Len(t, pkgs, 1)
		assert.Equal(t, "1.0-1.el9", pkgs[0].Version)
		assert.Empty(t, pkgs[0].Epoch)
	})

	t.Run("(none) license is normalized to empty", func(t *testing.T) {
		line := `foo 0:1.0-1.el9 x86_64__Red Hat, Inc.__foo__(none)__1704067200__(none)`
		pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
		require.Len(t, pkgs, 1)
		assert.Empty(t, pkgs[0].License)
	})

	t.Run("trailing empty modularity label still parses", func(t *testing.T) {
		line := `foo 0:1.0-1.el9 x86_64__Red Hat, Inc.__foo__MIT__1704067200__`
		pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
		require.Len(t, pkgs, 1, "a trailing separator with an empty label must not drop the package")
		assert.Equal(t, "foo", pkgs[0].Name)
	})

	t.Run("no modularity field at all", func(t *testing.T) {
		line := `foo 0:1.0-1.el9 x86_64__Red Hat, Inc.__foo__MIT__1704067200`
		pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(line+"\n"))
		require.Len(t, pkgs, 1)
		assert.Equal(t, "foo", pkgs[0].Name)
	})
}

// A line past the scanner's buffer ends the scan, so it does not drop one
// package -- it drops that package and every package after it. The fields are
// free-form text with no length bound, so the buffer has to be raised above
// bufio's 64 KB default.
func TestParseRpmPackages_LongLineDoesNotTruncateTheList(t *testing.T) {
	longLicense := strings.Repeat("GPLv2+ and ", 10_000) // ~110 KB, past the 64 KB default
	listing := `glibc 0:2.34-100.el8 x86_64__Red Hat, Inc.__libc__` + longLicense + `__1700000000__(none)
bash 0:5.1.8-6.el9 x86_64__Red Hat, Inc.__shell__GPLv3+__1700000000__(none)
`

	pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(listing))
	require.Len(t, pkgs, 2, "a long line must not end the scan and swallow the packages behind it")
	assert.Equal(t, "glibc", pkgs[0].Name)
	assert.Equal(t, longLicense, pkgs[0].License)
	assert.Equal(t, "bash", pkgs[1].Name)
}

// Widening the field classes must not make the regex match arbitrary text.
// rpm writes errors and warnings to the same stream in some configurations.
func TestParseRpmPackages_RejectsNonPackageLines(t *testing.T) {
	noise := strings.Join([]string{
		"",
		"   ",
		"error: rpmdb: BDB0113 Thread/process 1/1 failed",
		"warning: Found bdb Packages database while attempting sqlite backend",
		"rpm: command not found",
		"some random text without separators",
		"a b c",
	}, "\n")

	pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(noise+"\n"))
	assert.Empty(t, pkgs, "non-package lines must not be parsed as packages")
}

// The strongest guard: render real packages through the actual queryFormat()
// exactly the way rpm does, then parse the result back. This covers the whole
// path — format string, separator and regex — for names, versions and vendors
// that the old character classes rejected, on every queryFormat() variant.
func TestRpmQueryFormatRoundTrip_RealisticFields(t *testing.T) {
	packages := []map[string]string{
		{
			"NAME": "java-1.8.0-openjdk", "EPOCH": "1", "EPOCHNUM": "1",
			"VERSION": "1.8.0.402.b06", "RELEASE": "2.el8", "ARCH": "x86_64",
			"VENDOR": "Red Hat, Inc.", "SUMMARY": "OpenJDK 8 Runtime Environment",
			"LICENSE": "ASL 2.0 and GPLv2 with exceptions", "INSTALLTIME": "1704067200",
			"MODULARITYLABEL": "(none)",
		},
		{
			"NAME": "python3.11", "EPOCH": "0", "EPOCHNUM": "0",
			"VERSION": "3.11.5", "RELEASE": "1.el9", "ARCH": "x86_64",
			"VENDOR": "Red Hat, Inc.", "SUMMARY": "Version 3.11 of the Python interpreter",
			"LICENSE": "Python-2.0", "INSTALLTIME": "1704067200",
			"MODULARITYLABEL": "(none)",
		},
		{
			"NAME": "libstdc++", "EPOCH": "0", "EPOCHNUM": "0",
			"VERSION": "14.2.1", "RELEASE": "3.el9", "ARCH": "x86_64",
			"VENDOR": "Red Hat, Inc.", "SUMMARY": "GNU Standard C++ Library",
			"LICENSE": "GPLv3+ and GPLv3+ with exceptions", "INSTALLTIME": "1704067200",
			"MODULARITYLABEL": "(none)",
		},
		{
			"NAME": "dotnet-sdk-8.0", "EPOCH": "0", "EPOCHNUM": "0",
			"VERSION": "8.0.101", "RELEASE": "1", "ARCH": "x86_64",
			"VENDOR": "Microsoft", "SUMMARY": "Microsoft .NET SDK 8.0.101",
			"LICENSE": "MIT", "INSTALLTIME": "1704067200",
			"MODULARITYLABEL": "(none)",
		},
		{
			// tilde pre-release, and a vendor whose name contains a hyphen
			"NAME": "hpsa", "EPOCH": "0", "EPOCHNUM": "0",
			"VERSION": "1.0~rc1", "RELEASE": "1.el9", "ARCH": "x86_64",
			"VENDOR": "Hewlett-Packard", "SUMMARY": "HP Smart Array driver",
			"LICENSE": "GPLv2+", "INSTALLTIME": "1704067200",
			"MODULARITYLABEL": "(none)",
		},
		{
			// caret build snapshot, noarch
			"NAME": "389-ds-base", "EPOCH": "0", "EPOCHNUM": "0",
			"VERSION": "2.4.5^20240101git", "RELEASE": "1.el9", "ARCH": "noarch",
			"VENDOR": "Fedora Project", "SUMMARY": "389 Directory Server",
			"LICENSE": "GPLv3+", "INSTALLTIME": "1704067200",
			"MODULARITYLABEL": "(none)",
		},
	}

	platforms := []*inventory.Platform{
		{Name: "redhat", Version: "8", Arch: "x86_64"}, // EPOCHNUM + modularity
		{Name: "oraclelinux", Version: "9", Arch: "x86_64"},
		{Name: "suse", Version: "15.6", Arch: "x86_64"}, // EPOCH, no modularity
	}

	for _, pf := range platforms {
		t.Run(pf.Name, func(t *testing.T) {
			mgr := &RpmPkgManager{platform: pf}
			format := mgr.queryFormat()

			var out strings.Builder
			for _, fields := range packages {
				out.WriteString(renderRpmQueryFormat(format, fields))
			}

			pkgs := ParseRpmPackages(pf, strings.NewReader(out.String()))
			require.Lenf(t, pkgs, len(packages),
				"packages were dropped by RPM_REGEX. format=%q rendered=%q", format, out.String())

			for i, fields := range packages {
				p := pkgs[i]
				assert.Equal(t, fields["NAME"], p.Name)
				assert.Equal(t, fields["ARCH"], p.Arch)
				assert.Equal(t, fields["SUMMARY"], p.Description)
				assert.Equal(t, fields["LICENSE"], p.License)

				// Assert the exact version, not just a substring: an epoch
				// that leaks in as "0:" or ":" is the kind of drift that
				// changes the purl and makes one package look like two.
				wantVersion := fields["VERSION"] + "-" + fields["RELEASE"]
				if e := normalizeRpmEpoch(fields["EPOCH"]); e != "" {
					wantVersion = e + ":" + wantVersion
				}
				assert.Equal(t, wantVersion, p.Version)
			}
		})
	}
}

// A realistic multi-package listing: every line must survive, in order.
func TestParseRpmPackages_RealisticListing(t *testing.T) {
	listing := `glibc 0:2.34-100.el8 x86_64__Red Hat, Inc.__The GNU libc libraries__LGPLv2+__1700000000__(none)
java-1.8.0-openjdk 1:1.8.0.402.b06-2.el8 x86_64__Red Hat, Inc.__OpenJDK 8__ASL 2.0__1704067200__(none)
python3.11 0:3.11.5-1.el9 x86_64__Red Hat, Inc.__Python 3.11__Python-2.0__1704067200__(none)
libstdc++ 0:14.2.1-3.el9 x86_64__Red Hat, Inc.__GNU C++ lib__GPLv3+__1704067200__(none)
dotnet-sdk-8.0 0:8.0.1-1 x86_64__Microsoft__dotnet sdk__MIT__1704067200__(none)
389-ds-base 0:2.4.5-1.el9 x86_64__Red Hat, Inc.__389 DS__GPLv3+__1704067200__(none)
`

	pkgs := ParseRpmPackages(rpmCharsetPlatform, strings.NewReader(listing))
	require.Len(t, pkgs, 6, "every package in the listing must be parsed")

	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{
		"glibc",
		"java-1.8.0-openjdk",
		"python3.11",
		"libstdc++",
		"dotnet-sdk-8.0",
		"389-ds-base",
	}, names)
}
