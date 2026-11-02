// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The rows below are the uninstall entries SQL Server registered on Windows
// Server test VMs with side-by-side instances; the expected versions are each
// instance's sqlservr.exe ProductVersion after the step. One instance
// registers two "Database Engine Services" rows (engine and resource MSI),
// both at the release's base build.
func sqlPkg(name, version string) Package {
	return Package{Name: name, Version: version, PUrl: "pkg:windows/windows/" + url.PathEscape(name) + "@" + version + "?arch=AMD64"}
}

func sqlVersions(pkgs []Package) map[string]string {
	out := map[string]string{}
	for _, p := range pkgs {
		out[p.Name] = p.Version
	}
	return out
}

func stampSql(pkgs []Package) []Package {
	return stampMsSqlPackages(pkgs, append(findMsSqlHotfixes(pkgs), findMsSqlGdrUpdates(pkgs)...))
}

func TestStampMsSqlPackages_SideBySideReleases(t *testing.T) {
	t.Run("2022 on the CU track beside 2025 on the GDR track", func(t *testing.T) {
		got := sqlVersions(stampSql([]Package{
			sqlPkg("SQL Server 2022 Database Engine Services", "16.0.1000.6"),
			sqlPkg("SQL Server 2022 Database Engine Services", "16.0.1000.6"),
			sqlPkg("Microsoft VSS Writer for SQL Server 2022", "16.0.1000.6"),
			sqlPkg("Hotfix 4295 for SQL Server 2022 (KB5104824) (64-bit)", "16.0.4295.3"),
			sqlPkg("Hotfix 4305 for SQL Server 2022 (KB5126934) (64-bit)", "16.0.4305.5"),
			sqlPkg("SQL Server 2025 Database Engine Services", "17.0.1000.7"),
			sqlPkg("SQL Server 2025 Database Engine Services", "17.0.1000.7"),
			sqlPkg("SQL Server 2025 Common Files", "17.0.1000.7"),
			sqlPkg("GDR 1145 for SQL Server 2025 (KB5128492) (64-bit)", "17.0.1145.4"),
		}))
		assert.Equal(t, "16.0.4305.5", got["SQL Server 2022 Database Engine Services"])
		assert.Equal(t, "16.0.4305.5", got["Microsoft VSS Writer for SQL Server 2022"])
		assert.Equal(t, "17.0.1145.4", got["SQL Server 2025 Database Engine Services"], "the 2025 GDR is that release's patch level")
		assert.Equal(t, "17.0.1145.4", got["SQL Server 2025 Common Files"])
		assert.Equal(t, "17.0.1145.4", got["GDR 1145 for SQL Server 2025 (KB5128492) (64-bit)"], "an update row keeps its own version")
	})

	t.Run("patched 2019 beside an unpatched 2022", func(t *testing.T) {
		got := sqlVersions(stampSql([]Package{
			sqlPkg("SQL Server 2022 Database Engine Services", "16.0.1000.6"),
			sqlPkg("SQL Server 2022 Database Engine Services", "16.0.1000.6"),
			sqlPkg("SQL Server 2022 Common Files", "16.0.1000.6"),
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("SQL Server 2019 Common Files", "15.0.2000.5"),
			sqlPkg("Hotfix 4430 for SQL Server 2019 (KB5054833) (64-bit)", "15.0.4430.1"),
			sqlPkg("Hotfix 4500 for SQL Server 2019 (KB5128494) (64-bit)", "15.0.4500.2"),
		}))
		assert.Equal(t, "15.0.4500.2", got["SQL Server 2019 Database Engine Services"])
		assert.Equal(t, "15.0.4500.2", got["SQL Server 2019 Common Files"])
		assert.Equal(t, "16.0.1000.6", got["SQL Server 2022 Database Engine Services"], "no 2022 update is installed")
		assert.Equal(t, "16.0.1000.6", got["SQL Server 2022 Common Files"])
	})

	t.Run("two instances of one release are not stamped", func(t *testing.T) {
		// A default instance at CU32+GDR (15.0.4500.2) and a named instance
		// installed afterwards at RTM (15.0.2000.5): one Hotfix row serves both.
		got := sqlVersions(stampSql([]Package{
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("Hotfix 4500 for SQL Server 2019 (KB5128494) (64-bit)", "15.0.4500.2"),
		}))
		assert.Equal(t, "15.0.2000.5", got["SQL Server 2019 Database Engine Services"], "the RTM instance must not be reported as patched")
	})

	t.Run("an update without a release in its name stamps the host's only release", func(t *testing.T) {
		got := sqlVersions(stampSql([]Package{
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("Hotfix KB5001091 SQL Server", "15.0.4123.1"),
		}))
		assert.Equal(t, "15.0.4123.1", got["SQL Server 2019 Database Engine Services"])
	})

	t.Run("an update without a release in its name is ignored with several releases", func(t *testing.T) {
		got := sqlVersions(stampSql([]Package{
			sqlPkg("SQL Server 2019 Database Engine Services", "15.0.2000.5"),
			sqlPkg("SQL Server 2022 Database Engine Services", "16.0.1000.6"),
			sqlPkg("Hotfix KB5001091 SQL Server", "15.0.4123.1"),
		}))
		assert.Equal(t, "15.0.2000.5", got["SQL Server 2019 Database Engine Services"])
		assert.Equal(t, "16.0.1000.6", got["SQL Server 2022 Database Engine Services"])
	})
}

func TestCompareMsSqlVersions(t *testing.T) {
	assert.Equal(t, 1, compareMsSqlVersions("16.0.4305.5", "9.0.5000.0"))
	assert.Equal(t, -1, compareMsSqlVersions("15.0.4430.1", "15.0.4500.2"))
	assert.Equal(t, 0, compareMsSqlVersions("17.0.1145.4", "17.0.1145.4"))
}
