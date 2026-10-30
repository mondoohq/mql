// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

var oracleLinux98 = &inventory.Platform{Name: "oraclelinux", Version: "9.8", Arch: "x86_64", Family: []string{"redhat", "linux", "unix", "os"}}

const (
	sysimageRpmdb = "/usr/lib/sysimage/rpm/rpmdb.sqlite"
	varlibRpmdb   = "/var/lib/rpm/rpmdb.sqlite"
)

// staticRpmManager is an rpm manager on a filesystem without an rpm binary,
// with the given rpm databases (path on the target -> testdata file).
func staticRpmManager(t *testing.T, dbs map[string]string) *RpmPkgManager {
	t.Helper()
	files := map[string]*mock.MockFileData{}
	for path, fixture := range dbs {
		files[path] = &mock.MockFileData{Path: path, Content: readManifestTestdata(t, fixture)}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: oracleLinux98}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			rpmProbeCommand: {Stderr: "sh: rpm: command not found\n", ExitStatus: 127},
		},
		Files: files,
	}))
	require.NoError(t, err)
	return &RpmPkgManager{conn: conn, platform: oracleLinux98}
}

func names(pkgs []Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name)
	}
	return out
}

// The oraclelinux:9 image (Oracle Linux 9.8, rpm 4.16) ships two rpm
// databases. rpm's own %_dbpath is /var/lib/rpm, with all 188 packages, but the
// image also carries an rpmdb.sqlite under /usr/lib/sysimage/rpm that no
// package owns and that holds no packages. The first path that existed won, so
// the inventory was empty: no packages, no error, nothing to scan.
func TestRpmStaticListSkipsAnEmptyDatabase(t *testing.T) {
	pkgs, err := staticRpmManager(t, map[string]string{
		sysimageRpmdb: "rpmdb-ol9-sysimage-empty.sqlite",
		varlibRpmdb:   "rpmdb-ol9-two-packages.sqlite",
	}).List()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"basesystem", "dbus"}, names(pkgs))
	for _, p := range pkgs {
		assert.Equal(t, []FileRecord{{Path: varlibRpmdb}}, p.Files,
			"the package must name the database it was read from")
	}
}

// An rpm database with no packages in it is a real answer when it is the only
// one: the list is empty, not an error.
func TestRpmStaticListOnlyAnEmptyDatabase(t *testing.T) {
	pkgs, err := staticRpmManager(t, map[string]string{
		sysimageRpmdb: "rpmdb-ol9-sysimage-empty.sqlite",
	}).List()
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

// When more than one database has packages, the established order still
// decides, so no distro that read correctly before reads a different database.
func TestRpmStaticListKeepsThePathOrderBetweenPopulatedDatabases(t *testing.T) {
	pkgs, err := staticRpmManager(t, map[string]string{
		sysimageRpmdb: "rpmdb-ol9-two-packages.sqlite",
		varlibRpmdb:   "rpmdb-ol9-two-packages.sqlite",
	}).List()
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)
	assert.Equal(t, []FileRecord{{Path: sysimageRpmdb}}, pkgs[0].Files)
}
