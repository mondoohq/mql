// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseAixPackages(t *testing.T) {
	f, err := os.Open("testdata/packages_aix.txt")
	require.NoError(t, err)

	pf := &inventory.Platform{
		Name:    "aix",
		Version: "7.2",
		Arch:    "powerpc",
	}

	m, err := parseAixPackages(pf, f)
	require.Nil(t, err)
	assert.Equal(t, 17, len(m), "detected the right amount of packages")

	p := Package{
		Name:        "X11.apps.msmit",
		Arch:        "powerpc",
		Version:     "7.3.0.0",
		Description: "AIXwindows msmit Application",
		PUrl:        "pkg:generic/aix/X11.apps.msmit@7.3.0.0?arch=powerpc",
		CPEs: []string{
			"cpe:2.3:a:x11.apps.msmit:x11.apps.msmit:7.3.0.0:*:*:*:*:*:powerpc:*",
		},
		Format: "bff",
		Status: "COMMITTED",
	}
	assert.Contains(t, m, p)

	p = Package{
		Name:        "bos.sysmgt.nim.client",
		Arch:        "powerpc",
		Version:     "7.3.3.0",
		Description: "Network Install Manager - Client Tools",
		PUrl:        "pkg:generic/aix/bos.sysmgt.nim.client@7.3.3.0?arch=powerpc&efix=locked",
		CPEs: []string{
			"cpe:2.3:a:bos.sysmgt.nim.client:bos.sysmgt.nim.client:7.3.3.0:*:*:*:*:*:powerpc:*",
		},
		Format: "bff",
		Status: "COMMITTED|EFIXLOCKED",
	}
	assert.Contains(t, m, p)
}

// testdata/packages_aix73.txt is `lslpp -cl` from AIX 7.3 TL4 SP2, cut to the
// rows of six filesets. Filesets with a root part are listed once per objrepos.
func TestParseAixPackagesListsEachFilesetOnce(t *testing.T) {
	f, err := os.Open("testdata/packages_aix73.txt")
	require.NoError(t, err)
	defer f.Close()

	pf := &inventory.Platform{Name: "aix", Version: "7.3", Arch: "powerpc"}
	m, err := parseAixPackages(pf, f)
	require.NoError(t, err)

	names := []string{}
	for _, p := range m {
		names = append(names, p.Name)
	}
	assert.ElementsMatch(t, []string{
		"bos.adt.base", "bos.rte", "bos.rte.security", "openssh.base.server",
		"X11.apps.msmit", "bos.terminfo.ibm.data",
	}, names)
}

func TestParseAixPackagesProblemStateOfAnyPartWins(t *testing.T) {
	out := "#Fileset:Level:PTF Id:State:Type:Description:EFIX Locked\n" +
		"/usr/lib/objrepos:bos.rte:7.3.4.2::COMMITTED:I:Base Operating System Runtime:\n" +
		"/etc/objrepos:bos.rte:7.3.4.2::BROKEN:I:Base Operating System Runtime:\n"
	pf := &inventory.Platform{Name: "aix", Version: "7.3", Arch: "powerpc"}
	m, err := parseAixPackages(pf, strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 1)
	assert.Equal(t, "BROKEN", m[0].Status)
}

func TestParseAixPackagesSkipsShortRows(t *testing.T) {
	out := "#Fileset:Level:PTF Id:State:Type:Description:EFIX Locked\n" +
		"\n" +
		"/usr/lib/objrepos:bos.rte:7.3.4.2\n" +
		"/usr/lib/objrepos:bos.mp64:7.3.4.2::COMMITTED:I:Base Operating System 64 bit Multiprocessor Runtime:\n"
	pf := &inventory.Platform{Name: "aix", Version: "7.3", Arch: "powerpc"}
	m, err := parseAixPackages(pf, strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 1)
	assert.Equal(t, "bos.mp64", m[0].Name)
	assert.Equal(t, "Base Operating System 64 bit Multiprocessor Runtime", m[0].Description)
}

// The AIX Toolbox keeps an rpm database next to the installp object
// repositories, so AIX resolves both managers when it is there.
func TestResolveSystemPkgManagersAix(t *testing.T) {
	newConn := func(files map[string]*mock.MockFileData) *mock.Connection {
		conn, err := mock.New(0, &inventory.Asset{
			Platform: &inventory.Platform{Name: "aix", Version: "7.3", Arch: "powerpc", Family: []string{"unix", "os"}},
		}, mock.WithData(&mock.TomlData{Files: files}))
		require.NoError(t, err)
		return conn
	}

	t.Run("with the AIX Toolbox", func(t *testing.T) {
		pms, err := ResolveSystemPkgManagers(newConn(map[string]*mock.MockFileData{
			"/opt/freeware/packages": {Path: "/opt/freeware/packages", StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o755}},
		}))
		require.NoError(t, err)
		require.Len(t, pms, 2)
		assert.IsType(t, &AixPkgManager{}, pms[0])
		assert.IsType(t, &RpmPkgManager{}, pms[1])
	})

	t.Run("without it", func(t *testing.T) {
		pms, err := ResolveSystemPkgManagers(newConn(map[string]*mock.MockFileData{}))
		require.NoError(t, err)
		require.Len(t, pms, 1)
		assert.IsType(t, &AixPkgManager{}, pms[0])
	})
}
