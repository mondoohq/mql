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

// newProbeConn builds a mock connection for a platform whose name matches no
// case in ResolveSystemPkgManagers, so resolution reaches the plain-linux
// branch and has nothing but the given filesystem entries to go on.
func newProbeConn(t *testing.T, platform *inventory.Platform, paths ...string) *mock.Connection {
	t.Helper()

	files := map[string]*mock.MockFileData{}
	for _, p := range paths {
		files[p] = &mock.MockFileData{Path: p}
	}

	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(&mock.TomlData{Files: files}))
	require.NoError(t, err)
	return conn
}

func managerNames(pms []OperatingSystemPkgManager) []string {
	names := make([]string, 0, len(pms))
	for _, pm := range pms {
		names = append(names, pm.Name())
	}
	return names
}

// The rpm database still lives under /var/lib/rpm on most rpm distros. CBL-Mariner
// 2.0 was the host that exposed the gap: it reports ID=mariner with family
// ["linux","unix","os"], so it is not in the redhat family, and before the probe
// no case named it and packages errored on a host with 69 rpms on disk. Mariner
// itself is now claimed by name, so it no longer reaches this branch and cannot
// stand in for it. The path is covered here instead, on a distro nobody has
// named, which is the case the probe exists to serve.
func TestResolveSystemPkgManagersUnknownRpmVarLibPath(t *testing.T) {
	conn := newProbeConn(t, &inventory.Platform{
		Name:   "someotherrpmdistro",
		Family: []string{"linux", "unix", "os"},
	}, "/var/lib/rpm")

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err, "an rpm database is present, so a manager must resolve")
	require.Len(t, pms, 1)
	assert.IsType(t, &RpmPkgManager{}, pms[0])
}

// Some rpm distros moved the database off /var so /var can stay mutable state.
func TestResolveSystemPkgManagersRpmSysimagePath(t *testing.T) {
	conn := newProbeConn(t, &inventory.Platform{
		Name:   "somenewrpmdistro",
		Family: []string{"linux", "unix", "os"},
	}, "/usr/lib/sysimage/rpm")

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err)
	require.Len(t, pms, 1)
	assert.IsType(t, &RpmPkgManager{}, pms[0])
}

func TestResolveSystemPkgManagersUnknownDpkg(t *testing.T) {
	conn := newProbeConn(t, &inventory.Platform{
		Name:   "somenewdebiandistro",
		Family: []string{"linux", "unix", "os"},
	}, "/var/lib/dpkg/status")

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err)
	require.Len(t, pms, 1)
	assert.IsType(t, &DebPkgManager{}, pms[0])
}

func TestResolveSystemPkgManagersUnknownApk(t *testing.T) {
	conn := newProbeConn(t, &inventory.Platform{
		Name:   "somenewapkdistro",
		Family: []string{"linux", "unix", "os"},
	}, "/lib/apk/db/installed")

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err)
	require.Len(t, pms, 1)
	assert.IsType(t, &AlpinePkgManager{}, pms[0])
}

// apk-tools 3 keeps the database under /var/lib/apk rather than /lib/apk. The
// probe checked only the /lib path, so an unrecognized distro on apk-tools 3
// resolved no package manager at all even with a populated database on disk.
func TestResolveSystemPkgManagersUnknownApkVarLib(t *testing.T) {
	conn := newProbeConn(t, &inventory.Platform{
		Name:   "somenewapk3distro",
		Family: []string{"linux", "unix", "os"},
	}, "/var/lib/apk/db/installed")

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err)
	require.Len(t, pms, 1)
	assert.IsType(t, &AlpinePkgManager{}, pms[0])
}

// The probe must stay evidence-driven: a linux platform with no package
// database on disk still resolves nothing, and still says so.
func TestResolveSystemPkgManagersUnknownLinuxNoDatabase(t *testing.T) {
	conn := newProbeConn(t, &inventory.Platform{
		Name:   "somedistrowithoutpackages",
		Family: []string{"linux", "unix", "os"},
	}, "/etc/os-release")

	_, err := ResolveSystemPkgManagers(conn)
	require.Error(t, err)
}

// The probe lives in the plain-linux branch, which a distro that already
// matched an earlier case never reaches. If it ever leaked out of that branch,
// every rpm and dpkg host would resolve a second manager and packages would
// count each package twice.
func TestResolveSystemPkgManagersNoDoubleCountOnKnownPlatforms(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		files    []string
		expected []string
	}{
		{
			name: "redhat family with an rpm database",
			platform: &inventory.Platform{
				Name:   "redhat",
				Family: []string{"redhat", "linux", "unix", "os"},
			},
			files:    []string{"/var/lib/rpm"},
			expected: []string{"Rpm Package Manager"},
		},
		{
			name: "azurelinux with an rpm database",
			platform: &inventory.Platform{
				Name:   "azurelinux",
				Family: []string{"linux", "unix", "os"},
			},
			files:    []string{"/var/lib/rpm"},
			expected: []string{"Rpm Package Manager"},
		},
		{
			name: "debian family with a dpkg status file",
			platform: &inventory.Platform{
				Name:   "debian",
				Family: []string{"debian", "linux", "unix", "os"},
			},
			files:    []string{"/var/lib/dpkg/status"},
			expected: []string{"Debian Package Manager", "Snap Package Manager"},
		},
		{
			name: "alpine with an apk database",
			platform: &inventory.Platform{
				Name:   "alpine",
				Family: []string{"linux", "unix", "os"},
			},
			files:    []string{"/lib/apk/db/installed"},
			expected: []string{"apk Package Manager"},
		},
		{
			name: "alpaquita with an apk-tools 3 database",
			platform: &inventory.Platform{
				Name:   "alpaquita",
				Family: []string{"linux", "unix", "os"},
			},
			files:    []string{"/var/lib/apk/db/installed"},
			expected: []string{"apk Package Manager"},
		},
		{
			// The hardened images ship no apk binary, but the database it wrote
			// is left behind, so the inventory still reads.
			name: "bellsoft hardened containers with an apk-tools 3 database",
			platform: &inventory.Platform{
				Name:   "bellsoft-hardened-containers",
				Family: []string{"linux", "unix", "os"},
			},
			files:    []string{"/var/lib/apk/db/installed"},
			expected: []string{"apk Package Manager"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := newProbeConn(t, test.platform, test.files...)

			pms, err := ResolveSystemPkgManagers(conn)
			require.NoError(t, err)
			assert.Equal(t, test.expected, managerNames(pms))
		})
	}
}
