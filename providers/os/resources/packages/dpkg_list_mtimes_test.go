// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// Output of dpkgListMtimesCmd on a Debian 13 EC2 instance, filtered to a few
// packages. libc6 is Multi-Arch: same, so its list carries the architecture;
// systemd-timesyncd was removed with its configuration files kept (rc), and
// its list was rewritten at removal.
const deb13ListMtimes = `1789359780.3315391810 zlib1g:amd64.list
1789359786.0595243580 openssl.list
1789359767.0315808500 base-files.list
1789359862.7514023840 curl.list
1789359772.4835623620 libc6:amd64.list
1790573163.7118664630 systemd-timesyncd.list
`

// The matching entries of /var/lib/dpkg/status on the same host.
const deb13Status = `Package: base-files
Status: install ok installed
Architecture: amd64
Version: 13.8+deb13u7

Package: curl
Status: install ok installed
Architecture: amd64
Version: 8.14.1-2+deb13u5

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.41-12+deb13u4

Package: systemd-timesyncd
Status: deinstall ok config-files
Architecture: amd64
Version: 257.13-1~deb13u1
`

func TestParseDpkgListMtimes(t *testing.T) {
	m := ParseDpkgListMtimes(strings.NewReader(deb13ListMtimes))
	assert.Len(t, m, 6)

	// the fractional part is dropped, not rounded
	assert.Equal(t, "2026-09-14T04:24:22Z", m["curl"].Format(time.RFC3339))
	assert.Equal(t, time.UTC, m["curl"].Location())
	assert.Equal(t, "2026-09-14T04:22:52Z", m["libc6:amd64"].Format(time.RFC3339))
	_, ok := m["libc6"]
	assert.False(t, ok, "the architecture stays part of the list name")
}

func TestParseDpkgListMtimesSkipsMalformedLines(t *testing.T) {
	m := ParseDpkgListMtimes(strings.NewReader(strings.Join([]string{
		"",
		"1789359786 openssl.list",       // no fractional part, valid
		"1789359786.05 ",                // no file name
		"notanumber curl.list",          // bad time
		"0.0 zero.list",                 // no time recorded
		"1789359786.05 libc6.md5sums",   // not a file list
		"1789359786.05 .list",           // no package name
		"1789359786.05 bash.list extra", // name with a space is not a dpkg name
	}, "\n")))
	assert.Equal(t, DpkgListMtimes{"openssl": time.Unix(1789359786, 0).UTC()}, m)
}

func TestDpkgListMtimesGet(t *testing.T) {
	m := ParseDpkgListMtimes(strings.NewReader(deb13ListMtimes))

	got, ok := m.Get("libc6", "amd64")
	require.True(t, ok, "Multi-Arch: same packages are found under name:arch")
	assert.Equal(t, int64(1789359772), got.Unix())

	got, ok = m.Get("curl", "amd64")
	require.True(t, ok, "other packages fall back to the bare name")
	assert.Equal(t, int64(1789359862), got.Unix())

	_, ok = m.Get("libc6", "i386")
	assert.False(t, ok, "a foreign-architecture instance is not dated from the native one")

	_, ok = m.Get("nginx", "amd64")
	assert.False(t, ok)

	_, ok = DpkgListMtimes(nil).Get("curl", "amd64")
	assert.False(t, ok)
}

func TestDpkgStateHasCurrentFileList(t *testing.T) {
	tests := map[string]bool{
		"install ok installed":        true,
		"hold ok installed":           true,
		"install ok unpacked":         true, // iU, seen on a Debian 10 host
		"install ok half-configured":  true, // iF
		"install ok triggers-awaited": true, // it
		"install ok triggers-pending": true,
		"deinstall ok config-files":   false, // rc, seen on a Debian 13 host
		"install ok half-installed":   false,
		"purge ok not-installed":      false,
		"":                            false,
		"installed":                   false,
	}
	for status, want := range tests {
		assert.Equal(t, want, dpkgStateHasCurrentFileList(status), status)
	}
}

func TestApplyDpkgListMtimes(t *testing.T) {
	logDate := time.Date(2026, 9, 28, 5, 25, 42, 0, time.UTC)
	pkgs := []Package{
		{Name: "curl", Arch: "amd64", Status: "install ok installed"},
		{Name: "libc6", Arch: "amd64", Status: "install ok installed"},
		{Name: "systemd-timesyncd", Arch: "amd64", Status: "deinstall ok config-files"},
		{Name: "base-files", Arch: "amd64", Status: "install ok installed", InstallDate: logDate},
		{Name: "nginx", Arch: "amd64", Status: "install ok installed"},
	}
	applyDpkgListMtimes(pkgs, ParseDpkgListMtimes(strings.NewReader(deb13ListMtimes)))

	assert.Equal(t, int64(1789359862), pkgs[0].InstallDate.Unix())
	assert.Equal(t, int64(1789359772), pkgs[1].InstallDate.Unix())
	assert.True(t, pkgs[2].InstallDate.IsZero(), "a removed package's list was written by the removal")
	assert.Equal(t, logDate, pkgs[3].InstallDate, "a date from the dpkg log is kept")
	assert.True(t, pkgs[4].InstallDate.IsZero(), "no file list, no date")
}

func TestDpkgListMtimesFromFS(t *testing.T) {
	fs := afero.NewMemMapFs()
	mtime := time.Date(2025, 9, 14, 3, 44, 22, 751402384, time.UTC)
	for _, f := range []string{"curl.list", "libc6:amd64.list", "curl.md5sums"} {
		p := dpkgInfoDir + "/" + f
		require.NoError(t, afero.WriteFile(fs, p, []byte("/.\n"), 0o644))
		require.NoError(t, fs.Chtimes(p, mtime, mtime))
	}
	require.NoError(t, fs.MkdirAll(dpkgInfoDir+"/dir.list", 0o755))

	m := dpkgListMtimesFromFS(fs)
	assert.Equal(t, DpkgListMtimes{
		"curl":        mtime.Truncate(time.Second),
		"libc6:amd64": mtime.Truncate(time.Second),
	}, m)

	assert.Empty(t, dpkgListMtimesFromFS(afero.NewMemMapFs()), "no info directory, no times")
}

func TestDebPkgManagerListDatesFromFileLists(t *testing.T) {
	pf := &inventory.Platform{Name: "debian", Version: "13", Family: []string{"debian", "linux", "unix", "os"}}
	newMgr := func(t *testing.T, cmd *mock.Command) *DebPkgManager {
		data := &mock.TomlData{
			Files: map[string]*mock.MockFileData{
				"/var/lib/dpkg/status": {Content: deb13Status},
			},
			Commands: map[string]*mock.Command{},
		}
		if cmd != nil {
			data.Commands[dpkgListMtimesCmd] = cmd
		}
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(data))
		require.NoError(t, err)
		return &DebPkgManager{conn: conn, platform: pf}
	}
	dates := func(pkgs []Package) map[string]int64 {
		res := map[string]int64{}
		for _, p := range pkgs {
			if !p.InstallDate.IsZero() {
				res[p.Name] = p.InstallDate.Unix()
			}
		}
		return res
	}

	pkgs, err := newMgr(t, &mock.Command{Stdout: deb13ListMtimes}).List()
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{
		"base-files": 1789359767,
		"curl":       1789359862,
		"libc6":      1789359772,
	}, dates(pkgs))

	// find failing (for example, missing) leaves the packages undated rather
	// than erroring the list
	pkgs, err = newMgr(t, &mock.Command{ExitStatus: 1, Stderr: "find: not found"}).List()
	require.NoError(t, err)
	assert.Len(t, pkgs, 3, "systemd-timesyncd is config-files, not installed")
	assert.Empty(t, dates(pkgs))

	pkgs, err = newMgr(t, nil).List()
	require.NoError(t, err)
	assert.Empty(t, dates(pkgs))
}
