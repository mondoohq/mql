// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/mountedfs"
)

// readListUnitFiles parses `systemctl list-unit-files` output into unit
// name -> state.
func readListUnitFiles(t *testing.T, file string) map[string]string {
	t.Helper()
	f, err := os.Open(file)
	require.NoError(t, err)
	defer f.Close()
	res := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] == "UNIT" || strings.Contains(scanner.Text(), "unit files listed") {
			continue
		}
		res[fields[0]] = fields[1]
	}
	return res
}

// The unit-file states read from disk are the ones systemd itself reports
// for the same tree. The .list-unit-files.txt files next to each fixture are
// `systemctl --root=<fixture> list-unit-files` of systemd 252.
func TestReadSystemdUnitFilesMatchesSystemctl(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures need Unix symlinks")
	}
	for _, fixture := range []string{"systemd", "systemd-debian12-container", "systemd-states"} {
		t.Run(fixture, func(t *testing.T) {
			want := readListUnitFiles(t, filepath.Join("testdata", fixture+".list-unit-files.txt"))
			fs := mountedfs.NewMountedFs(filepath.Join("testdata", fixture))
			got := map[string]string{}
			for _, suffix := range []string{".service", ".socket", ".timer", ".target"} {
				units, err := readSystemdUnitFiles(fs, suffix)
				require.NoError(t, err)
				for _, u := range units {
					if isSystemdInstanceUnit(u.Name) {
						// list-unit-files leaves instances out
						continue
					}
					got[u.Name] = u.State
				}
			}
			assert.Equal(t, want, got)
		})
	}
}

// unitTree writes files and symlinks into a temporary root.
func unitTree(t *testing.T, files map[string]string, links map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the tree needs Unix symlinks")
	}
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	for p, target := range links {
		full := filepath.Join(root, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.Symlink(target, full))
	}
	return root
}

// testdata/systemd-states holds a unit for each rule systemd applies; their
// states are checked against systemd above. Beyond list-unit-files, the
// enabled instances are listed (`systemctl is-enabled` reports both
// enabled), with their template's file and their own description.
func TestReadSystemdUnitFilesInstances(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures need Unix symlinks")
	}
	units, err := readSystemdUnitFiles(mountedfs.NewMountedFs(filepath.Join("testdata", "systemd-states")), ".service")
	require.NoError(t, err)
	byName := map[string]*systemdUnitFile{}
	for _, u := range units {
		byName[u.Name] = u
	}

	require.Contains(t, byName, "getty@tty1.service")
	assert.Equal(t, "enabled", byName["getty@tty1.service"].State)
	assert.Equal(t, "/usr/lib/systemd/system/getty@.service", byName["getty@tty1.service"].Path)
	assert.Equal(t, "Getty on tty1", byName["getty@tty1.service"].Description)
	require.Contains(t, byName, "worker@db1.service")
	assert.Equal(t, "Worker db1 of worker", byName["worker@db1.service"].Description)

	// a template has no description until instantiated; a unit without
	// Description= reads as its name, as systemd reports it
	assert.Equal(t, "", byName["getty@.service"].Description)
	assert.Equal(t, "nodesc.service", byName["nodesc.service"].Description)
	assert.Equal(t, "real.service", byName["nickname.service"].Target)
	assert.Equal(t, "", byName["masked-here.service"].Path)
}

func TestSystemdFSServicesReportUnitFileState(t *testing.T) {
	root := unitTree(t, map[string]string{
		"lib/systemd/system/ssh.service":    "[Unit]\nDescription=OpenBSD Secure Shell server\n[Install]\nWantedBy=multi-user.target\nAlias=sshd.service\n",
		"lib/systemd/system/dbus.service":   "[Unit]\nDescription=D-Bus System Message Bus\n[Service]\nExecStart=/usr/bin/dbus-daemon\n",
		"lib/systemd/system/getty@.service": "[Unit]\nDescription=Getty on %I\n[Install]\nWantedBy=getty.target\nDefaultInstance=tty1\n",
	}, map[string]string{
		"etc/systemd/system/multi-user.target.wants/ssh.service":   "/lib/systemd/system/ssh.service",
		"etc/systemd/system/sshd.service":                          "/lib/systemd/system/ssh.service",
		"lib/systemd/system/multi-user.target.wants/dbus.service":  "../dbus.service",
		"etc/systemd/system/getty.target.wants/getty@tty1.service": "/lib/systemd/system/getty@.service",
		// a link to a unit that is not there
		"etc/systemd/system/gone.service": "/lib/systemd/system/removed.service",
	})
	s := SystemdFSServiceManager{Fs: mountedfs.NewMountedFs(root)}
	services, err := s.List()
	require.NoError(t, err)
	byName := map[string]*Service{}
	for _, svc := range services {
		byName[svc.Name] = svc
	}

	assert.Equal(t, &Service{Name: "ssh", Description: "OpenBSD Secure Shell server", State: ServiceUnknown, Type: "systemd",
		Installed: true, Enabled: true, Path: "/lib/systemd/system/ssh.service"}, byName["ssh"])
	// an alias reports the state of the unit it names, like the systemctl path
	assert.Equal(t, &Service{Name: "sshd", Description: "OpenBSD Secure Shell server", State: ServiceUnknown, Type: "systemd",
		Installed: true, Enabled: true, Path: "/lib/systemd/system/ssh.service"}, byName["sshd"])
	assert.Equal(t, &Service{Name: "dbus", Description: "D-Bus System Message Bus", State: ServiceUnknown, Type: "systemd",
		Installed: true, Static: true, Path: "/lib/systemd/system/dbus.service"}, byName["dbus"])
	require.Contains(t, byName, "getty@")
	assert.True(t, byName["getty@"].Enabled)
	assert.Equal(t, &Service{Name: "getty@tty1", Description: "Getty on tty1", State: ServiceUnknown, Type: "systemd",
		Installed: true, Enabled: true, Path: "/lib/systemd/system/getty@.service"}, byName["getty@tty1"])
	require.Contains(t, byName, "gone")
	assert.False(t, byName["gone"].Installed)

	sshd, err := s.Get("sshd")
	require.NoError(t, err)
	assert.True(t, sshd.Enabled)
}

func TestUnitDescriptionSpecifiers(t *testing.T) {
	assert.Equal(t, "Getty on tty1", unitDescription("getty@tty1.service", "Getty on %I"))
	assert.Equal(t, "File System Check on /dev/disk", unitDescription(`systemd-fsck@dev-disk.service`, "File System Check on /dev/disk"))
	assert.Equal(t, `fsck of dev-disk (dev-disk) 100%`, unitDescription(`systemd-fsck@dev-disk.service`, "fsck of %i (%I) 100%%"))
	assert.Equal(t, "a-b", unescapeSystemdName(`a\x2db`))
	assert.Equal(t, "nginx.service runs nginx", unitDescription("nginx.service", "%n runs %N"))
	assert.Equal(t, "x.service", unitDescription("x.service", ""))
}

// noLstatFs hides Lstat, like the docker-container file system: only the
// directory listing says which entries are links.
type noLstatFs struct {
	afero.Fs
	lr afero.LinkReader
}

func (f noLstatFs) ReadlinkIfPossible(name string) (string, error) {
	return f.lr.ReadlinkIfPossible(name)
}

func TestReadSystemdUnitFilesWithoutLstat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures need Unix symlinks")
	}
	mounted := mountedfs.NewMountedFs(filepath.Join("testdata", "systemd-states"))
	lr, ok := mounted.(afero.LinkReader)
	require.True(t, ok)
	fsys := noLstatFs{Fs: mounted, lr: lr}
	_, hasLstat := afero.Fs(fsys).(afero.Lstater)
	require.False(t, hasLstat)

	want := readListUnitFiles(t, filepath.Join("testdata", "systemd-states.list-unit-files.txt"))
	got := map[string]string{}
	for _, suffix := range []string{".service", ".socket", ".timer"} {
		units, err := readSystemdUnitFiles(fsys, suffix)
		require.NoError(t, err)
		for _, u := range units {
			if !isSystemdInstanceUnit(u.Name) {
				got[u.Name] = u.State
			}
		}
	}
	assert.Equal(t, want, got)
}
