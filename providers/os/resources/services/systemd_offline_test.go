// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/mountedfs"
)

const systemdNotBooted = "System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n"

// A debian:12 container with openssh-server, cron, nginx and systemd 252
// installed, where systemd is not PID 1. systemctl show needs the bus and
// prints nothing; list-unit-files reads the unit files and works.
func TestSystemDServiceManagerGetWithoutRunningSystemd(t *testing.T) {
	unitFiles, err := os.ReadFile("testdata/systemctl-list-unit-files-debian12-container.txt")
	require.NoError(t, err)

	show := func(unit string) string {
		return "systemctl show --property=Id,Names,LoadState,ActiveState,UnitFileState,Description " + unit
	}
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Version: "12", Family: []string{"debian", "linux"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			show("ssh.service"):                              {Stderr: systemdNotBooted, ExitStatus: 1},
			show("sudo.service"):                             {Stderr: systemdNotBooted, ExitStatus: 1},
			show("missing.service"):                          {Stderr: systemdNotBooted, ExitStatus: 1},
			"systemctl list-unit-files --type service --all": {Stdout: string(unitFiles)},
			"systemctl list-units --type service --all":      {Stderr: systemdNotBooted, ExitStatus: 1},
		},
	}))
	require.NoError(t, err)
	mgr := &SystemDServiceManager{conn: mockConn}

	ssh, err := mgr.Get("ssh")
	require.NoError(t, err)
	assert.True(t, ssh.Installed)
	assert.True(t, ssh.Enabled)
	assert.False(t, ssh.Running)

	sudo, err := mgr.Get("sudo")
	require.NoError(t, err)
	assert.True(t, sudo.Masked)

	_, err = mgr.Get("missing")
	require.ErrorIs(t, err, ErrServiceNotFound)
}

// The unit tree of the same container before systemd was installed: no
// default.target, so walking from it found nothing, and every service read
// as not installed.
func TestSystemdFSWithoutDefaultTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("testdata needs Unix symlinks")
	}
	s := SystemdFSServiceManager{Fs: mountedfs.NewMountedFs("testdata/systemd-debian12-container")}

	services, err := s.List()
	require.NoError(t, err)
	byName := map[string]*Service{}
	for _, svc := range services {
		byName[svc.Name] = svc
	}

	// enabled: linked from multi-user.target.wants
	for _, name := range []string{"ssh", "cron", "nginx", "rsyslog", "e2scrub_reap"} {
		require.Contains(t, byName, name)
		assert.True(t, byName[name].Installed, name)
		assert.True(t, byName[name].Enabled, name)
		assert.False(t, byName[name].Static, name)
	}
	// static: no [Install] section, not linked anywhere
	for _, name := range []string{"apt-daily", "pam_namespace", "logrotate", "fstrim"} {
		require.Contains(t, byName, name)
		assert.True(t, byName[name].Installed, name)
		assert.False(t, byName[name].Enabled, name)
		assert.True(t, byName[name].Static, name)
	}
	require.Contains(t, byName, "sudo")
	assert.True(t, byName["sudo"].Masked)
	assert.False(t, byName["sudo"].Enabled)

	// an alias is not a second service
	assert.NotContains(t, byName, "sshd")
	assert.NotContains(t, byName, "syslog")

	ssh, err := s.Get("ssh")
	require.NoError(t, err)
	assert.True(t, ssh.Enabled)
}

// ssh.service orders itself After=auditd.service and rsyslog.service is also
// reached as syslog.service. Each is one service, and rsyslog stays enabled
// whichever copy the walk saw first.
func TestSystemdFSAliasIsOneService(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("testdata needs Unix symlinks")
	}
	s := SystemdFSServiceManager{Fs: mountedfs.NewMountedFs("testdata/systemd-debian12-container")}
	for range 20 {
		services, err := s.List()
		require.NoError(t, err)
		var rsyslog []*Service
		for _, svc := range services {
			if svc.Name == "rsyslog" {
				rsyslog = append(rsyslog, svc)
			}
		}
		require.Len(t, rsyslog, 1)
		assert.True(t, rsyslog[0].Enabled)
	}
}
