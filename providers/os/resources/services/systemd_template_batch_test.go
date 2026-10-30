// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestIsSystemdTemplateUnit(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"autovt@.service", true},
		{"getty@.service", true},
		{"user@.service", true},
		{"sshd@.service", true},
		{"getty@tty1.service", false},
		{"user@1000.service", false},
		{"sshd.service", false},
		{"dbus-broker.service", false},
		{"weird@", false},
		{"@.service", true},
		{"", false},
		{".service", false},
	} {
		assert.Equal(t, tc.want, isSystemdTemplateUnit(tc.name), "name %q", tc.name)
	}
}

func TestSplitSystemdTemplateUnits(t *testing.T) {
	concrete, templates := splitSystemdTemplateUnits([]string{
		"sshd.service", "autovt@.service", "getty@tty1.service", "user@.service",
	})
	assert.Equal(t, []string{"sshd.service", "getty@tty1.service"}, concrete)
	assert.Equal(t, []string{"autovt@.service", "user@.service"}, templates)
}

// systemctl refuses to show an uninstantiated template -- "Unit name
// autovt@.service is neither a valid invocation ID nor unit name" -- and exits
// non-zero for the whole batch when one is in it. Nearly every host has a
// template, so leaving them in the batch made every batch fail, which sent the
// whole resource to the unit-file fallback. That fallback does not look in
// /run, so it silently lost every unit a generator had produced: 10 of them on
// openSUSE Leap 16.
func TestSystemdUnitManager_TemplateDoesNotFailTheWholeBatch(t *testing.T) {
	listing := `sshd.service         enabled  enabled
autovt@.service      alias    -
home-relabel.service generated -
`
	// systemctl answers for the concrete names only
	concreteShow := buildSystemdUnitShowCommand([]string{"sshd.service", "home-relabel.service"})

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "opensuse-leap", Version: "16.0", Family: []string{"suse", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {Stdout: listing},
		concreteShow: {Stdout: `Id=sshd.service
Description=OpenSSH server daemon
LoadState=loaded
ActiveState=active
NoNewPrivileges=yes

Id=home-relabel.service
Description=Relabel /home
LoadState=loaded
ActiveState=inactive
NoNewPrivileges=no
`},
		// the batch that still contains the template is what systemctl rejects
		buildSystemdUnitShowCommand([]string{"sshd.service", "autovt@.service", "home-relabel.service"}): {
			Stderr:     "Failed to get properties: Unit name autovt@.service is neither a valid invocation ID nor unit name.\n",
			ExitStatus: 1,
		},
	}}))
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/autovt@.service", []byte(`[Unit]
Description=Getty on %I

[Service]
ExecStart=/sbin/agetty -o '-p -- \u' --noclear %I
`), 0o644))

	units, err := (&SystemdUnitManager{conn: &fsConn{Connection: conn, fs: fs}}).List()
	require.NoError(t, err)

	byName := map[string]*SystemdUnit{}
	for _, u := range units {
		byName[u.Name] = u
	}

	// the generator-produced unit survives, which is what the wholesale
	// fallback used to lose
	require.Contains(t, byName, "home-relabel.service")
	assert.Equal(t, "Relabel /home", byName["home-relabel.service"].Description)

	// the concrete units still carry systemctl's values, so the resource did
	// not quietly degrade to reading unit files for everything
	require.Contains(t, byName, "sshd.service")
	assert.Equal(t, "active", byName["sshd.service"].ActiveState)
	assert.True(t, byName["sshd.service"].NoNewPrivileges)

	// and the template is reported too, read from its unit file
	require.Contains(t, byName, "autovt@.service")
	assert.Equal(t, "Getty on %I", byName["autovt@.service"].Description)

	assert.Len(t, units, 3)
}

// A template with no unit file of its own (an alias) is skipped rather than
// failing the listing.
func TestSystemdUnitManager_TemplateWithoutUnitFileIsSkipped(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Version: "13", Family: []string{"debian", "linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
		"systemctl list-unit-files --type service --all --no-legend": {Stdout: "sshd.service enabled enabled\nsshd-unix-local@.service alias -\n"},
		buildSystemdUnitShowCommand([]string{"sshd.service"}):        {Stdout: "Id=sshd.service\nLoadState=loaded\n"},
	}}))
	require.NoError(t, err)

	var _ shared.Connection = conn
	units, err := (&SystemdUnitManager{conn: &fsConn{Connection: conn, fs: afero.NewMemMapFs()}}).List()
	require.NoError(t, err)
	require.Len(t, units, 1)
	assert.Equal(t, "sshd.service", units[0].Name)
}
