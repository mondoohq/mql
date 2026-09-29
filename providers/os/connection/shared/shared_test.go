// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseSudo(t *testing.T) {
	assert.Nil(t, ParseSudo(map[string]*llx.Primitive{}))
	assert.Nil(t, ParseSudo(map[string]*llx.Primitive{"sudo": llx.BoolPrimitive(false)}))

	// --sudo leaves the executable empty so the connection detects it
	sudo := ParseSudo(map[string]*llx.Primitive{"sudo": llx.BoolPrimitive(true)})
	assert.Equal(t, &inventory.Sudo{Active: true}, sudo)
}

func TestParseElevationProbe(t *testing.T) {
	tests := []struct {
		name       string
		stdout     string
		executable string
		probed     bool
	}{
		{
			// Debian 12, Ubuntu 26.04 (sudo-rs via /etc/alternatives), RHEL 9
			name:       "sudo only",
			stdout:     "/usr/bin/sudo\nmql-elevation-probe-done\n",
			executable: "sudo",
			probed:     true,
		},
		{
			// Alpine 3.21 and 3.24, stock images ship doas and no sudo
			name:       "doas only",
			stdout:     "/usr/bin/doas\nmql-elevation-probe-done\n",
			executable: "doas",
			probed:     true,
		},
		{
			// Debian 12 with the opendoas package installed next to sudo
			name:       "sudo and doas prefers sudo",
			stdout:     "/usr/bin/sudo\n/usr/bin/doas\nmql-elevation-probe-done\n",
			executable: "sudo",
			probed:     true,
		},
		{
			// Alpine 3.21, probe run with PATH=/nonexistent
			name:       "neither installed",
			stdout:     "mql-elevation-probe-done\n",
			executable: "",
			probed:     true,
		},
		{
			// no POSIX shell ran the probe
			name:       "probe did not run",
			stdout:     "",
			executable: "",
			probed:     false,
		},
		{
			name:       "unrelated executable names are ignored",
			stdout:     "/usr/local/bin/sudo-wrapper\n/opt/doas.sh\nmql-elevation-probe-done\n",
			executable: "",
			probed:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executable, probed := ParseElevationProbe(tt.stdout)
			assert.Equal(t, tt.executable, executable)
			assert.Equal(t, tt.probed, probed)
		})
	}
}

func TestBuildSudoCommand(t *testing.T) {
	tests := []struct {
		name string
		sudo *inventory.Sudo
		cmd  string
		want string
	}{
		{
			name: "no elevation",
			sudo: nil,
			cmd:  "cat /etc/shadow",
			want: "cat /etc/shadow",
		},
		{
			name: "inactive",
			sudo: &inventory.Sudo{Active: false, Executable: "sudo"},
			cmd:  "cat /etc/shadow",
			want: "cat /etc/shadow",
		},
		{
			name: "empty executable defaults to sudo",
			sudo: &inventory.Sudo{Active: true},
			cmd:  "cat /etc/shadow",
			want: "sudo cat /etc/shadow",
		},
		{
			name: "sudo",
			sudo: &inventory.Sudo{Active: true, Executable: "sudo"},
			cmd:  "cat /etc/shadow",
			want: "sudo cat /etc/shadow",
		},
		{
			name: "sudo with user",
			sudo: &inventory.Sudo{Active: true, Executable: "sudo", User: "admin"},
			cmd:  "id -u",
			want: "sudo -u admin id -u",
		},
		{
			name: "sudo with shell",
			sudo: &inventory.Sudo{Active: true, Executable: "sudo", Shell: "sh"},
			cmd:  "'id -u'",
			want: "sudo sh -c 'id -u'",
		},
		{
			name: "sudo keeps leading environment assignments",
			sudo: &inventory.Sudo{Active: true, Executable: "sudo"},
			cmd:  "DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run",
			want: "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run",
		},
		{
			name: "doas",
			sudo: &inventory.Sudo{Active: true, Executable: "doas"},
			cmd:  "cat /etc/shadow",
			want: "doas cat /etc/shadow",
		},
		{
			name: "doas with user",
			sudo: &inventory.Sudo{Active: true, Executable: "doas", User: "nobody"},
			cmd:  "id -u",
			want: "doas -u nobody id -u",
		},
		{
			name: "doas with shell",
			sudo: &inventory.Sudo{Active: true, Executable: "doas", Shell: "sh"},
			cmd:  "'id -u'",
			want: "doas sh -c 'id -u'",
		},
		{
			name: "doas runs leading environment assignments through env",
			sudo: &inventory.Sudo{Active: true, Executable: "doas"},
			cmd:  "DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run",
			want: "doas env DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run",
		},
		{
			name: "doas does not add env for an assignment later in the command",
			sudo: &inventory.Sudo{Active: true, Executable: "doas"},
			cmd:  "grep FOO=bar /etc/environment",
			want: "doas grep FOO=bar /etc/environment",
		},
		{
			name: "configured executable is used as is",
			sudo: &inventory.Sudo{Active: true, Executable: "pfexec"},
			cmd:  "cat /etc/shadow",
			want: "pfexec cat /etc/shadow",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, BuildSudoCommand(tt.sudo, tt.cmd))
		})
	}
}

func probeRunner(t *testing.T, stdout string, err error) (func(string) (*Command, error), *int) {
	calls := 0
	return func(cmd string) (*Command, error) {
		calls++
		assert.Equal(t, ElevationProbeCommand, cmd)
		return &Command{Stdout: bytes.NewBufferString(stdout), Stderr: &bytes.Buffer{}}, err
	}, &calls
}

func TestResolveElevation(t *testing.T) {
	t.Run("sudo installed", func(t *testing.T) {
		// Debian 12
		sudo := &inventory.Sudo{Active: true}
		run, calls := probeRunner(t, "/usr/bin/sudo\nmql-elevation-probe-done\n", nil)
		require.NoError(t, ResolveElevation(sudo, run))
		assert.Equal(t, "sudo", sudo.Executable)
		assert.Equal(t, 1, *calls)
	})

	t.Run("sudo and doas installed", func(t *testing.T) {
		// Debian 12 with opendoas installed
		sudo := &inventory.Sudo{Active: true}
		run, _ := probeRunner(t, "/usr/bin/sudo\n/usr/bin/doas\nmql-elevation-probe-done\n", nil)
		require.NoError(t, ResolveElevation(sudo, run))
		assert.Equal(t, "sudo", sudo.Executable)
	})

	t.Run("doas only", func(t *testing.T) {
		// Alpine 3.24
		sudo := &inventory.Sudo{Active: true}
		run, _ := probeRunner(t, "/usr/bin/doas\nmql-elevation-probe-done\n", nil)
		require.NoError(t, ResolveElevation(sudo, run))
		assert.Equal(t, "doas", sudo.Executable)
	})

	t.Run("neither installed", func(t *testing.T) {
		sudo := &inventory.Sudo{Active: true}
		run, _ := probeRunner(t, "mql-elevation-probe-done\n", nil)
		err := ResolveElevation(sudo, run)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "neither sudo nor doas")
	})

	t.Run("probe could not run falls back to sudo", func(t *testing.T) {
		sudo := &inventory.Sudo{Active: true}
		run, _ := probeRunner(t, "", nil)
		require.NoError(t, ResolveElevation(sudo, run))
		assert.Equal(t, "sudo", sudo.Executable)

		sudo = &inventory.Sudo{Active: true}
		run, _ = probeRunner(t, "", errors.New("session failed"))
		require.NoError(t, ResolveElevation(sudo, run))
		assert.Equal(t, "sudo", sudo.Executable)
	})

	t.Run("configured executable is kept without probing", func(t *testing.T) {
		sudo := &inventory.Sudo{Active: true, Executable: "sudo"}
		run, calls := probeRunner(t, "/usr/bin/doas\nmql-elevation-probe-done\n", nil)
		require.NoError(t, ResolveElevation(sudo, run))
		assert.Equal(t, "sudo", sudo.Executable)
		assert.Equal(t, 0, *calls)
	})
}
