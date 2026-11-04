// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestBuildHostNamespacesCommand(t *testing.T) {
	sudo := &inventory.Sudo{Active: true, Executable: "sudo"}
	tests := []struct {
		name string
		sudo *inventory.Sudo
		cmd  string
		want string
	}{
		{
			name: "argv as root",
			sudo: nil,
			cmd:  "cat /proc/cmdline",
			want: "nsenter -t 1 -a -- cat /proc/cmdline",
		},
		{
			name: "argv with sudo",
			sudo: sudo,
			cmd:  "cat /proc/cmdline",
			want: "sudo nsenter -t 1 -a -- cat /proc/cmdline",
		},
		{
			name: "inactive elevation is not used",
			sudo: &inventory.Sudo{Active: false, Executable: "sudo"},
			cmd:  "id -u",
			want: "nsenter -t 1 -a -- id -u",
		},
		{
			name: "empty executable defaults to sudo",
			sudo: &inventory.Sudo{Active: true},
			cmd:  "id -u",
			want: "sudo nsenter -t 1 -a -- id -u",
		},
		{
			name: "elevation user",
			sudo: &inventory.Sudo{Active: true, Executable: "doas", User: "root"},
			cmd:  "id -u",
			want: "doas -u root nsenter -t 1 -a -- id -u",
		},
		{
			name: "elevation shell is not used",
			sudo: &inventory.Sudo{Active: true, Executable: "sudo", Shell: "sh"},
			cmd:  "id -u",
			want: "sudo nsenter -t 1 -a -- id -u",
		},
		{
			name: "command line runs in the given shell",
			sudo: sudo,
			cmd:  "stat -L /etc/passwd 2>/dev/null || echo missing",
			want: "sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'stat -L /etc/passwd 2>/dev/null || echo missing'",
		},
		{
			name: "single quotes in a command line",
			sudo: sudo,
			cmd:  "echo 'a' | cat",
			want: "sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'echo '\"'\"'a'\"'\"' | cat'",
		},
		{
			name: "environment assignment runs in the shell",
			sudo: sudo,
			cmd:  "LANG=C systemctl status chronyd",
			want: "sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'LANG=C systemctl status chronyd'",
		},
		{
			name: "a shell started as an argv is the given shell",
			sudo: sudo,
			cmd:  `sh -c 'test -e "$1" || exit 1; stat -L "$1"' - /etc/passwd`,
			want: `sudo nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'test -e "$1" || exit 1; stat -L "$1"' - /etc/passwd`,
		},
		{
			name: "a shell by path",
			sudo: nil,
			cmd:  "/bin/bash -c 'id'",
			want: "nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'id'",
		},
		{
			name: "a program whose name starts like a shell is not a shell",
			sudo: nil,
			cmd:  "shasum /etc/passwd",
			want: "nsenter -t 1 -a -- shasum /etc/passwd",
		},
		{
			name: "reserved word runs in the shell",
			sudo: nil,
			cmd:  "if true; then id; fi",
			want: "nsenter -t 1 -a -- /proc/$$/root/opt/bin/bash -c 'if true; then id; fi'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, BuildHostNamespacesCommand(tt.sudo, "/opt/bin/bash", tt.cmd))
		})
	}
}
