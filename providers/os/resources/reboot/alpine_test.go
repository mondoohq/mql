// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestAlpineKernelPackage(t *testing.T) {
	tests := []struct {
		release string
		name    string
		version string
		ok      bool
	}{
		// Alpine 3.21 and 3.22 EC2 instances
		{"6.12.110-0-virt", "linux-virt", "6.12.110-r0", true},
		// Alpine 3.23 and 3.24 EC2 instances
		{"6.18.53-0-virt", "linux-virt", "6.18.53-r0", true},
		{"6.12.47-1-lts", "linux-lts", "6.12.47-r1", true},
		{"6.17.0-0-edge", "linux-edge", "6.17.0-r0", true},
		{"6.12.47-0-rpi", "linux-rpi", "6.12.47-r0", true},
		// Docker Desktop's kernel, as seen from an Alpine container
		{"6.10.14-linuxkit", "", "", false},
		{"6.8.0", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.release, func(t *testing.T) {
			name, version, ok := alpineKernelPackage(tc.release)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.name, name)
			assert.Equal(t, tc.version, version)
		})
	}
}

func alpineConn(t *testing.T, opt mock.Option) *mock.Connection {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "alpine",
			Version: "3.22.6",
			Family:  []string{"linux", "unix", "os"},
		},
	}, opt)
	require.NoError(t, err)
	return conn
}

func TestRebootOnAlpineKernelUpgraded(t *testing.T) {
	path, err := filepath.Abs("./testdata/alpine_kernel_upgraded.toml")
	require.NoError(t, err)

	rb, err := New(alpineConn(t, mock.WithPath(path)))
	require.NoError(t, err)
	pending, err := rb.RebootPending()
	require.NoError(t, err)
	assert.True(t, pending)
}

func TestRebootOnAlpineKernelCurrent(t *testing.T) {
	// Alpine 3.24 EC2 instance: linux-virt-6.18.53-r0 installed and running
	conn := alpineConn(t, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"uname -r": {Stdout: "6.18.53-0-virt\n"},
		},
		Files: map[string]*mock.MockFileData{
			"/lib/apk/db/installed": {Content: "P:linux-virt\nV:6.18.53-r0\nA:x86_64\n"},
		},
	}))

	pending, err := (&AlpineReboot{conn: conn}).RebootPending()
	require.NoError(t, err)
	assert.False(t, pending)
}

// In a container on an Ubuntu EC2 host uname -r is the host's kernel, which
// has the shape of an Alpine release but no linux-aws package is
// installed, so there is nothing waiting to boot.
func TestRebootOnAlpineContainer(t *testing.T) {
	conn := alpineConn(t, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"uname -r": {Stdout: "6.8.0-1024-aws\n"},
		},
		Files: map[string]*mock.MockFileData{
			"/lib/apk/db/installed": {Content: "P:musl\nV:1.2.5-r10\nA:x86_64\n"},
		},
	}))

	pending, err := (&AlpineReboot{conn: conn}).RebootPending()
	require.NoError(t, err)
	assert.False(t, pending)
}
