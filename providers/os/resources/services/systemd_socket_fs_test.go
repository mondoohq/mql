// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/mountedfs"
)

func TestSystemdFSSocketManagerList(t *testing.T) {
	mgr := &SystemdFSSocketManager{
		Fs: mountedfs.NewMountedFs("testdata/systemd"),
	}

	sockets, err := mgr.List()
	require.NoError(t, err)

	socketMap := map[string]*SystemdSocket{}
	for _, s := range sockets {
		socketMap[s.Name] = s
	}

	// implicit-socket.socket exists in testdata
	require.Contains(t, socketMap, "implicit-socket")
	assert.Equal(t, "Implicit Socket", socketMap["implicit-socket"].Description)
	assert.True(t, socketMap["implicit-socket"].Installed)
	assert.True(t, socketMap["implicit-socket"].Static) // no [Install] section
	assert.False(t, socketMap["implicit-socket"].Running)

	// explicit-socket.socket exists in testdata
	require.Contains(t, socketMap, "explicit-socket")
	assert.Equal(t, "Explicit Socket", socketMap["explicit-socket"].Description)
	assert.True(t, socketMap["explicit-socket"].Installed)

	// multi-listen.socket
	require.Contains(t, socketMap, "multi-listen")
	assert.Equal(t, "Multi-listen socket", socketMap["multi-listen"].Description)
	assert.True(t, socketMap["multi-listen"].Installed)
	assert.False(t, socketMap["multi-listen"].Static) // has [Install]
}

func TestSystemdFSSocketManagerGet(t *testing.T) {
	mgr := &SystemdFSSocketManager{
		Fs: mountedfs.NewMountedFs("testdata/systemd"),
	}

	socket, err := mgr.Get("implicit-socket")
	require.NoError(t, err)
	assert.Equal(t, "implicit-socket", socket.Name)
	assert.Equal(t, "Implicit Socket", socket.Description)
}

func TestSystemdFSSocketManagerGetNotFound(t *testing.T) {
	mgr := &SystemdFSSocketManager{
		Fs: mountedfs.NewMountedFs("testdata/systemd"),
	}

	socket, err := mgr.Get("nonexistent")
	require.Nil(t, socket)
	require.ErrorIs(t, err, ErrServiceNotFound)
}

func TestSystemdFSSocketManagerShowProperties(t *testing.T) {
	mgr := &SystemdFSSocketManager{
		Fs: mountedfs.NewMountedFs("testdata/systemd"),
	}

	t.Run("socket with explicit Service", func(t *testing.T) {
		props, err := mgr.ShowSocketProperties("explicit-socket")
		require.NoError(t, err)
		assert.Equal(t, "/run/explicit/socket", props["Listen"])
		assert.Equal(t, "explicit-socket-service.service", props["Triggers"])
	})

	t.Run("socket with implicit Service", func(t *testing.T) {
		props, err := mgr.ShowSocketProperties("implicit-socket")
		require.NoError(t, err)
		assert.Equal(t, "/run/implicit/socket", props["Listen"])
		// No explicit Service= in the file, defaults to <name>.service
		assert.Equal(t, "implicit-socket.service", props["Triggers"])
	})

	t.Run("multi-listen socket", func(t *testing.T) {
		props, err := mgr.ShowSocketProperties("multi-listen")
		require.NoError(t, err)
		// Multiple ListenStream entries joined with newline
		assert.Equal(t, "/run/multi/a.sock\n/run/multi/b.sock", props["Listen"])
		assert.Equal(t, "yes", props["Accept"])

		// Verify ParseListenProperty works with the FS output
		addrs := ParseListenProperty(props["Listen"])
		assert.Equal(t, []string{"/run/multi/a.sock", "/run/multi/b.sock"}, addrs)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := mgr.ShowSocketProperties("nonexistent")
		require.ErrorIs(t, err, ErrServiceNotFound)
	})
}
