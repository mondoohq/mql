// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

func TestManagerDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"linux", "unix"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 3, len(mounts))
}

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 41, len(mounts))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix", "freebsd"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 41, len(mounts))
}

func TestManagerFreeBSD15State(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/freebsd15.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	list, err := mm.List()
	require.NoError(t, err)
	require.Len(t, list, 56)

	byPid := map[int64]*processes.OSProcess{}
	for _, p := range list {
		byPid[p.Pid] = p
	}
	want := map[int64]string{
		0:     "D (disk sleep)",       // DLs [kernel]
		1:     "I (idle)",             // ILs /sbin/init
		2:     "W (interrupt thread)", // WL [clock]
		11:    "R (running)",          // RNL [idle]
		1198:  "S (sleeping)",         // SCs syslogd
		1470:  "I (idle)",             // Is+ getty
		43851: "R (running)",          // R ps
	}
	for pid, state := range want {
		require.Contains(t, byPid, pid)
		assert.Equal(t, state, byPid[pid].State, "pid %d", pid)
	}
	assert.Equal(t, "/bin/sh - /dev/stdin daily", byPid[43822].Command)
}

func TestManagerMacosStateUnset(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := processes.ResolveManager(conn)
	require.NoError(t, err)
	list, err := mm.List()
	require.NoError(t, err)
	require.NotEmpty(t, list)
	for _, p := range list {
		assert.Empty(t, p.State, "pid %d", p.Pid)
	}
}

// func TestManagerWindows(t *testing.T) {
//  mock, err := mock.New(0, nil, mock.WithPath("./testdata/windows.toml"))
// 	require.NoError(t, err)
// 	m, err := motor.New(mock)
// 	require.NoError(t, err)

// 	mm, err := processes.ResolveManager(m)
// 	require.NoError(t, err)
// 	mounts, err := mm.List()
// 	require.NoError(t, err)

// 	assert.Equal(t, 5, len(mounts))
// }
