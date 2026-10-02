// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package systemd

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServicePids(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	// cgroup v2 (SLES 15 SP7, SLES 16)
	require.NoError(t, afs.WriteFile("/sys/fs/cgroup/system.slice/mongod.service/cgroup.procs", []byte("21279\n"), 0o644))
	// cgroup v1, a service with a main process and a helper
	require.NoError(t, afs.WriteFile("/sys/fs/cgroup/systemd/system.slice/named.service/cgroup.procs", []byte("812\n813\n"), 0o644))
	// a stopped service keeps an empty cgroup until it is garbage collected
	require.NoError(t, afs.WriteFile("/sys/fs/cgroup/system.slice/postgresql.service/cgroup.procs", []byte(""), 0o644))

	assert.Equal(t, []string{"21279"}, ServicePids(afs, "mongod.service"))
	assert.Equal(t, []string{"812", "813"}, ServicePids(afs, "named.service"))
	assert.Nil(t, ServicePids(afs, "postgresql.service"))
	assert.Nil(t, ServicePids(afs, "mysqld.service"))
}
