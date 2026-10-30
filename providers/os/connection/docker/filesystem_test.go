// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The links in /proc/<pid>/fd name the sockets a process holds; without them
// no listening port was attributed to its process over this transport.
func TestReadlinkIfPossible(t *testing.T) {
	fs := &FS{runner: &fakeContainer{}}

	target, err := fs.ReadlinkIfPossible("/proc/71/fd/6")
	require.NoError(t, err)
	assert.Equal(t, "socket:[20845]", target)

	_, err = fs.ReadlinkIfPossible("/proc/71/fd/99")
	assert.Error(t, err, "a path that is not a link")
}

// /proc, /dev and /sys are read inside the container; a path that merely
// starts with the same letters is not.
func TestIsDockerClientSupported(t *testing.T) {
	assert.False(t, isDockerClientSupported("/proc"))
	assert.False(t, isDockerClientSupported("/proc/1/cmdline"))
	assert.False(t, isDockerClientSupported("/dev/null"))
	assert.False(t, isDockerClientSupported("/sys/class/dmi/id/product_uuid"))
	assert.True(t, isDockerClientSupported("/devops/config.yaml"))
	assert.True(t, isDockerClientSupported("/system/app"))
	assert.True(t, isDockerClientSupported("/etc/os-release"))
}
