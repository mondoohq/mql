// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// linkFs is an in-memory Unix file system whose symlinks are given by a map,
// so the resolution in readUnit runs the same way on every OS.
type linkFs struct {
	afero.Fs
	links map[string]string
}

func (l linkFs) ReadlinkIfPossible(name string) (string, error) {
	if target, ok := l.links[name]; ok {
		return target, nil
	}
	return "", &os.PathError{Op: "readlink", Path: name, Err: os.ErrInvalid}
}

// A unit file can be a symlink, absolute or relative, and the target belongs
// to the scanned Unix file system. On Windows path/filepath treats
// "/lib/systemd/..." as relative and joins it onto the link's directory, so a
// scanner running on Windows could not read units linked this way.
func TestSystemdReadUnitFollowsUnixSymlinks(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/ssh.service",
		[]byte("[Unit]\nDescription=OpenBSD Secure Shell server\nWants=network.target\n"), 0o644))

	s := &SystemdFSServiceManager{Fs: linkFs{Fs: fs, links: map[string]string{
		"/etc/systemd/system/sshd.service":                        "/lib/systemd/system/ssh.service",
		"/etc/systemd/system/multi-user.target.wants/ssh.service": "../../../../lib/systemd/system/ssh.service",
	}}}

	for _, unitPath := range []string{
		"/etc/systemd/system/sshd.service",
		"/etc/systemd/system/multi-user.target.wants/ssh.service",
	} {
		t.Run(unitPath, func(t *testing.T) {
			var u unitInfo
			require.NoError(t, s.readUnit(unitPath, &u))
			assert.Equal(t, "OpenBSD Secure Shell server", u.description)
			assert.Contains(t, u.deps, "network.target")
		})
	}
}
