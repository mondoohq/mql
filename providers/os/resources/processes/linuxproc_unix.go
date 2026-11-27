// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package processes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
)

// procSocketInods reads all connected sockets for a process using the
// connection's filesystem abstraction, resolving each fd link with
// afero.LinkReader (ReadlinkIfPossible). That is a syscall per fd locally; on
// a connection whose filesystem reads /proc with commands it would be a
// command per fd, so ListSocketInodesByProcess uses socketInodesDumpCommand
// there instead.
func (lpm *LinuxProcManager) procSocketInods(_ int64, procPidPath string) ([]int64, error) {
	connFs := lpm.conn.FileSystem()
	fdDirPath := filepath.Join(procPidPath, "fd")

	fdDir, err := connFs.Open(fdDirPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fs.ErrPermission
		}
		return nil, err
	}
	defer fdDir.Close()

	fds, err := fdDir.Readdirnames(-1)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fs.ErrPermission
		}
		return nil, err
	}

	lr, ok := connFs.(afero.LinkReader)
	if !ok {
		return nil, errors.New("filesystem does not support readlink")
	}

	var res []int64
	for i := range fds {
		fdPath := filepath.Join(fdDirPath, fds[i])

		link, err := lr.ReadlinkIfPossible(fdPath)
		if err != nil {
			continue
		}

		inode, err := ParseSocketInode(link)
		if err != nil || inode < 0 {
			continue
		}

		res = append(res, inode)
	}

	return res, nil
}
