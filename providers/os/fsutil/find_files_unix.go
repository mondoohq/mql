// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build linux || darwin || netbsd || openbsd || freebsd

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// handleFsError checks if the error is a permission denied or non-existent file error and returns nil in such cases. the bool
// indicates if the file should be skipped
func handleFsError(err error) (bool, error) {
	if err != nil {
		// Check for denied permissions and non-existent files. This can sometimes happen, especially for procfs
		// We don't want to error out in such cases. We can safely skip over the file.
		if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrInvalid) || errors.Is(err, unix.EINVAL) {
			return true, nil
		}
		return true, err
	}
	return false, nil
}

func fileDeviceID(info fs.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	} // in-memory/archive filesystems have no host mounts
	return uint64(stat.Dev), true
}
