// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package fsutil

import (
	"errors"
	"io/fs"
	"os"
)

// handleFsError checks if the error is a permission denied or non-existent file error and returns nil in such cases.
func handleFsError(err error) (bool, error) {
	if err != nil {
		// Check for denied permissions and non-existent files. This can sometimes happen, especially for procfs
		// We don't want to error out in such cases. We can safely skip over the file.
		if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrInvalid) {
			return true, nil
		}
		return true, err
	}
	return false, nil
}

func fileDeviceID(info fs.FileInfo) (uint64, bool) {
	// FileInfo's Sys data does not carry a volume serial number. A strict
	// xdev search reports unsupported rather than silently crossing volumes.
	return 0, false
}
