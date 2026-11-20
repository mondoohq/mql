// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package resources

import (
	"os"
	"syscall"
)

// isOSFileStat reports whether fi came from the os package, whose Sys() is
// a *syscall.Win32FileAttributeData.
func isOSFileStat(fi os.FileInfo) bool {
	_, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok
}
