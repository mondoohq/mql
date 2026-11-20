// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package resources

import (
	"os"
	"syscall"
)

// isOSFileStat reports whether fi came from the os package, whose Sys() is
// the *syscall.Stat_t that os.SameFile compares.
func isOSFileStat(fi os.FileInfo) bool {
	_, ok := fi.Sys().(*syscall.Stat_t)
	return ok
}
