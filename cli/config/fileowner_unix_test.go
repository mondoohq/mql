// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package config

import (
	"io/fs"
	"syscall"
	"testing"
)

// ownerOf returns the uid and gid of a file, or -1s where the platform has none.
func ownerOf(t *testing.T, info fs.FileInfo) (int, int) {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(stat.Uid), int(stat.Gid)
}
