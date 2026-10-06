// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package filesfind

import (
	"io/fs"
	"syscall"
)

func deviceOf(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true //nolint:unconvert // Dev is int32 on darwin
}
