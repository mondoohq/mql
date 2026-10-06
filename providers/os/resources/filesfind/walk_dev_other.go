// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !unix

package filesfind

import "io/fs"

func deviceOf(fs.FileInfo) (uint64, bool) {
	return 0, false
}
