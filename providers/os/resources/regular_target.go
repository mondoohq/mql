// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "os"

// isRegularTarget reports whether Stat found a regular file, following a
// symbolic link. The command-based file systems (SSH with sudo) report the
// target's mode with the symlink bit added, so that bit is ignored.
func isRegularTarget(st os.FileInfo) bool {
	return (st.Mode() &^ os.ModeSymlink).IsRegular()
}
