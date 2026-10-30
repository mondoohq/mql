// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"
)

// A path found on a Windows target uses backslashes whatever OS mql runs on,
// while path/filepath only knows the separator of the scanning host: on macOS
// or Linux, filepath.Dir(`C:\Users\a\x.json`) is ".". These helpers split a
// target path on either separator when the target is Windows, and keep the
// path's own separators in what they return.

// targetSlashPath returns p with forward slashes.
func targetSlashPath(p string, windows bool) string {
	if windows {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return filepath.ToSlash(p)
}

// targetPathDir is filepath.Dir for a path on the target. It is meant for
// paths of files and directories below a drive root: for a bare root such as
// `C:\` it returns ".", where filepath.Dir on Windows returns `C:\`.
func targetPathDir(p string, windows bool) string {
	if !windows {
		return filepath.Dir(p)
	}
	p = strings.TrimRight(p, `\/`)
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 {
		return "."
	}
	return strings.TrimRight(p[:i], `\/`)
}

// targetPathBase is filepath.Base for a path on the target.
func targetPathBase(p string, windows bool) string {
	if !windows {
		return filepath.Base(p)
	}
	p = strings.TrimRight(p, `\/`)
	return p[strings.LastIndexAny(p, `\/`)+1:]
}
