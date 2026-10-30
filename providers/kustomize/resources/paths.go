// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"
)

// resolveContainedPath resolves rel against baseDir and returns the path to
// read, refusing anything that lands outside baseDir. It is shared by every
// place a kustomization names a sibling file to read (patches, replacements),
// so a malicious or mistaken reference such as "../../etc/passwd" — or a
// symlink inside the directory whose target escapes it — can't reach past the
// scan root.
//
// Both the base and the candidate are symlink-resolved before the containment
// check so a symlinked scan root (e.g. /tmp on macOS, which resolves to
// /private/tmp) doesn't cause false rejections. When symlink resolution fails
// for any reason other than a resolvable escape — a broken or unresolvable
// component in baseDir itself, or a candidate that simply doesn't exist yet —
// it falls back to a lexical containment check so a perfectly readable file
// isn't silently dropped.
func resolveContainedPath(baseDir, rel string) (string, bool) {
	full := filepath.Join(baseDir, rel)
	base, target := filepath.Clean(baseDir), filepath.Clean(full)
	if rb, err := filepath.EvalSymlinks(baseDir); err == nil {
		if rt, err := filepath.EvalSymlinks(full); err == nil {
			base, target = rb, rt
		}
	}

	relPath, err := filepath.Rel(base, target)
	if err != nil {
		return "", false
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}
