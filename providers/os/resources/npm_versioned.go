// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// versionedNodeModulesPrefix starts the name of the node_modules directory a
// Fedora or RHEL 10 nodejs stream installs its global packages into, such as
// /usr/lib/node_modules_24 for nodejs24-npm. Unlike /usr/lib/node_modules, it
// is not inside a prefix directory of its own, so a search path naming it is
// the node_modules directory itself.
const versionedNodeModulesPrefix = "node_modules_"

func isVersionedNodeModulesPath(path string) bool {
	return strings.HasPrefix(filepath.Base(path), versionedNodeModulesPrefix)
}

// versionedNodeModulesPackageDirs returns the package directories, scoped
// packages included, in every directory the pattern matches. A package that
// the unversioned node_modules beside it holds as well is skipped, because the
// search of that prefix already reports it: on RHEL 10, /usr/lib/node_modules
// is a link to node_modules_22.
func versionedNodeModulesPackageDirs(fs afero.Fs, pattern string) []string {
	matches, err := afero.Glob(fs, pattern)
	if err != nil {
		log.Debug().Err(err).Str("path", pattern).Msg("could not search for versioned node_modules")
		return nil
	}

	afs := &afero.Afero{Fs: fs}
	var res []string
	add := func(dir, pkgPath string) {
		if isDir, err := afs.IsDir(pkgPath); err != nil || !isDir {
			return
		}
		if alsoInNodeModules(afs, dir, pkgPath) {
			return
		}
		res = append(res, pkgPath)
	}
	for _, dir := range matches {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			pkgPath := filepath.Join(dir, entry.Name())
			if !strings.HasPrefix(entry.Name(), "@") {
				add(dir, pkgPath)
				continue
			}
			// npm scope, see https://docs.npmjs.com/about-scopes
			scoped, err := afs.ReadDir(pkgPath)
			if err != nil {
				continue
			}
			for _, s := range scoped {
				add(dir, filepath.Join(pkgPath, s.Name()))
			}
		}
	}
	return res
}

// alsoInNodeModules reports whether the node_modules directory beside the
// versioned directory holds the same package, with an identical package.json.
// Comparing the manifests rather than reading the symlink works on every
// connection, SFTP included, which cannot read links.
func alsoInNodeModules(afs *afero.Afero, versionedDir string, pkgPath string) bool {
	rel, err := filepath.Rel(versionedDir, pkgPath)
	if err != nil {
		return false
	}
	own, err := afs.ReadFile(filepath.Join(pkgPath, "package.json"))
	if err != nil || len(own) == 0 {
		return false
	}
	other, err := afs.ReadFile(filepath.Join(filepath.Dir(versionedDir), "node_modules", rel, "package.json"))
	if err != nil {
		return false
	}
	return bytes.Equal(own, other)
}
