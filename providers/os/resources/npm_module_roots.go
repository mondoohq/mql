// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
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

// isNodeModuleRootPath reports whether a search path is a directory whose
// children are packages, rather than a project or a prefix that holds a
// node_modules directory:
//   - a node_modules directory, including Fedora's versioned node_modules_<major>
//   - Debian's module directories for packaged modules (node-*, npm):
//     /usr/share/nodejs (Debian 11+), /usr/lib/nodejs (Debian 9-11) and
//     /usr/lib/<multiarch triplet>/nodejs
func isNodeModuleRootPath(p string) bool {
	p = path.Clean(filepath.ToSlash(p))
	base := path.Base(p)
	if base == "node_modules" || strings.HasPrefix(base, versionedNodeModulesPrefix) {
		return true
	}
	if base != "nodejs" {
		return false
	}
	dir := path.Dir(p)
	return dir == "/usr/share" || dir == "/usr/lib" || path.Dir(dir) == "/usr/lib"
}

// nodeModuleRootPackage is the package.json of one package in a module root.
type nodeModuleRootPackage struct {
	manifestPath string
	manifest     []byte
}

// nodeModuleRootPackages reads the package.json of every package, scoped
// packages included, in every directory the pattern matches. A package in a
// module root is installed, so its package.json describes it; a lockfile
// shipped beside it is the upstream project's development state.
//
// Each manifest is read once, which keeps a scan of Debian's /usr/share/nodejs
// (over 1,500 packages on Debian 12) affordable over SFTP. Two kinds of
// entries are skipped because another entry already reports the package:
//   - a package that the unversioned node_modules beside a versioned one holds
//     as well: on RHEL 10, /usr/lib/node_modules is a link to node_modules_22
//   - an alias of a sibling: Debian links gyp to node-gyp and lodash-es's
//     package.json to lodash's
func nodeModuleRootPackages(fs afero.Fs, pattern string) []nodeModuleRootPackage {
	matches, err := afero.Glob(fs, pattern)
	if err != nil {
		log.Debug().Err(err).Str("path", pattern).Msg("could not search for node module directories")
		return nil
	}

	afs := &afero.Afero{Fs: fs}
	var res []nodeModuleRootPackage
	add := func(dir string, entry os.FileInfo, pkgPath string) {
		// a link to a package directory is not a directory entry itself
		if !entry.IsDir() {
			if isDir, err := afs.IsDir(pkgPath); err != nil || !isDir {
				return
			}
		}
		manifestPath := filepath.Join(pkgPath, "package.json")
		manifest, err := afs.ReadFile(manifestPath)
		if err != nil || len(manifest) == 0 {
			return
		}
		if alsoInNodeModules(afs, dir, pkgPath, manifest) || aliasOfSibling(afs, dir, pkgPath, manifest) {
			return
		}
		res = append(res, nodeModuleRootPackage{manifestPath: manifestPath, manifest: manifest})
	}
	for _, dir := range matches {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			pkgPath := filepath.Join(dir, entry.Name())
			if !strings.HasPrefix(entry.Name(), "@") {
				add(dir, entry, pkgPath)
				continue
			}
			// npm scope, see https://docs.npmjs.com/about-scopes
			scoped, err := afs.ReadDir(pkgPath)
			if err != nil {
				continue
			}
			for _, s := range scoped {
				add(dir, s, filepath.Join(pkgPath, s.Name()))
			}
		}
	}
	return res
}

// alsoInNodeModules reports whether the node_modules directory beside a
// versioned node_modules_<major> directory holds the same package, with an
// identical package.json. Comparing the manifests rather than reading the
// symlink works on every connection, SFTP included, which cannot read links.
func alsoInNodeModules(afs *afero.Afero, moduleRoot string, pkgPath string, manifest []byte) bool {
	if !strings.HasPrefix(filepath.Base(moduleRoot), versionedNodeModulesPrefix) {
		return false
	}
	rel, err := filepath.Rel(moduleRoot, pkgPath)
	if err != nil {
		return false
	}
	other, err := afs.ReadFile(filepath.Join(filepath.Dir(moduleRoot), "node_modules", rel, "package.json"))
	if err != nil {
		return false
	}
	return bytes.Equal(manifest, other)
}

// aliasOfSibling reports whether a package directory holds the package of a
// sibling directory under another name: its package.json names a different
// package, and the directory of that name in the same module root has an
// identical package.json.
func aliasOfSibling(afs *afero.Afero, moduleRoot string, pkgPath string, manifest []byte) bool {
	rel, err := filepath.Rel(moduleRoot, pkgPath)
	if err != nil {
		return false
	}
	var m struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return false
	}
	if m.Name == "" || m.Name == filepath.ToSlash(rel) || strings.Contains(m.Name, "..") {
		return false
	}
	other, err := afs.ReadFile(filepath.Join(moduleRoot, filepath.FromSlash(m.Name), "package.json"))
	if err != nil {
		return false
	}
	return bytes.Equal(manifest, other)
}
