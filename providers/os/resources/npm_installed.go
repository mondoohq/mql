// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript/packagejson"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript/packagelockjson"
)

// maxNodeModulesNesting bounds the walk into node_modules/<pkg>/node_modules.
// npm hoists most packages to the top; real trees nest only a few levels.
const maxNodeModulesNesting = 32

// npmInstalledBom describes a project, or a global prefix, from what is
// installed in its node_modules: the versions npm actually put on disk, not
// the ranges a package.json declares.
type npmInstalledBom struct {
	root   *languages.Package
	direct languages.Packages
	all    languages.Packages
}

func (b *npmInstalledBom) Root() *languages.Package       { return b.root }
func (b *npmInstalledBom) Direct() languages.Packages     { return b.direct }
func (b *npmInstalledBom) Transitive() languages.Packages { return b.all }

// hasNodeModules reports whether dir has a node_modules directory.
func hasNodeModules(fs afero.Fs, dir string) bool {
	fi, err := fs.Stat(filepath.Join(dir, "node_modules"))
	return err == nil && fi.IsDir()
}

// collectInstalledNpmPackages builds the bom of a project without a lockfile
// from its package.json and the packages installed in its node_modules.
func collectInstalledNpmPackages(fs afero.Fs, manifestPath string, manifest []byte) (languages.Bom, error) {
	pj, err := (&packagejson.Extractor{}).Parse(bytes.NewReader(manifest), manifestPath)
	if err != nil {
		return nil, err
	}
	nodeModules := filepath.Join(filepath.Dir(manifestPath), "node_modules")
	bom := &npmInstalledBom{
		root: pj.Root(),
		all:  installedNodeModules(fs, nodeModules),
	}
	for _, name := range npmManifestDependencyNames(manifest) {
		if pkg := readInstalledNpmPackage(fs, filepath.Join(nodeModules, name)); pkg != nil {
			bom.direct = append(bom.direct, pkg)
		}
	}
	return bom, nil
}

// npmManifestDependencyNames returns the names in a package.json's
// `dependencies`, sorted.
func npmManifestDependencyNames(manifest []byte) []string {
	var m struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil
	}
	names := make([]string, 0, len(m.Dependencies))
	for name := range m.Dependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// installedNodeModules lists every package installed in a node_modules
// directory, nested ones included. npm 7+ keeps a record of the tree in
// node_modules/.package-lock.json; when it is there it is read, otherwise
// every package's own package.json is.
func installedNodeModules(fs afero.Fs, nodeModules string) languages.Packages {
	hidden := filepath.Join(nodeModules, ".package-lock.json")
	if data, err := afero.ReadFile(fs, hidden); err == nil {
		bom, err := (&packagelockjson.Extractor{}).Parse(bytes.NewReader(data), hidden)
		if err == nil {
			return bom.Transitive()
		}
		log.Debug().Err(err).Str("path", hidden).Msg("cannot parse hidden npm lockfile, reading node_modules instead")
	}
	return walkNodeModules(fs, nodeModules, nil, 0)
}

// walkNodeModules appends the package in every node_modules/<name> and
// node_modules/@scope/<name> directory, then descends into that package's own
// node_modules, where npm installs a version it could not hoist.
func walkNodeModules(fs afero.Fs, nodeModules string, list languages.Packages, depth int) languages.Packages {
	if depth > maxNodeModulesNesting {
		return list
	}
	for _, dir := range nodeModulesPackageDirs(fs, nodeModules) {
		if pkg := readInstalledNpmPackage(fs, dir); pkg != nil {
			list = append(list, pkg)
		}
		list = walkNodeModules(fs, filepath.Join(dir, "node_modules"), list, depth+1)
	}
	return list
}

// nodeModulesPackageDirs returns the package directories directly inside a
// node_modules directory: <name> and @scope/<name>, skipping .bin and other
// dot entries.
func nodeModulesPackageDirs(fs afero.Fs, nodeModules string) []string {
	entries, err := afero.ReadDir(fs, nodeModules)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn().Err(err).Str("path", nodeModules).Msg("cannot read node_modules, skipping")
		}
		return nil
	}
	var dirs []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasPrefix(name, "@") {
			dirs = append(dirs, filepath.Join(nodeModules, name))
			continue
		}
		scoped, err := afero.ReadDir(fs, filepath.Join(nodeModules, name))
		if err != nil {
			continue
		}
		for _, s := range scoped {
			if s.IsDir() {
				dirs = append(dirs, filepath.Join(nodeModules, name, s.Name()))
			}
		}
	}
	return dirs
}

// readInstalledNpmPackage reads the package installed in dir from its own
// package.json. It returns nil when there is none or it cannot be parsed.
func readInstalledNpmPackage(fs afero.Fs, dir string) *languages.Package {
	path := filepath.Join(dir, "package.json")
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil
	}
	bom, err := (&packagejson.Extractor{}).Parse(bytes.NewReader(data), path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("cannot parse installed npm package")
		return nil
	}
	root := bom.Root()
	if root == nil || root.Name == "" {
		return nil
	}
	return root
}
