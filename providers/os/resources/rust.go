// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/rust/cargolock"
	"go.mondoo.com/mql/providers/os/resources/languages/rust/cargotoml"
	"go.mondoo.com/mql/types"
)

// defaultRustPaths are searched for Cargo.lock and Cargo.toml.
// Only top-level files in these directories are scanned.
var defaultRustPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
	"/workspace",
	"/opt",
}

func initRustPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in rust.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlRustPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "rust.packages/" + r.Path.Data, nil
	}
	return "rust.packages", nil
}

type mqlRustPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlRustPackages) gatherData() error {
	if r.fetched {
		return nil
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.fetched {
		return nil
	}

	conn := r.MqlRuntime.Connection.(shared.Connection)
	fs := conn.FileSystem()
	afs := &afero.Afero{Fs: fs}

	path := r.Path.Data

	var root *languages.Package
	var directDeps []*languages.Package
	var transitiveDeps []*languages.Package
	var filePaths []string

	if path != "" {
		root, directDeps, transitiveDeps, filePaths = collectRustPackages(afs, path)
	} else {
		for _, searchPath := range defaultRustPaths {
			// Prefer Cargo.lock when available (resolved truth)
			lockMatches, _ := afero.Glob(fs, filepath.Join(searchPath, "Cargo.lock"))
			if len(lockMatches) > 0 {
				for _, match := range lockMatches {
					collectedRoot, _, t, f := collectRustPackages(afs, match)
					if root == nil {
						root = collectedRoot
					}
					transitiveDeps = append(transitiveDeps, t...)
					filePaths = append(filePaths, f...)
				}
				continue
			}

			// Fall back to Cargo.toml only if no Cargo.lock in this path
			tomlMatches, _ := afero.Glob(fs, filepath.Join(searchPath, "Cargo.toml"))
			for _, match := range tomlMatches {
				collectedRoot, d, t, f := collectRustPackages(afs, match)
				if root == nil {
					root = collectedRoot
				}
				directDeps = append(directDeps, d...)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(directDeps, languages.SortFn)
	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Set root
	if root != nil {
		mqlPkg, err := newRustPackage(r.MqlRuntime, root)
		if err != nil {
			return err
		}
		r.Root = plugin.TValue[*mqlRustPackage]{Data: mqlPkg, State: plugin.StateIsSet}
	} else {
		r.Root = plugin.TValue[*mqlRustPackage]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Set list (union of all packages, deduplicated)
	combined := make([]*languages.Package, 0, len(transitiveDeps)+len(directDeps))
	combined = append(combined, transitiveDeps...)
	combined = append(combined, directDeps...)
	allPkgs := deduplicateRustPackages(combined)
	slices.SortFunc(allPkgs, languages.SortFn)
	allResources, err := newRustPackageList(r.MqlRuntime, allPkgs)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	// Set direct dependencies
	directResources, err := newRustPackageList(r.MqlRuntime, directDeps)
	if err != nil {
		return err
	}
	r.DirectDependencies = plugin.TValue[[]any]{Data: directResources, State: plugin.StateIsSet}

	// Set files
	mqlFiles := []any{}
	for _, p := range filePaths {
		lf, err := CreateResource(r.MqlRuntime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return err
		}
		mqlFiles = append(mqlFiles, lf)
	}
	r.Files = plugin.TValue[[]any]{Data: mqlFiles, State: plugin.StateIsSet}

	r.fetched = true
	return nil
}

func collectRustPackages(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Rust path")
		return nil, nil, nil, nil
	}

	if isDir {
		return collectRustFromDir(afs, path)
	}

	if strings.HasSuffix(path, "Cargo.lock") {
		return collectFromCargoLock(afs, path)
	}
	if strings.HasSuffix(path, "Cargo.toml") {
		return collectFromCargoToml(afs, path)
	}

	return nil, nil, nil, nil
}

func collectRustFromDir(afs *afero.Afero, dir string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	// Prefer Cargo.lock when available
	lockPath := filepath.Join(dir, "Cargo.lock")
	if exists, _ := afs.Exists(lockPath); exists {
		return collectFromCargoLock(afs, lockPath)
	}

	// Fall back to Cargo.toml
	tomlPath := filepath.Join(dir, "Cargo.toml")
	if exists, _ := afs.Exists(tomlPath); exists {
		return collectFromCargoToml(afs, tomlPath)
	}

	return nil, nil, nil, nil
}

func collectFromCargoLock(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Cargo.lock")
		return nil, nil, nil, nil
	}
	defer f.Close()

	extractor := &cargolock.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Cargo.lock")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func collectFromCargoToml(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Cargo.toml")
		return nil, nil, nil, nil
	}
	defer f.Close()

	extractor := &cargotoml.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Cargo.toml")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func deduplicateRustPackages(pkgs []*languages.Package) []*languages.Package {
	seen := make(map[string]bool)
	var result []*languages.Package
	for _, pkg := range pkgs {
		key := pkg.Name + "@" + pkg.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, pkg)
	}
	return result
}

func (r *mqlRustPackages) root() (*mqlRustPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlRustPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlRustPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlRustPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newRustPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newRustPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newRustPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlRustPackage, error) {
	cpes := []any{}
	for i := range pkg.Cpes {
		cpe, err := runtime.CreateSharedResource("cpe", map[string]*llx.RawData{
			"uri": llx.StringData(pkg.Cpes[i]),
		})
		if err != nil {
			return nil, err
		}
		cpes = append(cpes, cpe)
	}

	mqlFiles := []any{}
	for i := range pkg.EvidenceList {
		evidence := pkg.EvidenceList[i]
		lf, err := CreateResource(runtime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(evidence.Value),
		})
		if err != nil {
			return nil, err
		}
		mqlFiles = append(mqlFiles, lf)
	}

	path := ""
	if len(mqlFiles) > 0 {
		if fi, ok := mqlFiles[0].(*mqlPkgFileInfo); ok {
			path = fi.Path.Data
		}
	}

	mqlPkg, err := CreateResource(runtime, "rust.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"cpes":    llx.ArrayData(cpes, types.Resource("cpe")),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlRustPackage), nil
}

func (k *mqlRustPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlRustPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlRustPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlRustPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlRustPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlRustPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlRustPackage) populateData() error {
	// rust.package instances are only created via newRustPackage, which pre-populates
	// all fields at creation time. This fallback is only reached if a rust.package is
	// resolved by ID alone without going through newRustPackage.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
