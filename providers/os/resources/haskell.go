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
	"go.mondoo.com/mql/providers/os/resources/languages/haskell/cabalfreeze"
	"go.mondoo.com/mql/providers/os/resources/languages/haskell/stacklock"
	"go.mondoo.com/mql/types"
)

var defaultHaskellPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initHaskellPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in haskell.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlHaskellPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "haskell.packages/" + r.Path.Data, nil
	}
	return "haskell.packages", nil
}

type mqlHaskellPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlHaskellPackages) gatherData() error {
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

	var transitiveDeps []*languages.Package
	var filePaths []string

	if path != "" {
		t, f := collectHaskellPackages(afs, fs, path)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, searchPath := range defaultHaskellPaths {
			matches, err := afero.Glob(fs, searchPath)
			if err != nil {
				continue
			}
			if len(matches) == 0 {
				if strings.ContainsAny(searchPath, "*?[") {
					continue
				}
				// Non-glob literal path — try it directly (afs.IsDir will bail if missing)
				matches = []string{searchPath}
			}
			for _, match := range matches {
				t, f := collectHaskellPackages(afs, fs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Set list
	allResources, err := newHaskellPackageList(r.MqlRuntime, transitiveDeps)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

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

func collectHaskellPackages(afs *afero.Afero, fs afero.Fs, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Haskell path")
		return nil, nil
	}

	if isDir {
		// Prefer stack.yaml.lock over cabal.project.freeze when both exist,
		// since Stack lock files have richer metadata (pantry tree hashes).
		stackPath := filepath.Join(path, "stack.yaml.lock")
		if exists, _ := afs.Exists(stackPath); exists {
			return collectFromFile(afs, stackPath, &stacklock.Extractor{})
		}
		// Fall back to cabal.project.freeze
		cabalPath := filepath.Join(path, "cabal.project.freeze")
		if exists, _ := afs.Exists(cabalPath); exists {
			return collectFromFile(afs, cabalPath, &cabalfreeze.Extractor{})
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "stack.yaml.lock") {
		return collectFromFile(afs, path, &stacklock.Extractor{})
	}
	if strings.HasSuffix(path, "cabal.project.freeze") {
		return collectFromFile(afs, path, &cabalfreeze.Extractor{})
	}

	return nil, nil
}

func collectFromFile(afs *afero.Afero, path string, extractor languages.Extractor) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Haskell file")
		return nil, nil
	}
	defer f.Close()

	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Haskell file")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
}

func (r *mqlHaskellPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlHaskellPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newHaskellPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newHaskellPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newHaskellPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlHaskellPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "haskell.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlHaskellPackage), nil
}

func (k *mqlHaskellPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlHaskellPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlHaskellPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlHaskellPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlHaskellPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlHaskellPackage) populateData() error {
	return errors.New("haskell.package can only be created via haskell.packages")
}
