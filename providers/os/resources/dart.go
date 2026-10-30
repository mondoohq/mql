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
	"go.mondoo.com/mql/providers/os/resources/languages/dart/pubspeclock"
	"go.mondoo.com/mql/types"
)

var defaultDartPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initDartPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in dart.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlDartPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "dart.packages/" + r.Path.Data, nil
	}
	return "dart.packages", nil
}

type mqlDartPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlDartPackages) gatherData() error {
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

	var directDeps []*languages.Package
	var transitiveDeps []*languages.Package
	var filePaths []string

	if path != "" {
		_, d, t, f := collectDartPackages(afs, fs, path)
		directDeps = append(directDeps, d...)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, searchPath := range defaultDartPaths {
			matches, err := afero.Glob(fs, searchPath)
			if err != nil {
				continue
			}
			if len(matches) == 0 {
				if strings.ContainsAny(searchPath, "*?[") {
					continue
				}
				matches = []string{searchPath}
			}
			for _, match := range matches {
				_, d, t, f := collectDartPackages(afs, fs, match)
				directDeps = append(directDeps, d...)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(directDeps, languages.SortFn)
	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Root is nil for pubspec.lock
	r.Root = plugin.TValue[*mqlDartPackage]{State: plugin.StateIsSet | plugin.StateIsNull}

	// Set list
	allResources, err := newDartPackageList(r.MqlRuntime, transitiveDeps)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	// Set direct
	directResources, err := newDartPackageList(r.MqlRuntime, directDeps)
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

func collectDartPackages(afs *afero.Afero, fs afero.Fs, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Dart path")
		return nil, nil, nil, nil
	}

	if isDir {
		lockPath := filepath.Join(path, "pubspec.lock")
		if exists, _ := afs.Exists(lockPath); exists {
			return collectFromPubspecLock(afs, lockPath)
		}
		return nil, nil, nil, nil
	}

	if strings.HasSuffix(path, "pubspec.lock") {
		return collectFromPubspecLock(afs, path)
	}

	return nil, nil, nil, nil
}

func collectFromPubspecLock(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open pubspec.lock")
		return nil, nil, nil, nil
	}
	defer f.Close()

	extractor := &pubspeclock.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse pubspec.lock")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func (r *mqlDartPackages) root() (*mqlDartPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlDartPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlDartPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlDartPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newDartPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newDartPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newDartPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlDartPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "dart.package", map[string]*llx.RawData{
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
	return mqlPkg.(*mqlDartPackage), nil
}

func (k *mqlDartPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlDartPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlDartPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlDartPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlDartPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlDartPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlDartPackage) populateData() error {
	return errors.New("dart.package can only be created via dart.packages")
}
