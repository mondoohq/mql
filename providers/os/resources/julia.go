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
	"go.mondoo.com/mql/providers/os/resources/languages/julia/manifest"
	"go.mondoo.com/mql/types"
)

var defaultJuliaPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
	"/home/*/.julia/environments/v*",
}

func initJuliaPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in julia.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlJuliaPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "julia.packages/" + r.Path.Data, nil
	}
	return "julia.packages", nil
}

type mqlJuliaPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlJuliaPackages) gatherData() error {
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

	searchPath := r.Path.Data

	var transitiveDeps []*languages.Package
	var filePaths []string

	if searchPath != "" {
		t, f := collectJuliaPackages(afs, fs, searchPath)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, sp := range defaultJuliaPaths {
			matches, err := afero.Glob(fs, sp)
			if err != nil {
				continue
			}
			if len(matches) == 0 {
				if strings.ContainsAny(sp, "*?[") {
					continue
				}
				matches = []string{sp}
			}
			for _, match := range matches {
				t, f := collectJuliaPackages(afs, fs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	allResources, err := newJuliaPackageList(r.MqlRuntime, transitiveDeps)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

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

func collectJuliaPackages(afs *afero.Afero, fs afero.Fs, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Julia path")
		return nil, nil
	}

	if isDir {
		manifestPath := filepath.Join(path, "Manifest.toml")
		if exists, _ := afs.Exists(manifestPath); exists {
			return collectJuliaFromFile(afs, manifestPath)
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "Manifest.toml") {
		return collectJuliaFromFile(afs, path)
	}

	return nil, nil
}

func collectJuliaFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Julia Manifest.toml")
		return nil, nil
	}
	defer f.Close()

	extractor := &manifest.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Julia Manifest.toml")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
}

func (r *mqlJuliaPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlJuliaPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newJuliaPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newJuliaPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newJuliaPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlJuliaPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "julia.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlJuliaPackage), nil
}

func (k *mqlJuliaPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlJuliaPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlJuliaPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlJuliaPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlJuliaPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlJuliaPackage) populateData() error {
	return errors.New("julia.package can only be created via julia.packages")
}
