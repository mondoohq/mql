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
	"go.mondoo.com/mql/providers/os/resources/languages/conda"
	"go.mondoo.com/mql/types"
)

var defaultCondaPaths = []string{
	"/opt/conda",
	"/home/*/miniconda3",
	"/home/*/anaconda3",
	"/root/miniconda3",
	"/root/anaconda3",
	"/app",
	"/usr/src/app",
}

func initCondaPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in conda.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlCondaPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "conda.packages/" + r.Path.Data, nil
	}
	return "conda.packages", nil
}

type mqlCondaPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlCondaPackages) gatherData() error {
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
		t, f := collectCondaPackages(afs, searchPath)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, sp := range defaultCondaPaths {
			matches, err := afero.Glob(fs, sp)
			if err != nil {
				continue
			}
			if len(matches) == 0 {
				continue
			}
			for _, match := range matches {
				t, f := collectCondaPackages(afs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	allResources, err := newCondaPackageList(r.MqlRuntime, transitiveDeps)
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

func collectCondaPackages(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		return nil, nil
	}

	if isDir {
		// Check for conda-meta directory
		condaMetaPath := filepath.Join(path, "conda-meta")
		pkgs, fps := conda.ParseCondaMeta(afs, condaMetaPath)
		if len(pkgs) > 0 {
			return pkgs, fps
		}

		// Check for environment.yml
		envPath := filepath.Join(path, "environment.yml")
		if exists, _ := afs.Exists(envPath); exists {
			return collectCondaFromFile(afs, envPath)
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "environment.yml") {
		return collectCondaFromFile(afs, path)
	}

	return nil, nil
}

func collectCondaFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Conda file")
		return nil, nil
	}
	defer f.Close()

	extractor := &conda.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Conda file")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
}

func (r *mqlCondaPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlCondaPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newCondaPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newCondaPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newCondaPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlCondaPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "conda.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlCondaPackage), nil
}

func (k *mqlCondaPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlCondaPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlCondaPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlCondaPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlCondaPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlCondaPackage) populateData() error {
	return errors.New("conda.package can only be created via conda.packages")
}
