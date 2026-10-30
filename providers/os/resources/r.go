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
	"go.mondoo.com/mql/providers/os/resources/languages/r/renvlock"
	"go.mondoo.com/mql/types"
)

var defaultRPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
	"/home/*",
}

func initRPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in r.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlRPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "r.packages/" + r.Path.Data, nil
	}
	return "r.packages", nil
}

type mqlRPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlRPackages) gatherData() error {
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
		t, f := collectRPackages(afs, fs, searchPath)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, sp := range defaultRPaths {
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
				t, f := collectRPackages(afs, fs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	allResources, err := newRPackageList(r.MqlRuntime, transitiveDeps)
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

func collectRPackages(afs *afero.Afero, fs afero.Fs, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check R path")
		return nil, nil
	}

	if isDir {
		renvPath := filepath.Join(path, "renv.lock")
		if exists, _ := afs.Exists(renvPath); exists {
			return collectRFromFile(afs, renvPath, &renvlock.Extractor{})
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "renv.lock") {
		return collectRFromFile(afs, path, &renvlock.Extractor{})
	}

	return nil, nil
}

func collectRFromFile(afs *afero.Afero, path string, extractor languages.Extractor) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open R file")
		return nil, nil
	}
	defer f.Close()

	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse R file")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
}

func (r *mqlRPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlRPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newRPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newRPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newRPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlRPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "r.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlRPackage), nil
}

func (k *mqlRPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlRPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlRPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlRPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlRPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlRPackage) populateData() error {
	return errors.New("r.package can only be created via r.packages")
}
