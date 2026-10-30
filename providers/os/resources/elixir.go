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
	"go.mondoo.com/mql/providers/os/resources/languages/elixir/mixlock"
	"go.mondoo.com/mql/types"
)

var defaultElixirPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initElixirPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if _, ok := x.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'path' in elixir.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlElixirPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "elixir.packages/" + r.Path.Data, nil
	}
	return "elixir.packages", nil
}

type mqlElixirPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlElixirPackages) gatherData() error {
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
		t, f := collectElixirPackages(afs, fs, path)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, searchPath := range defaultElixirPaths {
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
				t, f := collectElixirPackages(afs, fs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	allResources, err := newElixirPackageList(r.MqlRuntime, transitiveDeps)
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

func collectElixirPackages(afs *afero.Afero, _ afero.Fs, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Elixir path")
		return nil, nil
	}

	if isDir {
		lockPath := filepath.Join(path, "mix.lock")
		if exists, _ := afs.Exists(lockPath); exists {
			return collectFromElixirFile(afs, lockPath)
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "mix.lock") {
		return collectFromElixirFile(afs, path)
	}
	return nil, nil
}

func collectFromElixirFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open mix.lock")
		return nil, nil
	}
	defer f.Close()

	extractor := &mixlock.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse mix.lock")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
}

func (r *mqlElixirPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlElixirPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newElixirPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newElixirPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newElixirPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlElixirPackage, error) {
	mqlFiles := []any{}
	for i := range pkg.EvidenceList {
		lf, err := CreateResource(runtime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(pkg.EvidenceList[i].Value),
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

	mqlPkg, err := CreateResource(runtime, "elixir.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlElixirPackage), nil
}

func (k *mqlElixirPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlElixirPackage) name() (string, error)    { return "", r.populateData() }
func (r *mqlElixirPackage) version() (string, error) { return "", r.populateData() }
func (r *mqlElixirPackage) purl() (string, error)    { return "", r.populateData() }
func (r *mqlElixirPackage) files() ([]any, error)    { return nil, r.populateData() }
func (r *mqlElixirPackage) populateData() error {
	return errors.New("elixir.package can only be created via elixir.packages")
}
