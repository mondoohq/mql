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
	"go.mondoo.com/mql/providers/os/resources/languages/erlang/rebarlock"
	"go.mondoo.com/mql/types"
)

var defaultErlangPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initErlangPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if _, ok := x.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'path' in erlang.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlErlangPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "erlang.packages/" + r.Path.Data, nil
	}
	return "erlang.packages", nil
}

type mqlErlangPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlErlangPackages) gatherData() error {
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
		t, f := collectErlangPackages(afs, fs, path)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, searchPath := range defaultErlangPaths {
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
				t, f := collectErlangPackages(afs, fs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	allResources, err := newErlangPackageList(r.MqlRuntime, transitiveDeps)
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

func collectErlangPackages(afs *afero.Afero, _ afero.Fs, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Erlang path")
		return nil, nil
	}

	if isDir {
		lockPath := filepath.Join(path, "rebar.lock")
		if exists, _ := afs.Exists(lockPath); exists {
			return collectFromErlangFile(afs, lockPath)
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "rebar.lock") {
		return collectFromErlangFile(afs, path)
	}
	return nil, nil
}

func collectFromErlangFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open rebar.lock")
		return nil, nil
	}
	defer f.Close()

	extractor := &rebarlock.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse rebar.lock")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
}

func (r *mqlErlangPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlErlangPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newErlangPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newErlangPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newErlangPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlErlangPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "erlang.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlErlangPackage), nil
}

func (k *mqlErlangPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlErlangPackage) name() (string, error)    { return "", r.populateData() }
func (r *mqlErlangPackage) version() (string, error) { return "", r.populateData() }
func (r *mqlErlangPackage) purl() (string, error)    { return "", r.populateData() }
func (r *mqlErlangPackage) files() ([]any, error)    { return nil, r.populateData() }
func (r *mqlErlangPackage) populateData() error {
	return errors.New("erlang.package can only be created via erlang.packages")
}
