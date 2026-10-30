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
	"go.mondoo.com/mql/providers/os/resources/languages/cpp/vcpkg"
	"go.mondoo.com/mql/types"
)

var defaultVcpkgPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initVcpkgPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if _, ok := x.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'path' in vcpkg.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlVcpkgPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "vcpkg.packages/" + r.Path.Data, nil
	}
	return "vcpkg.packages", nil
}

type mqlVcpkgPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlVcpkgPackages) gatherData() error {
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

	var deps []*languages.Package
	var filePaths []string

	if searchPath != "" {
		t, f := collectVcpkgPackages(afs, searchPath)
		deps = append(deps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, sp := range defaultVcpkgPaths {
			matches, err := afero.Glob(fs, sp)
			if err != nil {
				continue
			}
			for _, match := range matches {
				t, f := collectVcpkgPackages(afs, match)
				deps = append(deps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(deps, languages.SortFn)

	allResources, err := newVcpkgPackageList(r.MqlRuntime, deps)
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

func collectVcpkgPackages(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		return nil, nil
	}

	if isDir {
		manifest := filepath.Join(path, "vcpkg.json")
		if exists, _ := afs.Exists(manifest); exists {
			return collectVcpkgFromFile(afs, manifest)
		}
		return nil, nil
	}

	if strings.HasSuffix(path, "vcpkg.json") {
		return collectVcpkgFromFile(afs, path)
	}

	return nil, nil
}

func collectVcpkgFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open vcpkg file")
		return nil, nil
	}
	defer f.Close()

	extractor := &vcpkg.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse vcpkg file")
		return nil, nil
	}

	// vcpkg dependencies are reported as direct; the root is the project itself.
	pkgs := append(bom.Direct(), bom.Transitive()...)
	return pkgs, []string{path}
}

func (r *mqlVcpkgPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlVcpkgPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newVcpkgPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newVcpkgPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newVcpkgPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlVcpkgPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "vcpkg.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlVcpkgPackage), nil
}

func (k *mqlVcpkgPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlVcpkgPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlVcpkgPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlVcpkgPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlVcpkgPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlVcpkgPackage) populateData() error {
	return errors.New("vcpkg.package can only be created via vcpkg.packages")
}
