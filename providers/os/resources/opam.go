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
	"go.mondoo.com/mql/providers/os/resources/languages/ocaml/opam"
	"go.mondoo.com/mql/types"
)

var defaultOpamPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initOpamPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if _, ok := x.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'path' in opam.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlOpamPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "opam.packages/" + r.Path.Data, nil
	}
	return "opam.packages", nil
}

type mqlOpamPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlOpamPackages) gatherData() error {
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
		t, f := collectOpamPackages(afs, searchPath)
		deps = append(deps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, sp := range defaultOpamPaths {
			matches, err := afero.Glob(fs, sp)
			if err != nil {
				continue
			}
			for _, match := range matches {
				t, f := collectOpamPackages(afs, match)
				deps = append(deps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(deps, languages.SortFn)

	allResources, err := newOpamPackageList(r.MqlRuntime, deps)
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

// isOpamFile reports whether a filename is an opam manifest (*.opam) or lock
// variant (*.opam.locked).
func isOpamFile(name string) bool {
	return strings.HasSuffix(name, ".opam") || strings.HasSuffix(name, ".opam.locked")
}

func collectOpamPackages(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		return nil, nil
	}

	if !isDir {
		if isOpamFile(path) {
			return collectOpamFromFile(afs, path)
		}
		return nil, nil
	}

	// A directory can declare several packages, one *.opam file each.
	entries, err := afs.ReadDir(path)
	if err != nil {
		return nil, nil
	}
	var deps []*languages.Package
	var files []string
	for _, e := range entries {
		if e.IsDir() || !isOpamFile(e.Name()) {
			continue
		}
		d, f := collectOpamFromFile(afs, filepath.Join(path, e.Name()))
		deps = append(deps, d...)
		files = append(files, f...)
	}
	return deps, files
}

func collectOpamFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open opam file")
		return nil, nil
	}
	defer f.Close()

	extractor := &opam.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse opam file")
		return nil, nil
	}

	// opam dependencies are reported as direct; the root is the package itself.
	pkgs := append(bom.Direct(), bom.Transitive()...)
	return pkgs, []string{path}
}

func (r *mqlOpamPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlOpamPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newOpamPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newOpamPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newOpamPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlOpamPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "opam.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlOpamPackage), nil
}

func (k *mqlOpamPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlOpamPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlOpamPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlOpamPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlOpamPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlOpamPackage) populateData() error {
	return errors.New("opam.package can only be created via opam.packages")
}
