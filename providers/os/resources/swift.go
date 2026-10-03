// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/swift/packageresolved"
	"go.mondoo.com/mql/providers/os/resources/languages/swift/podfilelock"
	"go.mondoo.com/mql/types"
)

// defaultSwiftPaths are searched for Swift package files.
// Only top-level files in these directories are scanned.
var defaultSwiftPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
}

func initSwiftPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in swift.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlSwiftPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "swift.packages/" + r.Path.Data, nil
	}
	return "swift.packages", nil
}

type mqlSwiftPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlSwiftPackages) gatherData() error {
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

	var allDeps []*languages.Package
	var filePaths []string

	if path != "" {
		deps, files, err := collectSwiftPackages(afs, path)
		if err := explicitLockfileError(err); err != nil {
			return err
		}
		allDeps = append(allDeps, deps...)
		filePaths = append(filePaths, files...)
	} else {
		for _, searchPath := range defaultSwiftPaths {
			// Expand glob wildcards in search paths (e.g., /home/*/app)
			matches, err := afero.Glob(fs, searchPath)
			if err != nil {
				// Skip paths with invalid glob patterns
				continue
			}
			if len(matches) == 0 {
				// Only fall back to literal path for non-glob paths (avoid
				// unnecessary stat calls for glob patterns with no matches)
				if strings.ContainsAny(searchPath, "*?[") {
					continue
				}
				matches = []string{searchPath}
			}
			for _, match := range matches {
				deps, files, err := collectSwiftFromDir(afs, match)
				skipLockfileError(match, err)
				allDeps = append(allDeps, deps...)
				filePaths = append(filePaths, files...)
			}
		}
	}

	// Deduplicate and sort
	allDeps = deduplicateSwiftPackages(allDeps)
	slices.SortFunc(allDeps, languages.SortFn)

	// Set list
	allResources, err := newSwiftPackageList(r.MqlRuntime, allDeps)
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

func collectSwiftPackages(afs *afero.Afero, path string) ([]*languages.Package, []string, error) {
	isDir, err := lockfileIsDir(afs, path)
	if err != nil {
		return nil, nil, err
	}

	if isDir {
		return collectSwiftFromDir(afs, path)
	}

	return collectSwiftFromFile(afs, path)
}

// collectSwiftFromDir reads Package.resolved and Podfile.lock in dir. A file
// that cannot be read or parsed is returned as an error alongside what the
// other holds.
func collectSwiftFromDir(afs *afero.Afero, dir string) ([]*languages.Package, []string, error) {
	var allDeps []*languages.Package
	var files []string
	var errs []error

	for _, name := range []string{"Package.resolved", "Podfile.lock"} {
		p := filepath.Join(dir, name)
		exists, err := lockfileExists(afs, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !exists {
			continue
		}
		deps, f, err := collectSwiftFromFile(afs, p)
		errs = append(errs, err)
		allDeps = append(allDeps, deps...)
		files = append(files, f...)
	}

	return allDeps, files, errors.Join(errs...)
}

func collectSwiftFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string, error) {
	var extractor languages.Extractor
	switch {
	case strings.HasSuffix(path, "Package.resolved"):
		extractor = &packageresolved.Extractor{}
	case strings.HasSuffix(path, "Podfile.lock"):
		extractor = &podfilelock.Extractor{}
	default:
		return nil, nil, nil
	}

	bom, err := parseLockfile(afs, path, extractor)
	if err != nil {
		return nil, nil, err
	}
	return bom.Transitive(), []string{path}, nil
}

func deduplicateSwiftPackages(pkgs []*languages.Package) []*languages.Package {
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

func (r *mqlSwiftPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlSwiftPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newSwiftPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newSwiftPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newSwiftPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlSwiftPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "swift.package", map[string]*llx.RawData{
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
	return mqlPkg.(*mqlSwiftPackage), nil
}

func (k *mqlSwiftPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlSwiftPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlSwiftPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlSwiftPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlSwiftPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlSwiftPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlSwiftPackage) populateData() error {
	// swift.package instances are only created via newSwiftPackage, which pre-populates
	// all fields at creation time.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
