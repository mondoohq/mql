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
	"go.mondoo.com/mql/providers/os/resources/languages/golang/gomod"
	"go.mondoo.com/mql/providers/os/resources/languages/golang/gosum"
	"go.mondoo.com/mql/types"
)

var defaultGoPaths = []string{
	// Common project locations
	"/app",
	"/home/*/go/src",
	"/root/go/src",
	"/usr/local/go/src",
	// Container app paths
	"/usr/src/app",
	"/workspace",
}

func initGoPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in go.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlGoPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "go.packages/" + r.Path.Data, nil
	}
	return "go.packages", nil
}

type mqlGoPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlGoPackages) gatherData() error {
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

	var root *languages.Package
	var directDeps []*languages.Package
	var transitiveDeps []*languages.Package
	var filePaths []string

	if path != "" {
		// Specific path provided
		bom, evidence, err := collectGoPackages(afs, path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not collect Go packages")
		} else if bom != nil {
			root = bom.Root()
			directDeps = bom.Direct()
			transitiveDeps = bom.Transitive()
			filePaths = evidence
		}
	} else {
		// Search default locations
		for _, searchPath := range defaultGoPaths {
			matches, err := afero.Glob(fs, filepath.Join(searchPath, "go.mod"))
			if err != nil {
				continue
			}
			for _, match := range matches {
				dir := filepath.Dir(match)
				bom, evidence, err := collectGoPackages(afs, dir)
				if err != nil {
					continue
				}
				if bom != nil {
					if root == nil {
						root = bom.Root()
					}
					directDeps = append(directDeps, bom.Direct()...)
					transitiveDeps = append(transitiveDeps, bom.Transitive()...)
					filePaths = append(filePaths, evidence...)
				}
			}
		}
	}

	// Sort packages
	slices.SortFunc(directDeps, languages.SortFn)
	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Set root
	if root != nil {
		mqlPkg, err := newGoPackage(r.MqlRuntime, root)
		if err != nil {
			return err
		}
		r.Root = plugin.TValue[*mqlGoPackage]{Data: mqlPkg, State: plugin.StateIsSet}
	} else {
		r.Root = plugin.TValue[*mqlGoPackage]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Set transitive list
	transitiveResources, err := newGoPackageList(r.MqlRuntime, transitiveDeps)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: transitiveResources, State: plugin.StateIsSet}

	// Set direct dependencies
	directResources, err := newGoPackageList(r.MqlRuntime, directDeps)
	if err != nil {
		return err
	}
	r.DirectDependencies = plugin.TValue[[]any]{Data: directResources, State: plugin.StateIsSet}

	// Set files
	mqlFiles := []any{}
	for _, path := range filePaths {
		lf, err := CreateResource(r.MqlRuntime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(path),
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

// collectGoPackages reads go.mod (and optionally go.sum) from a directory or file path.
// Returns the BOM and a list of evidence file paths.
func collectGoPackages(afs *afero.Afero, path string) (languages.Bom, []string, error) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		return nil, nil, err
	}

	var goModPath string
	if isDir {
		goModPath = filepath.Join(path, "go.mod")
	} else if strings.HasSuffix(path, "go.mod") {
		goModPath = path
	} else if strings.HasSuffix(path, "go.sum") {
		// If pointed directly at a go.sum, parse it
		return parseGoSumFile(afs, path)
	} else {
		return nil, nil, errors.New("path is not a go.mod, go.sum, or directory containing one")
	}

	exists, err := afs.Exists(goModPath)
	if err != nil || !exists {
		return nil, nil, errors.New("go.mod not found at " + goModPath)
	}

	// Parse go.mod
	f, err := afs.Open(goModPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	extractor := &gomod.Extractor{}
	bom, err := extractor.Parse(f, goModPath)
	if err != nil {
		return nil, nil, err
	}

	return bom, []string{goModPath}, nil
}

func parseGoSumFile(afs *afero.Afero, path string) (languages.Bom, []string, error) {
	f, err := afs.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	extractor := &gosum.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		return nil, nil, err
	}

	return bom, []string{path}, nil
}

func (r *mqlGoPackages) root() (*mqlGoPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlGoPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlGoPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlGoPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

// newGoPackageList creates a list of Go package resources.
func newGoPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newGoPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

// newGoPackage creates a new Go package resource.
func newGoPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlGoPackage, error) {
	// Handle CPEs
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

	// Create files for each evidence path
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

	mqlPkg, err := CreateResource(runtime, "go.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"cpes":    llx.ArrayData(cpes, types.Resource("cpe")),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlGoPackage), nil
}

func (k *mqlGoPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlGoPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlGoPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlGoPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlGoPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlGoPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlGoPackage) populateData() error {
	// go.package instances are only created via newGoPackage, which pre-populates
	// all fields (name, version, purl, cpes, files) at creation time. This fallback
	// is only reached if a go.package is resolved by ID alone without going through
	// newGoPackage, which does not happen in normal operation.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
