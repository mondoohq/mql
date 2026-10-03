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
	"go.mondoo.com/mql/providers/os/resources/languages/terraform/lockfile"
	"go.mondoo.com/mql/types"
)

func initTerraformPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in terraform.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlTerraformPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "terraform.packages/" + r.Path.Data, nil
	}
	return "terraform.packages", nil
}

type mqlTerraformPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlTerraformPackages) gatherData() error {
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
		deps, files, err := collectTerraformPackages(afs, path)
		if err := explicitLockfileError(err); err != nil {
			return err
		}
		allDeps = append(allDeps, deps...)
		filePaths = append(filePaths, files...)
	} else {
		// Search for .terraform.lock.hcl in current directory
		deps, files, err := collectTerraformFromFile(afs, ".terraform.lock.hcl")
		skipLockfileError(".terraform.lock.hcl", err)
		allDeps = append(allDeps, deps...)
		filePaths = append(filePaths, files...)
	}

	slices.SortFunc(allDeps, languages.SortFn)

	allResources, err := newTerraformPackageList(r.MqlRuntime, allDeps)
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

func collectTerraformPackages(afs *afero.Afero, path string) ([]*languages.Package, []string, error) {
	isDir, err := lockfileIsDir(afs, path)
	if err != nil {
		return nil, nil, err
	}

	if isDir {
		lockPath := filepath.Join(path, ".terraform.lock.hcl")
		return collectTerraformFromFile(afs, lockPath)
	}

	if strings.HasSuffix(path, ".terraform.lock.hcl") {
		return collectTerraformFromFile(afs, path)
	}

	return nil, nil, nil
}

// collectTerraformFromFile reads the lock file at path. A lock file that does
// not exist is returned as an os.ErrNotExist error.
func collectTerraformFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string, error) {
	bom, err := parseLockfile(afs, path, &lockfile.Extractor{})
	if err != nil {
		return nil, nil, err
	}
	return bom.Transitive(), []string{path}, nil
}

func (r *mqlTerraformPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlTerraformPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newTerraformPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newTerraformPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newTerraformPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlTerraformPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "terraform.package", map[string]*llx.RawData{
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
	return mqlPkg.(*mqlTerraformPackage), nil
}

func (k *mqlTerraformPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlTerraformPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlTerraformPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlTerraformPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlTerraformPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlTerraformPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlTerraformPackage) populateData() error {
	// terraform.package instances are only created via newTerraformPackage,
	// which pre-populates all fields at creation time.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
