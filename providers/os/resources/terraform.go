// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
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
	if path == "" {
		path = "."
	}

	allDeps, filePaths := collectTerraformPackages(afs, path)

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

// terraformLockFile is the file `terraform init` writes to pin provider versions.
const terraformLockFile = ".terraform.lock.hcl"

// maxLockSearchDepth bounds how far below the search root a lock file is looked
// for. Terraform workspaces nest a few levels at most (envs/prod, stacks/network);
// the cap keeps the walk from descending an entire filesystem when the resource
// runs against an OS or container connection, where the root is / and there is
// usually no lock file at all.
const maxLockSearchDepth = 8

// skipLockSearchDirs never hold the project's own lock file. `.terraform` is the
// one that matters for correctness: it holds downloaded modules, each of which
// may ship a lock file of its own, and reporting those would attribute a
// dependency's providers to this project.
var skipLockSearchDirs = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	".terraform":   true,
	"node_modules": true,
	"vendor":       true,
	"proc":         true,
	"sys":          true,
	"dev":          true,
}

func collectTerraformPackages(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Terraform path")
		return nil, nil
	}

	if !isDir {
		if strings.HasSuffix(path, terraformLockFile) {
			return collectTerraformFromFile(afs, path)
		}
		return nil, nil
	}

	return collectTerraformInTree(afs, path)
}

// collectTerraformInTree searches a directory tree for lock files. A repository
// commonly holds more than one — a workspace per environment, each with its own
// pinned provider set — and before this walk only a lock file sitting exactly at
// the search root was ever found.
func collectTerraformInTree(afs *afero.Afero, root string) ([]*languages.Package, []string) {
	var deps []*languages.Package
	var files []string

	rootDepth := strings.Count(filepath.ToSlash(filepath.Clean(root)), "/")

	err := afero.Walk(afs, root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			// An unreadable subtree is skipped rather than failing the walk:
			// a permission error deep in a tree must not cost us the lock
			// files we already found.
			return nil //nolint:nilerr
		}

		if info.IsDir() {
			if p != root && skipLockSearchDirs[info.Name()] {
				return filepath.SkipDir
			}
			if strings.Count(filepath.ToSlash(p), "/")-rootDepth > maxLockSearchDepth {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Name() != terraformLockFile {
			return nil
		}

		d, f := collectTerraformFromFile(afs, p)
		deps = append(deps, d...)
		files = append(files, f...)
		return nil
	})
	if err != nil {
		log.Debug().Err(err).Str("path", root).Msg("could not search for Terraform lock files")
	}

	return deps, files
}

func collectTerraformFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Terraform lock file")
		return nil, nil
	}
	defer f.Close()

	extractor := &lockfile.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Terraform lock file")
		return nil, nil
	}

	return bom.Transitive(), []string{path}
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
