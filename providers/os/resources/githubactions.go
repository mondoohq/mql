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
	"go.mondoo.com/mql/providers/os/resources/languages/githubactions/workflows"
	"go.mondoo.com/mql/types"
)

func initGithubactionsPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in githubactions.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlGithubactionsPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "githubactions.packages/" + r.Path.Data, nil
	}
	return "githubactions.packages", nil
}

type mqlGithubactionsPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlGithubactionsPackages) gatherData() error {
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
		deps, files, err := collectGithubActionsPackages(afs, fs, path)
		if err := explicitLockfileError(err); err != nil {
			return err
		}
		allDeps = append(allDeps, deps...)
		filePaths = append(filePaths, files...)
	} else {
		// Search default location: .github/workflows/
		deps, files, err := collectGithubActionsFromDir(afs, ".github/workflows")
		skipLockfileError(".github/workflows", err)
		allDeps = append(allDeps, deps...)
		filePaths = append(filePaths, files...)
	}

	// Deduplicate and sort
	allDeps = deduplicateGithubActionsPackages(allDeps)
	slices.SortFunc(allDeps, languages.SortFn)

	// Set list
	allResources, err := newGithubActionsPackageList(r.MqlRuntime, allDeps)
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

// collectGithubActionsPackages reads the workflow file at path, or the
// workflow files in the directory at path. A repository checkout keeps its
// workflows in .github/workflows, so for a directory those are read as well.
func collectGithubActionsPackages(afs *afero.Afero, fs afero.Fs, path string) ([]*languages.Package, []string, error) {
	isDir, err := lockfileIsDir(afs, path)
	if err != nil {
		return nil, nil, err
	}

	if !isDir {
		return collectGithubActionsFromFile(afs, path)
	}

	deps, files, err := collectGithubActionsFromDir(afs, path)
	errs := []error{err}
	workflowsDir := filepath.Join(path, ".github", "workflows")
	if exists, err := lockfileExists(afs, workflowsDir); err != nil {
		errs = append(errs, err)
	} else if exists {
		d, f, err := collectGithubActionsFromDir(afs, workflowsDir)
		errs = append(errs, err)
		deps = append(deps, d...)
		files = append(files, f...)
	}
	return deps, files, errors.Join(errs...)
}

// collectGithubActionsFromDir reads the workflow files in dir. A file that
// cannot be read or parsed is returned as an error alongside what the others
// hold.
func collectGithubActionsFromDir(afs *afero.Afero, dir string) ([]*languages.Package, []string, error) {
	var allDeps []*languages.Package
	var files []string
	var errs []error

	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil, nil, lockfileReadError(dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isWorkflowFile(name) {
			continue
		}
		deps, f, err := collectGithubActionsFromFile(afs, filepath.Join(dir, name))
		errs = append(errs, err)
		allDeps = append(allDeps, deps...)
		files = append(files, f...)
	}

	return allDeps, files, errors.Join(errs...)
}

func collectGithubActionsFromFile(afs *afero.Afero, path string) ([]*languages.Package, []string, error) {
	bom, err := parseLockfile(afs, path, &workflows.Extractor{})
	if err != nil {
		return nil, nil, err
	}
	return bom.Transitive(), []string{path}, nil
}

func isWorkflowFile(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func deduplicateGithubActionsPackages(pkgs []*languages.Package) []*languages.Package {
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

func (r *mqlGithubactionsPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlGithubactionsPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newGithubActionsPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newGithubActionsPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newGithubActionsPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlGithubactionsPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "githubactions.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlGithubactionsPackage), nil
}

func (k *mqlGithubactionsPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlGithubactionsPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlGithubactionsPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlGithubactionsPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlGithubactionsPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlGithubactionsPackage) populateData() error {
	// githubactions.package instances are only created via newGithubActionsPackage,
	// which pre-populates all fields at creation time.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
