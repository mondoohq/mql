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
	"go.mondoo.com/mql/providers/os/resources/languages/php/composerjson"
	"go.mondoo.com/mql/providers/os/resources/languages/php/composerlock"
	"go.mondoo.com/mql/providers/os/resources/languages/php/installedjson"
	"go.mondoo.com/mql/types"
)

// defaultPhpPaths are searched for Composer files.
// Only top-level files in these directories are scanned.
var defaultPhpPaths = []string{
	"/app",
	"/var/www/html",
	"/var/www",
	// SUSE's Apache document root
	"/srv/www/htdocs",
	"/usr/src/app",
	"/home/*/app",
}

func initPhpPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in php.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlPhpPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "php.packages/" + r.Path.Data, nil
	}
	return "php.packages", nil
}

type mqlPhpPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlPhpPackages) gatherData() error {
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
		root, directDeps, transitiveDeps, filePaths = collectPhpPackages(afs, path)
	} else {
		for _, searchPath := range defaultPhpPaths {
			hasLock := false

			// Check composer.lock for resolved versions
			lockMatches, _ := afero.Glob(fs, filepath.Join(searchPath, "composer.lock"))
			if len(lockMatches) > 0 {
				hasLock = true
				for _, match := range lockMatches {
					_, d, t, f := collectPhpPackages(afs, match)
					directDeps = append(directDeps, d...)
					transitiveDeps = append(transitiveDeps, t...)
					filePaths = append(filePaths, f...)
				}
			}

			// Always check composer.json for root project info;
			// only use deps from it if no lock file was found
			jsonMatches, _ := afero.Glob(fs, filepath.Join(searchPath, "composer.json"))
			for _, match := range jsonMatches {
				collectedRoot, d, t, f := collectPhpPackages(afs, match)
				if root == nil {
					root = collectedRoot
				}
				if !hasLock {
					directDeps = append(directDeps, d...)
					transitiveDeps = append(transitiveDeps, t...)
				}
				filePaths = append(filePaths, f...)
			}

			// Also check vendor/composer/installed.json
			installedMatches, _ := afero.Glob(fs, filepath.Join(searchPath, "vendor/composer/installed.json"))
			for _, match := range installedMatches {
				_, _, t, f := collectPhpPackages(afs, match)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(directDeps, languages.SortFn)
	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Set root
	if root != nil {
		mqlPkg, err := newPhpPackage(r.MqlRuntime, root)
		if err != nil {
			return err
		}
		r.Root = plugin.TValue[*mqlPhpPackage]{Data: mqlPkg, State: plugin.StateIsSet}
	} else {
		r.Root = plugin.TValue[*mqlPhpPackage]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Set list (union of all packages, deduplicated).
	combined := make([]*languages.Package, 0, len(transitiveDeps)+len(directDeps))
	combined = append(combined, transitiveDeps...)
	combined = append(combined, directDeps...)
	allPkgs := deduplicatePhpPackages(combined)
	slices.SortFunc(allPkgs, languages.SortFn)
	allResources, err := newPhpPackageList(r.MqlRuntime, allPkgs)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	// Set direct dependencies
	directResources, err := newPhpPackageList(r.MqlRuntime, directDeps)
	if err != nil {
		return err
	}
	r.DirectDependencies = plugin.TValue[[]any]{Data: directResources, State: plugin.StateIsSet}

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

func collectPhpPackages(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check PHP path")
		return nil, nil, nil, nil
	}

	if isDir {
		return collectPhpFromDir(afs, path)
	}

	return collectPhpFromFile(afs, path)
}

func collectPhpFromDir(afs *afero.Afero, dir string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	var root *languages.Package
	var direct []*languages.Package
	var transitive []*languages.Package
	var files []string

	// Check for composer.lock (resolved versions, preferred source)
	hasLock := false
	lockPath := filepath.Join(dir, "composer.lock")
	if exists, _ := afs.Exists(lockPath); exists {
		hasLock = true
		_, d, t, f := parsePhpFile(afs, lockPath, &composerlock.Extractor{})
		direct = append(direct, d...)
		transitive = append(transitive, t...)
		files = append(files, f...)
	}

	// Always check composer.json for root project info;
	// only use deps from it if no lock file was found
	jsonPath := filepath.Join(dir, "composer.json")
	if exists, _ := afs.Exists(jsonPath); exists {
		r, d, t, f := parsePhpFile(afs, jsonPath, &composerjson.Extractor{})
		if root == nil {
			root = r
		}
		if !hasLock {
			direct = append(direct, d...)
			transitive = append(transitive, t...)
		}
		files = append(files, f...)
	}

	// Check vendor/composer/installed.json
	installedPath := filepath.Join(dir, "vendor", "composer", "installed.json")
	if exists, _ := afs.Exists(installedPath); exists {
		_, _, t, f := parsePhpFile(afs, installedPath, &installedjson.Extractor{})
		transitive = append(transitive, t...)
		files = append(files, f...)
	}

	return root, direct, transitive, files
}

func collectPhpFromFile(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	var extractor languages.Extractor

	switch {
	case strings.HasSuffix(path, "composer.lock"):
		extractor = &composerlock.Extractor{}
	case strings.HasSuffix(path, "composer.json"):
		extractor = &composerjson.Extractor{}
	case strings.HasSuffix(path, "installed.json"):
		extractor = &installedjson.Extractor{}
	default:
		return nil, nil, nil, nil
	}

	return parsePhpFile(afs, path, extractor)
}

func parsePhpFile(afs *afero.Afero, path string, extractor languages.Extractor) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open PHP file")
		return nil, nil, nil, nil
	}
	defer f.Close()

	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse PHP file")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func deduplicatePhpPackages(pkgs []*languages.Package) []*languages.Package {
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

func (r *mqlPhpPackages) root() (*mqlPhpPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlPhpPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlPhpPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlPhpPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newPhpPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newPhpPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newPhpPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlPhpPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "php.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		// composer.lock and installed.json both state these; the extractors
		// render the license list as an SPDX expression.
		"license":     llx.StringData(pkg.License),
		"description": llx.StringData(pkg.Description),
		"cpes":        llx.ArrayData(cpes, types.Resource("cpe")),
		"files":       llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlPhpPackage), nil
}

func (k *mqlPhpPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlPhpPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlPhpPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlPhpPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlPhpPackage) license() (string, error) {
	return "", r.populateData()
}

func (r *mqlPhpPackage) description() (string, error) {
	return "", r.populateData()
}

func (r *mqlPhpPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlPhpPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlPhpPackage) populateData() error {
	// php.package instances are only created via newPhpPackage, which pre-populates
	// all fields at creation time. This fallback is only reached if a php.package is
	// resolved by ID alone without going through newPhpPackage.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.License = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Description = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
