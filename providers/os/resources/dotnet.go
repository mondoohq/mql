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
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet/csproj"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet/depsjson"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet/packagesconfig"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet/packageslockjson"
	"go.mondoo.com/mql/types"
)

// defaultDotnetPaths are searched for .NET package files.
// Only top-level files in these directories are scanned.
var defaultDotnetPaths = []string{
	// Linux/container paths
	"/app",
	"/usr/src/app",
	"/home/*/app",
	"/opt",
	// Windows paths (WinRM scanning)
	"C:\\inetpub\\wwwroot",
	"C:\\Users\\*\\source",
	"C:\\app",
}

func initDotnetPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in dotnet.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlDotnetPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "dotnet.packages/" + r.Path.Data, nil
	}
	return "dotnet.packages", nil
}

type mqlDotnetPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlDotnetPackages) gatherData() error {
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
		root, directDeps, transitiveDeps, filePaths = collectDotnetPackages(afs, path)
	} else {
		for _, searchPath := range defaultDotnetPaths {
			for _, pattern := range []string{"packages.lock.json", "*.deps.json", "packages.config", "*.csproj", "*.fsproj"} {
				matches, err := afero.Glob(fs, filepath.Join(searchPath, pattern))
				if err != nil {
					continue
				}
				for _, match := range matches {
					collectedRoot, d, t, f := collectDotnetPackages(afs, match)
					if root == nil {
						root = collectedRoot
					}
					directDeps = append(directDeps, d...)
					transitiveDeps = append(transitiveDeps, t...)
					filePaths = append(filePaths, f...)
				}
			}
		}
	}

	slices.SortFunc(directDeps, languages.SortFn)
	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Set root
	if root != nil {
		mqlPkg, err := newDotnetPackage(r.MqlRuntime, root)
		if err != nil {
			return err
		}
		r.Root = plugin.TValue[*mqlDotnetPackage]{Data: mqlPkg, State: plugin.StateIsSet}
	} else {
		r.Root = plugin.TValue[*mqlDotnetPackage]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Set list (union of all packages, deduplicated).
	// Both slices are combined because some extractors (e.g., depsjson) return nil
	// for Direct() and only populate Transitive(), while others (e.g., packageslockjson)
	// include direct packages in Transitive(). Deduplication handles overlap.
	combined := make([]*languages.Package, 0, len(transitiveDeps)+len(directDeps))
	combined = append(combined, transitiveDeps...)
	combined = append(combined, directDeps...)
	allPkgs := deduplicateDotnetPackages(combined)
	slices.SortFunc(allPkgs, languages.SortFn)
	allResources, err := newDotnetPackageList(r.MqlRuntime, allPkgs)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	// Set direct dependencies
	directResources, err := newDotnetPackageList(r.MqlRuntime, directDeps)
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

func collectDotnetPackages(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check .NET path")
		return nil, nil, nil, nil
	}

	if isDir {
		return collectDotnetFromDir(afs, path)
	}

	return collectDotnetFromFile(afs, path)
}

func collectDotnetFromDir(afs *afero.Afero, dir string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	var root *languages.Package
	var direct []*languages.Package
	var transitive []*languages.Package
	var files []string

	// Prefer packages.lock.json (resolved versions)
	lockPath := filepath.Join(dir, "packages.lock.json")
	if exists, _ := afs.Exists(lockPath); exists {
		r, d, t, f := parseDotnetFile(afs, lockPath, &packageslockjson.Extractor{})
		root = r
		direct = append(direct, d...)
		transitive = append(transitive, t...)
		files = append(files, f...)
		return root, direct, transitive, files
	}

	// Try deps.json files
	entries, err := afs.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".deps.json") {
				_, _, t, f := parseDotnetFile(afs, filepath.Join(dir, entry.Name()), &depsjson.Extractor{})
				transitive = append(transitive, t...)
				files = append(files, f...)
			}
		}
	}

	// Try packages.config
	configPath := filepath.Join(dir, "packages.config")
	if exists, _ := afs.Exists(configPath); exists {
		_, d, t, f := parseDotnetFile(afs, configPath, &packagesconfig.Extractor{})
		direct = append(direct, d...)
		transitive = append(transitive, t...)
		files = append(files, f...)
	}

	// Try csproj/fsproj files
	if entries == nil {
		entries, _ = afs.ReadDir(dir)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".fsproj")) {
			_, d, t, f := parseDotnetFile(afs, filepath.Join(dir, name), &csproj.Extractor{})
			direct = append(direct, d...)
			transitive = append(transitive, t...)
			files = append(files, f...)
		}
	}

	return root, direct, transitive, files
}

func collectDotnetFromFile(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	var extractor languages.Extractor

	switch {
	case strings.HasSuffix(path, "packages.lock.json"):
		extractor = &packageslockjson.Extractor{}
	case strings.HasSuffix(path, ".deps.json"):
		extractor = &depsjson.Extractor{}
	case strings.HasSuffix(path, "packages.config"):
		extractor = &packagesconfig.Extractor{}
	case strings.HasSuffix(path, ".csproj") || strings.HasSuffix(path, ".fsproj"):
		extractor = &csproj.Extractor{}
	default:
		return nil, nil, nil, nil
	}

	return parseDotnetFile(afs, path, extractor)
}

func parseDotnetFile(afs *afero.Afero, path string, extractor languages.Extractor) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open .NET file")
		return nil, nil, nil, nil
	}
	defer f.Close()

	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse .NET file")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func deduplicateDotnetPackages(pkgs []*languages.Package) []*languages.Package {
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

func (r *mqlDotnetPackages) root() (*mqlDotnetPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlDotnetPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlDotnetPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlDotnetPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newDotnetPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newDotnetPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newDotnetPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlDotnetPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "dotnet.package", map[string]*llx.RawData{
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
	return mqlPkg.(*mqlDotnetPackage), nil
}

func (k *mqlDotnetPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlDotnetPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlDotnetPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlDotnetPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlDotnetPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlDotnetPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlDotnetPackage) populateData() error {
	// dotnet.package instances are only created via newDotnetPackage, which pre-populates
	// all fields at creation time. This fallback is only reached if a dotnet.package is
	// resolved by ID alone without going through newDotnetPackage.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
