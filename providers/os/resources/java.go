// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
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
	"go.mondoo.com/mql/providers/os/resources/languages/java/gradlelockfile"
	"go.mondoo.com/mql/providers/os/resources/languages/java/jarscanner"
	"go.mondoo.com/mql/providers/os/resources/languages/java/pomxml"
	"go.mondoo.com/mql/types"
)

// defaultJavaPaths are searched for pom.xml, gradle.lockfile, and JAR files.
// Only top-level files in these directories are scanned, except in
// defaultJavaArchiveTrees; use java.packages(path: "/specific/dir") for
// targeted scanning.
var defaultJavaPaths = []string{
	// Common deployment locations
	"/app",
	"/opt",
	"/usr/local/lib",
	"/usr/share/java",
	// Container app paths
	"/usr/src/app",
	"/home/*/app",
}

// defaultJavaArchiveTrees are default paths whose subdirectories are searched
// for JAR files as well, down to javaArchiveSearchDepth. SUSE, Fedora and RHEL
// install packaged jars in the JPackage layout, one subdirectory per package
// (/usr/share/java/log4j/log4j-core.jar). The other default paths are
// application directories, often holding node_modules or vendor trees with
// thousands of entries, which cost a round trip each over SSH.
var defaultJavaArchiveTrees = []string{
	"/usr/share/java",
}

// javaArchiveSearchDepth is how many levels of subdirectories below a search
// directory are scanned for archives. One covers the JPackage layout SUSE,
// Fedora and RHEL install packaged jars in (/usr/share/java/log4j/log4j-core.jar)
// and keeps the walk to one listing per subdirectory: only the entries of the
// search directory itself are stat'ed, and over SSH with --sudo every stat is
// a command of its own.
const javaArchiveSearchDepth = 1

func initJavaPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in java.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlJavaPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "java.packages/" + r.Path.Data, nil
	}
	return "java.packages", nil
}

type mqlJavaPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlJavaPackages) gatherData() error {
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
		r, d, t, f, err := collectJavaPackages(afs, path)
		if err := explicitLockfileError(err); err != nil {
			return err
		}
		root = r
		directDeps = d
		transitiveDeps = t
		filePaths = f
	} else {
		directDeps, transitiveDeps, filePaths = collectJavaDefaults(afs, defaultJavaPaths)
	}

	// Sort packages
	slices.SortFunc(directDeps, languages.SortFn)
	slices.SortFunc(transitiveDeps, languages.SortFn)

	// Set root
	if root != nil {
		mqlPkg, err := newJavaPackage(r.MqlRuntime, root)
		if err != nil {
			return err
		}
		r.Root = plugin.TValue[*mqlJavaPackage]{Data: mqlPkg, State: plugin.StateIsSet}
	} else {
		r.Root = plugin.TValue[*mqlJavaPackage]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Set list as the union of all packages (transitive already includes direct
	// for most formats; for JAR scanning, packages go into transitiveDeps only).
	// Deduplicate by name@version.
	allPkgs := deduplicatePackages(append(transitiveDeps, directDeps...))
	slices.SortFunc(allPkgs, languages.SortFn)
	allResources, err := newJavaPackageList(r.MqlRuntime, allPkgs)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	// Set direct dependencies
	directResources, err := newJavaPackageList(r.MqlRuntime, directDeps)
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

// collectJavaDefaults searches the default locations: pom.xml,
// gradle.lockfile and JAR files in each directory, and JAR files in the
// subdirectories of defaultJavaArchiveTrees. What cannot be read is logged
// and skipped.
func collectJavaDefaults(afs *afero.Afero, searchPaths []string) ([]*languages.Package, []*languages.Package, []string) {
	var directDeps []*languages.Package
	var transitiveDeps []*languages.Package
	var filePaths []string

	for _, searchPath := range searchPaths {
		// Look for pom.xml
		matches, err := afero.Glob(afs.Fs, filepath.Join(searchPath, "pom.xml"))
		if err == nil {
			for _, match := range matches {
				_, d, t, f, err := collectJavaPackages(afs, match)
				skipLockfileError(match, err)
				directDeps = append(directDeps, d...)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}

		// Look for gradle.lockfile
		matches, err = afero.Glob(afs.Fs, filepath.Join(searchPath, "gradle.lockfile"))
		if err == nil {
			for _, match := range matches {
				_, _, t, f, err := collectJavaPackages(afs, match)
				skipLockfileError(match, err)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}

		// Look for JAR files
		dirs, err := afero.Glob(afs.Fs, searchPath)
		if err != nil {
			continue
		}
		depth := 0
		if slices.Contains(defaultJavaArchiveTrees, searchPath) {
			depth = javaArchiveSearchDepth
		}
		isJar := func(name string) bool { return strings.HasSuffix(name, ".jar") }
		for _, dir := range dirs {
			archives, err := findJavaArchives(afs, dir, depth, isJar)
			skipLockfileError(dir, err)
			for _, match := range archives {
				_, _, t, f, err := collectFromArchive(afs, match)
				skipLockfileError(match, err)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	return directDeps, transitiveDeps, filePaths
}

// findJavaArchives lists the files in dir whose names match, then those in
// its subdirectories down to depth levels, in name order. A directory that
// exists but cannot be listed is returned as an error alongside the archives
// found elsewhere.
//
// Names are read without a stat per entry, and only an entry that does not
// match and could still be descended into is stat'ed: over SSH with --sudo
// every stat is a command of its own, and directories such as
// /usr/local/lib/python3.x/site-packages hold hundreds of entries.
func findJavaArchives(afs *afero.Afero, dir string, depth int, match func(name string) bool) ([]string, error) {
	f, err := afs.Open(dir)
	if err != nil {
		return nil, lockfileReadError(dir, err)
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, lockfileReadError(dir, err)
	}
	slices.Sort(names)

	var res []string
	var subdirs []string
	for _, name := range names {
		p := filepath.Join(dir, name)
		if match(name) {
			res = append(res, p)
			continue
		}
		if depth == 0 {
			continue
		}
		if isDir, err := afs.IsDir(p); err == nil && isDir {
			subdirs = append(subdirs, p)
		}
	}
	var errs []error
	for _, sub := range subdirs {
		archives, err := findJavaArchives(afs, sub, depth-1, match)
		errs = append(errs, err)
		res = append(res, archives...)
	}
	return res, errors.Join(errs...)
}

// collectJavaPackages parses Java package metadata from a given path.
// Returns root, direct deps, transitive deps, and evidence file paths, and
// what could not be read or parsed as an error.
func collectJavaPackages(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string, error) {
	isDir, err := lockfileIsDir(afs, path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if isDir {
		return collectJavaFromDir(afs, path)
	}

	// Single file
	if strings.HasSuffix(path, "pom.xml") {
		return collectJavaFromFile(afs, path, &pomxml.Extractor{})
	}
	if strings.HasSuffix(path, "gradle.lockfile") {
		return collectJavaFromFile(afs, path, &gradlelockfile.Extractor{})
	}
	if jarscanner.IsArchive(path) {
		return collectFromArchive(afs, path)
	}

	return nil, nil, nil, nil, nil
}

// collectJavaFromDir reads pom.xml, gradle.lockfile and the archives in dir
// and its subdirectories. What cannot be read, and a pom.xml or
// gradle.lockfile that does not parse, is returned as an error alongside the
// rest. An archive that is not a valid one is logged and skipped: a
// directory of jars may well hold one that is not, and it must not hide the
// others.
func collectJavaFromDir(afs *afero.Afero, dir string) (*languages.Package, []*languages.Package, []*languages.Package, []string, error) {
	var root *languages.Package
	var direct []*languages.Package
	var transitive []*languages.Package
	var files []string
	var errs []error

	// Try pom.xml first
	pomPath := filepath.Join(dir, "pom.xml")
	if exists, err := lockfileExists(afs, pomPath); err != nil {
		errs = append(errs, err)
	} else if exists {
		r, d, t, f, err := collectJavaFromFile(afs, pomPath, &pomxml.Extractor{})
		errs = append(errs, err)
		root = r
		direct = append(direct, d...)
		transitive = append(transitive, t...)
		files = append(files, f...)
	}

	// Try gradle.lockfile
	gradlePath := filepath.Join(dir, "gradle.lockfile")
	if exists, err := lockfileExists(afs, gradlePath); err != nil {
		errs = append(errs, err)
	} else if exists {
		_, _, t, f, err := collectJavaFromFile(afs, gradlePath, &gradlelockfile.Extractor{})
		errs = append(errs, err)
		transitive = append(transitive, t...)
		files = append(files, f...)
	}

	// Scan JAR files in the directory and its subdirectories
	archives, err := findJavaArchives(afs, dir, javaArchiveSearchDepth, jarscanner.IsArchive)
	errs = append(errs, err)
	for _, jarPath := range archives {
		_, _, t, f, err := collectFromArchive(afs, jarPath)
		if errors.Is(err, llx.ErrMalformedData) {
			log.Warn().Err(err).Str("path", jarPath).Msg("could not scan Java archive, skipping")
			continue
		}
		errs = append(errs, err)
		transitive = append(transitive, t...)
		files = append(files, f...)
	}

	return root, direct, transitive, files, errors.Join(errs...)
}

func collectJavaFromFile(afs *afero.Afero, path string, extractor languages.Extractor) (*languages.Package, []*languages.Package, []*languages.Package, []string, error) {
	bom, err := parseLockfile(afs, path, extractor)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}, nil
}

// collectFromArchive scans the archive at path. An archive that cannot be
// read is an error, one that is not a valid archive malformed data.
func collectFromArchive(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string, error) {
	packages, err := jarscanner.ScanArchive(afs, path)
	if err != nil {
		if isFsError(err) {
			return nil, nil, nil, nil, lockfileReadError(path, err)
		}
		return nil, nil, nil, nil, llx.MalformedData(fmt.Errorf("cannot scan %s: %w", path, err))
	}
	if len(packages) == 0 {
		return nil, nil, nil, nil, nil
	}

	return nil, nil, packages, []string{path}, nil
}

// deduplicatePackages removes duplicate packages by name@version.
func deduplicatePackages(pkgs []*languages.Package) []*languages.Package {
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

func (r *mqlJavaPackages) root() (*mqlJavaPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlJavaPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlJavaPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlJavaPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

// newJavaPackageList creates a list of Java package resources.
func newJavaPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newJavaPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

// newJavaPackage creates a new Java package resource.
func newJavaPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlJavaPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "java.package", map[string]*llx.RawData{
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
	return mqlPkg.(*mqlJavaPackage), nil
}

func (k *mqlJavaPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlJavaPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlJavaPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlJavaPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlJavaPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlJavaPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlJavaPackage) populateData() error {
	// java.package instances are only created via newJavaPackage, which pre-populates
	// all fields at creation time. This fallback is only reached if a java.package is
	// resolved by ID alone without going through newJavaPackage.
	r.Name = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Purl = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Cpes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	r.Files = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil
}
