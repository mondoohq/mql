// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/fsutil"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
	"go.mondoo.com/mql/providers/os/resources/languages/python/pdmlock"
	"go.mondoo.com/mql/providers/os/resources/languages/python/pipfilelock"
	"go.mondoo.com/mql/providers/os/resources/languages/python/poetrylock"
	"go.mondoo.com/mql/providers/os/resources/languages/python/requirements"
	"go.mondoo.com/mql/providers/os/resources/languages/python/uvlock"
	"go.mondoo.com/mql/providers/os/resources/languages/python/wheelegg"
	"go.mondoo.com/mql/types"
)

// defaultPythonPaths lists the directories that *contain* a site-packages or
// dist-packages directory; collectPythonPackagesInPaths appends those names.
//
// These are glob patterns evaluated by afero.Glob, which supports "*" but not
// "**", so every directory level has to be spelled out. Note that, unlike shell
// globbing, "*" here does match dot-directories, so "/app/*/lib/python*" picks
// up "/app/.venv/lib/python3.13".
var defaultPythonPaths = []string{
	// Linux
	"/usr/local/lib/python*",
	"/usr/local/lib64/python*",
	"/usr/lib/python*",
	"/usr/lib64/python*",
	// Virtualenvs. Applications -- container images especially -- commonly
	// install their dependencies into a venv instead of the system paths above,
	// so without these the application's own packages are missing entirely.
	// The venv directory name varies (.venv, venv, env, ...), hence the "*".
	//
	// Known limitation: because there is no "**", these reach a venv sitting
	// directly in one of these roots and one directory deeper (a project
	// checkout that carries its own venv). A venv buried deeper than that --
	// /app/myproject/backend/.venv, say -- is still missed. Set the python
	// resource's `path` argument explicitly to cover such a layout.
	"/venv/lib/python*",
	"/.venv/lib/python*",
	"/app/*/lib/python*",
	"/code/*/lib/python*",
	"/workspace/*/lib/python*",
	"/srv/*/lib/python*",
	"/opt/*/lib/python*",
	"/usr/src/*/*/lib/python*",
	// a project directory under one of the roots above holding its own venv
	"/app/*/*/lib/python*",
	"/code/*/*/lib/python*",
	"/workspace/*/*/lib/python*",
	"/srv/*/*/lib/python*",
	"/opt/*/*/lib/python*",
	// per-user venvs. The "*" covers .venv, venv and env alike; virtualenvwrapper
	// and poetry instead collect them under a dedicated directory.
	"/root/*/lib/python*",
	"/root/*/*/lib/python*",
	"/root/.virtualenvs/*/lib/python*",
	"/home/*/*/lib/python*",
	"/home/*/.virtualenvs/*/lib/python*",
	// Windows
	"C:\\Python*\\Lib",
	"C:\\Program Files\\Python*\\Lib",
	// per-user installs across all profiles
	"C:\\Users\\*\\AppData\\Local\\Programs\\Python\\Python*\\Lib",
	// Windows venvs put site-packages directly under Lib, with no pythonX.Y level
	"C:\\venv\\Lib",
	"C:\\.venv\\Lib",
	"C:\\Users\\*\\.venv\\Lib",
	"C:\\Users\\*\\*\\.venv\\Lib",
	// macOS
	"/opt/homebrew/lib/python*",
	"/System/Library/Frameworks/Python.framework/Versions/*/lib/python*",
	// we use 3.x to exclude the macOS 'Current' symlink
	"/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.*/lib/python*",
	"/Users/*/*/lib/python*",
	"/Users/*/.virtualenvs/*/lib/python*",
}

func initPython(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in python initialization, it must be a string")
		}
	} else {
		// empty path means search through default locations
		args["path"] = llx.StringData("")
	}

	return args, nil, nil
}

func (r *mqlPython) id() (string, error) {
	// The path has to be part of the ID. Without it every python(path: ...)
	// shares one cache key, so the first one scanned wins and every later
	// lookup -- with a completely different path -- gets handed its packages.
	if r.Path.Data != "" {
		return "python/" + r.Path.Data, nil
	}
	return "python", nil
}

func (r *mqlPython) packages() ([]any, error) {
	allPyPkgDetails, err := r.getAllPackages()
	if err != nil {
		return nil, err
	}

	// this is the "global" map so that the recursive function calls can keep track of
	// resources already created
	pythonPackageResourceMap := map[string]plugin.Resource{}

	resp := []any{}

	for _, pyPkgDetails := range allPyPkgDetails {
		res, err := pythonPackageDetailsWithDependenciesToResource(r.MqlRuntime, pyPkgDetails, pythonPackageResourceMap)
		if err != nil {
			log.Error().Err(err).Msg("error while creating resource(s) for python package")
			// we will keep trying to make resources even if a single one failed
			continue
		}
		resp = append(resp, res)
	}

	return resp, nil
}

func (r *mqlPython) toplevel() ([]any, error) {
	allPyPkgDetails, err := r.getAllPackages()
	if err != nil {
		return nil, err
	}

	// this is the "global" map so that the recursive function calls can keep track of
	// resources already created
	pythonPackageResourceMap := map[string]plugin.Resource{}

	resp := []any{}

	for _, pyPkgDetails := range allPyPkgDetails {
		if !pyPkgDetails.IsLeaf {
			continue
		}

		res, err := pythonPackageDetailsWithDependenciesToResource(r.MqlRuntime, pyPkgDetails, pythonPackageResourceMap)
		if err != nil {
			log.Error().Err(err).Msg("error while creating resource(s) for python package")
			// we will keep trying to make resources even if a single one failed
			continue
		}
		resp = append(resp, res)
	}

	return resp, nil
}

func (r *mqlPython) getAllPackages() ([]python.PackageDetails, error) {
	conn, ok := r.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, fmt.Errorf("provider is not an operating system provider")
	}
	fs := conn.FileSystem()
	if r.Path.Error != nil {
		return nil, r.Path.Error
	}
	pyPath := r.Path.Data
	if pyPath != "" {
		allResults, err := collectPythonPackages(r.MqlRuntime, fs, pyPath)
		if err != nil {
			return nil, err
		}

		// Also scan for source manifests (requirements.txt, lock files) in the path.
		manifestResults := collectPythonManifestPackages(fs, pyPath)
		allResults = mergePythonPackages(allResults, manifestResults)

		return allResults, nil
	} else {
		return collectPythonPackagesInPaths(r.MqlRuntime, fs, defaultPythonPaths)
	}
}

func pythonPackageDetailsWithDependenciesToResource(
	runtime *plugin.Runtime,
	newPyPkgDetails python.PackageDetails,
	pythonPackageResourceMap map[string]plugin.Resource,
) (any, error) {
	res := pythonPackageResourceMap[newPyPkgDetails.File]
	if res != nil {
		// already created the pythonPackage resource
		return res, nil
	}

	// finally create the resource
	r, err := newMqlPythonPackage(runtime, newPyPkgDetails)
	if err != nil {
		log.Error().Err(err).Str("resource", newPyPkgDetails.File).Msg("error while creating MQL resource")
		return nil, err
	}

	// name is not guaranteed to be unique, so we use the file path as the key
	pythonPackageResourceMap[newPyPkgDetails.File] = r

	return r, nil
}

func collectPythonPackagesInPaths(runtime *plugin.Runtime, fs afero.Fs, paths []string) ([]python.PackageDetails, error) {
	allResults := []python.PackageDetails{}

	// The default paths overlap: /opt/homebrew/lib/python3.11 is matched by both
	// "/opt/*/lib/python*" and "/opt/homebrew/lib/python*". Without this set the
	// directory is scanned once per matching pattern and every package inside it
	// is reported that many times, which inflates the inventory and emits one
	// duplicate SBOM entry and vulnerability finding per extra match.
	seen := map[string]struct{}{}

	err := fsutil.WalkGlob(fs, paths, func(fs afero.Fs, walkPath string) error {
		log.Debug().Str("filepath", walkPath).Msg("found matching python path")
		packageDirs := []string{"site-packages", "dist-packages"}
		for _, packageDir := range packageDirs {
			pythonPackageDir := filepath.Join(walkPath, packageDir)
			if _, ok := seen[pythonPackageDir]; ok {
				continue
			}
			seen[pythonPackageDir] = struct{}{}

			results, err := collectPythonPackages(runtime, fs, pythonPackageDir)
			if err != nil {
				// Skip this directory rather than abandoning the whole search.
				// The default paths are broad globs, so a single match that is
				// unreadable, or is a file rather than a directory, must not
				// cost us every other venv on the system.
				log.Debug().Err(err).Str("dir", pythonPackageDir).Msg("skipping unreadable python package directory")
				continue
			}
			allResults = append(allResults, results...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return allResults, nil
}

func collectPythonPackages(runtime *plugin.Runtime, fs afero.Fs, path string) ([]python.PackageDetails, error) {
	allResults := []python.PackageDetails{}
	afs := &afero.Afero{Fs: fs}

	fileList, err := afs.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []python.PackageDetails{}, nil
		}
		log.Warn().Err(err).Str("dir", path).Msg("unable to open directory")
		return nil, err
	}
	for _, dEntry := range fileList {
		// only process files/directories that might actually contain
		// the data we're looking for
		if !strings.HasSuffix(dEntry.Name(), ".dist-info") &&
			!strings.HasSuffix(dEntry.Name(), ".egg-info") {
			continue
		}

		// There is the possibility that the .egg-info entry is a file
		// (not a directory) that we can directly process.
		packagePayload := dEntry.Name()

		// requestedPackage just marks whether we found the empty REQUESTED file
		// to indicate a child/leaf package
		requestedPackage := false

		requiresTxtPath := ""

		// in the event the directory entry is itself another directory
		// go into each directory looking for our parsable payload
		// (ie. METADATA and PKG-INFO files)
		if dEntry.IsDir() {
			pythonPackageDir := filepath.Join(path, packagePayload)
			packageDirFiles, err := afs.ReadDir(pythonPackageDir)
			if err != nil {
				// Skip this package and keep the rest of the directory.
				// Container images routinely list entries that cannot be read:
				// a dist-info removed in a later layer still appears in the
				// merged listing but fails to open. Aborting here discarded
				// every other package in the same site-packages, so one stale
				// entry cost an image its entire Python inventory.
				log.Debug().Err(err).Str("dir", pythonPackageDir).Msg("skipping unreadable python package directory")
				continue
			}

			foundMeta := false
			for _, packageFile := range packageDirFiles {
				if packageFile.Name() == "METADATA" || packageFile.Name() == "PKG-INFO" {
					// use the METADATA / PKG-INFO file as our source of python package info
					packagePayload = filepath.Join(dEntry.Name(), packageFile.Name())
					foundMeta = true
				}
				if packageFile.Name() == "REQUESTED" {
					requestedPackage = true
				}
				if packageFile.Name() == "requires.txt" {
					requiresTxtPath = filepath.Join(dEntry.Name(), packageFile.Name())
				}
			}
			if !foundMeta {
				// A .dist-info / .egg-info directory with no METADATA or PKG-INFO
				// is an incomplete install: the metadata was removed in a later
				// container image layer, or the install was interrupted. The
				// directory name still identifies the package, so report it from
				// that rather than dropping it from the inventory.
				if ppd := pythonPackageFromDirName(dEntry.Name(), filepath.Join(path, dEntry.Name())); ppd != nil {
					ppd.IsLeaf = requestedPackage
					allResults = append(allResults, *ppd)
				}
				continue
			}
		}

		pythonPackageFilepath := filepath.Join(path, packagePayload)
		exists, _ := afs.Exists(pythonPackageFilepath)
		if !exists {
			continue
		}

		f, err := newFile(runtime, pythonPackageFilepath)
		if err != nil {
			return nil, err
		}
		content := f.GetContent()
		if content.Error != nil {
			return nil, content.Error
		}
		ppd, err := wheelegg.ParseMIME(strings.NewReader(content.Data), pythonPackageFilepath)
		if err != nil || ppd.Name == "" {
			// Unparsable or nameless metadata -- fall back to the identity in the
			// directory name so a corrupt file does not erase the package.
			ppd = pythonPackageFromDirName(dEntry.Name(), filepath.Join(path, dEntry.Name()))
			if ppd == nil {
				continue
			}
		}
		ppd.IsLeaf = requestedPackage

		// if the MIME data didn't include dependency information, but there was a requires.txt file available,
		// then use that for dependency info (as pip appears to do)
		if len(ppd.Dependencies) == 0 && requiresTxtPath != "" {
			requirementsPath := filepath.Join(path, requiresTxtPath)
			f, err := newFile(runtime, requirementsPath)
			if err != nil {
				return nil, err
			}
			content := f.GetContent()
			if content.Error != nil {
				return nil, content.Error
			}
			requiresTxtDeps, err := requirements.ParseRequiresTxtDependencies(strings.NewReader(content.Data))
			if err != nil {
				log.Warn().Err(err).Str("dir", pythonPackageFilepath).Msg("failed to parse requires.txt")
				return nil, err
			} else {
				ppd.Dependencies = requiresTxtDeps
			}
		}

		allResults = append(allResults, *ppd)
	}

	return allResults, nil
}

func newMqlPythonPackage(runtime *plugin.Runtime, ppd python.PackageDetails) (plugin.Resource, error) {
	f, err := newFile(runtime, ppd.File)
	if err != nil {
		log.Error().Err(err).Msg("error while creating file resource for python package resource")
		return nil, err
	}

	cpes := []any{}
	for i := range ppd.Cpes {
		cpe, err := runtime.CreateSharedResource("cpe", map[string]*llx.RawData{
			"uri": llx.StringData(ppd.Cpes[i]),
		})
		if err != nil {
			return nil, err
		}
		cpes = append(cpes, cpe)
	}

	r, err := CreateResource(runtime, "python.package", map[string]*llx.RawData{
		"id":             llx.StringData(ppd.File),
		"name":           llx.StringData(ppd.Name),
		"version":        llx.StringData(ppd.Version),
		"author":         llx.StringData(ppd.Author),
		"authorEmail":    llx.StringData(ppd.AuthorEmail),
		"summary":        llx.StringData(ppd.Summary),
		"license":        llx.StringData(ppd.License),
		"requiresPython": llx.StringData(ppd.RequiresPython),
		"projectUrls":    llx.MapData(convert.MapToInterfaceMap(ppd.ProjectUrls), types.String),
		"file":           llx.ResourceData(f, f.MqlName()),
		"purl":           llx.StringData(ppd.Purl),
		"cpes":           llx.ArrayData(cpes, types.Resource("cpe")),
	})
	if err != nil {
		log.Error().AnErr("err", err).Msg("error while creating MQL resource")
		return nil, err
	}
	pkg := r.(*mqlPythonPackage)
	pkg.deps = ppd.Dependencies
	pkg.siteDir = pythonPackageSiteDir(ppd.File)
	return r, nil
}

// pythonPackageFromDirName builds package details from a ".dist-info" /
// ".egg-info" entry name when its metadata file cannot be read. It returns nil
// when the name carries no usable identity.
func pythonPackageFromDirName(entry string, file string) *python.PackageDetails {
	name, version := wheelegg.ParseDistInfoName(entry)
	if name == "" {
		return nil
	}
	return &python.PackageDetails{
		Name:    name,
		Version: version,
		File:    file,
		Purl:    python.NewPackageUrl(name, version),
		Cpes:    python.NewCpes(name, version),
	}
}

// pythonPackageSiteDir returns the directory a package was installed into, so
// dependencies can be resolved among its siblings. For an installed package the
// metadata path is "<site>/<name>.dist-info/METADATA", so the site directory is
// two levels up; for a bare ".egg-info" file, and for packages read out of a
// manifest such as requirements.txt, it is the file's own directory.
func pythonPackageSiteDir(file string) string {
	dir := filepath.Dir(file)
	if base := filepath.Base(dir); strings.HasSuffix(base, ".dist-info") || strings.HasSuffix(base, ".egg-info") {
		return filepath.Dir(dir)
	}
	return dir
}

func (r *mqlPythonPackage) id() (string, error) {
	return r.Id.Data, nil
}

func initPythonPackage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in python.package initialization, it must be a string")
		}

		file, err := newFile(runtime, path)
		if err != nil {
			return nil, nil, err
		}

		content := file.GetContent()
		if content.Error != nil {
			return nil, nil, content.Error
		}
		pkg, err := wheelegg.ParseMIME(strings.NewReader(content.Data), file.Path.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing python package data: %s", err)
		}

		// Use newMqlPythonPackage so that deps is populated on the resource
		res, err := newMqlPythonPackage(runtime, *pkg)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	}
	return args, nil, nil
}

type mqlPythonPackageInternal struct {
	deps []string
	// siteDir is the directory this package was installed into. Dependencies are
	// resolved among its siblings only -- see dependencies().
	siteDir string
}

func (r *mqlPythonPackage) dependencies() ([]any, error) {
	obj, err := CreateResource(r.MqlRuntime, "python", nil)
	if err != nil {
		return nil, err
	}
	py := obj.(*mqlPython)
	pkgs := py.GetPackages()
	if pkgs.Error != nil {
		return nil, pkgs.Error
	}

	// A dependency has to be resolved within the environment that declares it. An
	// asset commonly carries the same package in several environments -- a venv
	// per application, one site-packages per interpreter version -- and matching
	// on name alone returns every one of them. That both inflates the list and
	// silently answers questions about the wrong environment: a check asserting
	// "this app pulls in a patched certifi" would pass on some other venv's copy.
	deps := []any{}
	for _, dep := range r.deps {
		for i := range pkgs.Data {
			candidate := pkgs.Data[i].(*mqlPythonPackage)
			if candidate.Name.Data != dep || candidate.siteDir != r.siteDir {
				continue
			}
			deps = append(deps, pkgs.Data[i])
			break
		}
	}
	return deps, nil
}

// pythonManifestFiles maps manifest filenames to their extractor. Lock files
// are listed first so they take priority (checked in order).
var pythonManifestFiles = []struct {
	name      string
	extractor languages.Extractor
}{
	{"Pipfile.lock", &pipfilelock.Extractor{}},
	{"poetry.lock", &poetrylock.Extractor{}},
	{"uv.lock", &uvlock.Extractor{}},
	{"pdm.lock", &pdmlock.Extractor{}},
}

// collectPythonManifestPackages scans a directory for Python source manifest
// files (lock files and requirements.txt) and returns packages found in them.
// It prioritises lock files over requirements.txt to avoid duplicates.
func collectPythonManifestPackages(fs afero.Fs, dir string) []python.PackageDetails {
	afs := &afero.Afero{Fs: fs}

	// Try lock files first — if any succeeds, use it and skip requirements.txt.
	for _, mf := range pythonManifestFiles {
		p := filepath.Join(dir, mf.name)
		f, err := afs.Open(p)
		if err != nil {
			continue
		}
		bom, err := mf.extractor.Parse(f, p)
		f.Close()
		if err != nil {
			log.Debug().Err(err).Str("file", p).Msg("failed to parse python manifest")
			continue
		}
		pkgs := bom.Transitive()
		if len(pkgs) > 0 {
			return languagePackagesToDetails(pkgs, p)
		}
	}

	// Fall back to requirements.txt
	if results := parseRequirementsTxtFile(afs, dir); len(results) > 0 {
		return results
	}

	// Fall back to setup.py / setup.cfg
	for _, name := range []string{"setup.py", "setup.cfg"} {
		if results := parseSetupFile(afs, dir, name); len(results) > 0 {
			return results
		}
	}

	return nil
}

func parseRequirementsTxtFile(afs *afero.Afero, dir string) []python.PackageDetails {
	reqPath := filepath.Join(dir, "requirements.txt")
	f, err := afs.Open(reqPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	reqs, err := requirements.ParseRequirementsTxt(f)
	if err != nil {
		log.Debug().Err(err).Str("file", reqPath).Msg("failed to parse requirements.txt")
		return nil
	}

	var results []python.PackageDetails
	for _, req := range reqs {
		if req.Name == "" {
			continue
		}
		results = append(results, python.PackageDetails{
			Name:    req.Name,
			Version: req.Version,
			File:    reqPath,
			Purl:    python.NewPackageUrl(req.Name, req.Version),
			Cpes:    python.NewCpes(req.Name, req.Version),
			IsLeaf:  true,
		})
	}
	return results
}

func parseSetupFile(afs *afero.Afero, dir, name string) []python.PackageDetails {
	p := filepath.Join(dir, name)
	f, err := afs.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	reqs, err := requirements.ParseSetupPy(f)
	if err != nil {
		log.Debug().Err(err).Str("file", p).Msg("failed to parse setup file")
		return nil
	}

	var results []python.PackageDetails
	for _, req := range reqs {
		if req.Name == "" {
			continue
		}
		results = append(results, python.PackageDetails{
			Name:    req.Name,
			Version: req.Version,
			File:    p,
			Purl:    python.NewPackageUrl(req.Name, req.Version),
			Cpes:    python.NewCpes(req.Name, req.Version),
			IsLeaf:  true,
		})
	}
	return results
}

// languagePackagesToDetails converts languages.Packages to python.PackageDetails.
func languagePackagesToDetails(pkgs languages.Packages, file string) []python.PackageDetails {
	results := make([]python.PackageDetails, 0, len(pkgs))
	for _, pkg := range pkgs {
		results = append(results, python.PackageDetails{
			Name:    pkg.Name,
			Version: pkg.Version,
			File:    file,
			Purl:    pkg.Purl,
			Cpes:    pkg.Cpes,
			License: pkg.License,
			Author:  pkg.Author,
			IsLeaf:  true,
		})
	}
	return results
}

// mergePythonPackages merges two slices of PackageDetails, deduplicating by name.
// Packages from the primary slice take precedence.
func mergePythonPackages(primary, secondary []python.PackageDetails) []python.PackageDetails {
	if len(secondary) == 0 {
		return primary
	}
	// Compare normalized names: installed metadata and manifests spell the same
	// project differently ("ruamel.yaml" vs "ruamel-yaml"), so a plain lowercase
	// key reports one project twice.
	seen := make(map[string]bool, len(primary))
	for _, p := range primary {
		seen[python.NormalizeName(p.Name)] = true
	}
	for _, p := range secondary {
		if !seen[python.NormalizeName(p.Name)] {
			primary = append(primary, p)
			seen[python.NormalizeName(p.Name)] = true
		}
	}
	return primary
}
