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
	"go.mondoo.com/mql/providers/os/resources/languages/ruby/gemfilelock"
	"go.mondoo.com/mql/providers/os/resources/languages/ruby/gemspec"
	"go.mondoo.com/mql/types"
)

var defaultRubyPaths = []string{
	"/app",
	"/usr/src/app",
	"/home/*/app",
	"/var/www",
}

func initRubyPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in ruby.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlRubyPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "ruby.packages/" + r.Path.Data, nil
	}
	return "ruby.packages", nil
}

type mqlRubyPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlRubyPackages) gatherData() error {
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
		collectedRoot, d, t, f := collectRubyPackages(afs, fs, path)
		if collectedRoot != nil {
			root = collectedRoot
		}
		directDeps = append(directDeps, d...)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		for _, searchPath := range defaultRubyPaths {
			// Expand glob wildcards
			matches, err := afero.Glob(fs, searchPath)
			if err != nil {
				continue
			}
			if len(matches) == 0 {
				if strings.ContainsAny(searchPath, "*?[") {
					continue
				}
				matches = []string{searchPath}
			}
			for _, match := range matches {
				collectedRoot, d, t, f := collectRubyPackages(afs, fs, match)
				if collectedRoot != nil && root == nil {
					root = collectedRoot
				}
				directDeps = append(directDeps, d...)
				transitiveDeps = append(transitiveDeps, t...)
				filePaths = append(filePaths, f...)
			}
		}
	}

	slices.SortFunc(directDeps, languages.SortFn)

	// Set root (available from gemspec, nil from Gemfile.lock)
	if root != nil {
		mqlPkg, err := newRubyPackage(r.MqlRuntime, root)
		if err != nil {
			return err
		}
		r.Root = plugin.TValue[*mqlRubyPackage]{Data: mqlPkg, State: plugin.StateIsSet}
	} else {
		r.Root = plugin.TValue[*mqlRubyPackage]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Set list — Transitive() already returns all resolved gems (including direct ones)
	slices.SortFunc(transitiveDeps, languages.SortFn)
	allResources, err := newRubyPackageList(r.MqlRuntime, transitiveDeps)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	// Set direct
	directResources, err := newRubyPackageList(r.MqlRuntime, directDeps)
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

func collectRubyPackages(afs *afero.Afero, fs afero.Fs, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not check Ruby path")
		return nil, nil, nil, nil
	}

	if isDir {
		// Prefer Gemfile.lock or gems.locked (resolved versions)
		for _, lockName := range []string{"Gemfile.lock", "gems.locked"} {
			lockPath := filepath.Join(path, lockName)
			if exists, _ := afs.Exists(lockPath); exists {
				return collectFromGemfileLock(afs, lockPath)
			}
		}

		// Fall back to .gemspec files
		entries, err := afs.ReadDir(path)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".gemspec") {
					return collectFromGemspec(afs, filepath.Join(path, entry.Name()))
				}
			}
		}

		return nil, nil, nil, nil
	}

	if strings.HasSuffix(path, "Gemfile.lock") || strings.HasSuffix(path, "gems.locked") {
		return collectFromGemfileLock(afs, path)
	}
	if strings.HasSuffix(path, ".gemspec") {
		return collectFromGemspec(afs, path)
	}

	return nil, nil, nil, nil
}

func collectFromGemfileLock(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open Gemfile.lock")
		return nil, nil, nil, nil
	}
	defer f.Close()

	extractor := &gemfilelock.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse Gemfile.lock")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func collectFromGemspec(afs *afero.Afero, path string) (*languages.Package, []*languages.Package, []*languages.Package, []string) {
	f, err := afs.Open(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not open gemspec")
		return nil, nil, nil, nil
	}
	defer f.Close()

	extractor := &gemspec.Extractor{}
	bom, err := extractor.Parse(f, path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse gemspec")
		return nil, nil, nil, nil
	}

	return bom.Root(), bom.Direct(), bom.Transitive(), []string{path}
}

func (r *mqlRubyPackages) root() (*mqlRubyPackage, error) {
	return nil, r.gatherData()
}

func (r *mqlRubyPackages) directDependencies() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlRubyPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlRubyPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newRubyPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newRubyPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newRubyPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlRubyPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "ruby.package", map[string]*llx.RawData{
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
	return mqlPkg.(*mqlRubyPackage), nil
}

func (k *mqlRubyPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlRubyPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlRubyPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlRubyPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlRubyPackage) cpes() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlRubyPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlRubyPackage) populateData() error {
	return errors.New("ruby.package can only be created via ruby.packages")
}
