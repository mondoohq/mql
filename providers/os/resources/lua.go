// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/lua/luarocks"
	"go.mondoo.com/mql/types"
)

// System rock trees. A rock tree keeps its installed rocks under
// lib/luarocks/rocks (LuaRocks 2.x, every Lua version together) or
// lib/luarocks/rocks-<lua version> (LuaRocks 3.x).
var defaultLuaRocksSystemTrees = []string{
	"/usr/local",
	"/usr",
}

// Per-user rock trees (`luarocks --local`). `luarocks list` reports only the
// trees of the user running it, so these are always read from disk.
var defaultLuaRocksUserTreeGlobs = []string{
	"/root/.luarocks",
	"/home/*/.luarocks",
}

func initLuaPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in lua.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlLuaPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "lua.packages/" + r.Path.Data, nil
	}
	return "lua.packages", nil
}

type mqlLuaPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlLuaPackages) gatherData() error {
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

	searchPath := r.Path.Data

	var transitiveDeps []*languages.Package
	var filePaths []string

	if searchPath != "" {
		t, f := collectLuaPackages(afs, searchPath)
		transitiveDeps = append(transitiveDeps, t...)
		filePaths = append(filePaths, f...)
	} else {
		// The CLI also reports rocks in trees configured outside the
		// default locations; the rock trees on disk are added to it.
		if conn.Capabilities().Has(shared.Capability_RunCommand) {
			cmd, err := conn.RunCommand("luarocks list --porcelain")
			if err == nil && cmd.ExitStatus == 0 {
				pkgs, fps := luarocks.ParseLuaRocksList(cmd.Stdout, "")
				transitiveDeps = append(transitiveDeps, pkgs...)
				filePaths = append(filePaths, luaRocksListFiles(afs, fps)...)
			} else {
				exitStatus := -1
				if cmd != nil {
					exitStatus = cmd.ExitStatus
				}
				log.Debug().Err(err).Int("exitStatus", exitStatus).Msg("mql[lua]> luarocks list failed, reading the rock trees from disk only")
			}
		}

		transitiveDeps, filePaths = addDefaultLuaRockTrees(afs, transitiveDeps, filePaths)
	}

	slices.SortFunc(transitiveDeps, languages.SortFn)

	allResources, err := newLuaPackageList(r.MqlRuntime, transitiveDeps)
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

// luaRocksListFiles returns the files of the rocks `luarocks list` reported,
// given their version directories: the rockspec, or the rock_manifest, which
// is what a rock read from disk reports. A directory with neither keeps its
// own name.
func luaRocksListFiles(afs *afero.Afero, versionDirs []string) []string {
	out := make([]string, len(versionDirs))
	for i, dir := range versionDirs {
		out[i] = dir
		if f := luarocks.RockEvidence(afs, dir); f != "" {
			out[i] = f
		}
	}
	return out
}

// addDefaultLuaRockTrees adds the rocks of the system trees and every user's
// tree, read from disk, to what `luarocks list` reported. The CLI is not
// enough on its own: it lists the rocks of one Lua version (on RHEL and
// Fedora, rocks for compat-lua 5.1 in /usr/lib/luarocks/rocks-5.1 are missing
// from a list for 5.4) and only the trees of the user running it.
func addDefaultLuaRockTrees(afs *afero.Afero, pkgs []*languages.Package, filePaths []string) ([]*languages.Package, []string) {
	trees := append([]string{}, defaultLuaRocksSystemTrees...)
	for _, pattern := range defaultLuaRocksUserTreeGlobs {
		matches, err := afero.Glob(afs, pattern)
		if err != nil {
			log.Debug().Err(err).Str("pattern", pattern).Msg("mql[lua]> could not search for per-user rock trees")
			continue
		}
		trees = append(trees, matches...)
	}
	return addLuaRockTrees(afs, pkgs, filePaths, trees)
}

// addLuaRockTrees adds the rocks of each tree to pkgs, skipping a rock already
// listed with the same version directory: the CLI reports the trees of the
// user running it, and those are read from disk again here.
func addLuaRockTrees(afs *afero.Afero, pkgs []*languages.Package, filePaths []string, trees []string) ([]*languages.Package, []string) {
	seen := map[string]struct{}{}
	for _, pkg := range pkgs {
		if len(pkg.EvidenceList) > 0 {
			seen[pkg.EvidenceList[0].Value] = struct{}{}
		}
	}
	for _, tree := range trees {
		treePkgs, treeFps := collectLuaRockTree(afs, tree)
		for i, pkg := range treePkgs {
			// ParseRocksDir gives every rock its version directory as
			// evidence; a rock without one has nothing to dedupe by.
			if len(pkg.EvidenceList) > 0 {
				if _, ok := seen[pkg.EvidenceList[0].Value]; ok {
					continue
				}
				seen[pkg.EvidenceList[0].Value] = struct{}{}
			}
			pkgs = append(pkgs, pkg)
			filePaths = append(filePaths, treeFps[i])
		}
	}
	return pkgs, filePaths
}

// collectLuaPackages reads the rocks under searchPath, which may be a rocks
// directory itself (/usr/local/lib/luarocks/rocks-5.1), the directory holding
// the rocks directories (/usr/local/lib/luarocks), or a rock tree (/usr/local,
// ~/.luarocks).
//
// The forms that name their rocks directories are tried before reading
// searchPath as a rocks directory: that reads every directory two levels
// down, which for a rock tree such as /usr means all of /usr/lib64 and
// /usr/share, a stat per entry, and minutes over SSH with --sudo.
func collectLuaPackages(afs *afero.Afero, searchPath string) ([]*languages.Package, []string) {
	isDir, err := afs.IsDir(searchPath)
	if err != nil || !isDir {
		return nil, nil
	}

	if isRocksDirName(path.Base(searchPath)) {
		if pkgs, fps := luarocks.ParseRocksDir(afs, searchPath); len(pkgs) > 0 {
			return pkgs, fps
		}
	}

	if pkgs, fps := collectRocksDirsIn(afs, searchPath); len(pkgs) > 0 {
		return pkgs, fps
	}

	if pkgs, fps := collectLuaRockTree(afs, searchPath); len(pkgs) > 0 {
		return pkgs, fps
	}

	// a rocks directory under another name
	if !looksLikeRocksDir(afs, searchPath) {
		return nil, nil
	}
	return luarocks.ParseRocksDir(afs, searchPath)
}

// looksLikeRocksDir reports whether dir, which LuaRocks did not name, holds
// rocks: it has the manifest LuaRocks writes into every rocks directory, or
// each of its directories is a rock, which holds version directories that have
// a rockspec or rock_manifest. It stops at the first directory that is not a
// rock, so a rock tree without rocks of its own, such as Amazon Linux's /usr
// with LuaRocks in /usr/local, costs a listing of the tree and of its first
// directory instead of a read of every directory two levels down.
func looksLikeRocksDir(afs *afero.Afero, dir string) bool {
	if ok, _ := afs.Exists(path.Join(dir, "manifest")); ok {
		return true
	}
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return false
	}
	found := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !isRock(afs, path.Join(dir, entry.Name())) {
			return false
		}
		found = true
	}
	return found
}

// isRock reports whether the first entry of a rock's directory is a version
// directory that holds an installed rock. It lists the entry names only: over
// SSH with --sudo, reading a directory's entries stats each of them, which for
// /usr/bin is a command per program.
func isRock(afs *afero.Afero, rockDir string) bool {
	f, err := afs.Open(rockDir)
	if err != nil {
		return false
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil || len(names) == 0 {
		return false
	}
	slices.Sort(names)
	versionDir := path.Join(rockDir, names[0])
	if isDir, err := afs.IsDir(versionDir); err != nil || !isDir {
		return false
	}
	return luarocks.RockEvidence(afs, versionDir) != ""
}

// collectLuaRockTree reads every rocks directory of the rock tree rooted at
// tree.
func collectLuaRockTree(afs *afero.Afero, tree string) ([]*languages.Package, []string) {
	// path.Join (not filepath.Join) — always Linux paths
	return collectRocksDirsIn(afs, path.Join(tree, "lib", "luarocks"))
}

// collectRocksDirsIn reads the rocks directories directly inside dir: "rocks"
// (LuaRocks 2.x) and "rocks-<lua version>" (LuaRocks 3.x).
func collectRocksDirsIn(afs *afero.Afero, dir string) ([]*languages.Package, []string) {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var allPkgs []*languages.Package
	var allFps []string
	for _, entry := range entries {
		if !entry.IsDir() || !isRocksDirName(entry.Name()) {
			continue
		}
		pkgs, fps := luarocks.ParseRocksDir(afs, path.Join(dir, entry.Name()))
		allPkgs = append(allPkgs, pkgs...)
		allFps = append(allFps, fps...)
	}
	return allPkgs, allFps
}

func isRocksDirName(name string) bool {
	return name == "rocks" || strings.HasPrefix(name, "rocks-")
}

func (r *mqlLuaPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlLuaPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newLuaPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newLuaPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newLuaPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlLuaPackage, error) {
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

	mqlPkg, err := CreateResource(runtime, "lua.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlLuaPackage), nil
}

func (k *mqlLuaPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlLuaPackage) name() (string, error) {
	return "", r.populateData()
}

func (r *mqlLuaPackage) version() (string, error) {
	return "", r.populateData()
}

func (r *mqlLuaPackage) purl() (string, error) {
	return "", r.populateData()
}

func (r *mqlLuaPackage) files() ([]any, error) {
	return nil, r.populateData()
}

func (r *mqlLuaPackage) populateData() error {
	return errors.New("lua.package can only be created via lua.packages")
}
