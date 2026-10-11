// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"slices"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/prolog/packpl"
	"go.mondoo.com/mql/types"
)

func initPrologPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if _, ok := x.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'path' in prolog.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlPrologPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "prolog.packages/" + r.Path.Data, nil
	}
	return "prolog.packages", nil
}

// defaultPrologPackDirs are the directories SWI-Prolog installs packs into
// for every user: /usr/lib/swi-prolog/pack, and the pack directory under each
// common_app_data directory ($XDG_DATA_DIRS, /usr/local/share and /usr/share
// by default), which is where pack_install puts a pack when root runs it.
var defaultPrologPackDirs = []string{
	"/usr/lib/swi-prolog/pack",
	"/usr/local/share/swi-prolog/pack",
	"/usr/share/swi-prolog/pack",
}

// scanPrologPackDirs reads the packs in each directory and returns them with
// the directories that held at least one pack.
func scanPrologPackDirs(afs *afero.Afero, dirs []string) ([]packpl.PrologPack, []string) {
	var packs []packpl.PrologPack
	var found []string
	for _, dir := range dirs {
		// ScanPackDir does not fail, an unreadable directory has no packs
		dirPacks, _ := packpl.ScanPackDir(afs, dir)
		if len(dirPacks) == 0 {
			continue
		}
		packs = append(packs, dirPacks...)
		found = append(found, dir)
	}
	return packs, found
}

type mqlPrologPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlPrologPackages) gatherData() error {
	if r.fetched {
		return nil
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.fetched {
		return nil
	}

	conn := r.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	var packs []packpl.PrologPack
	var packDirs []string
	if r.Path.Data == "" {
		packs, packDirs = scanPrologPackDirs(afs, defaultPrologPackDirs)
	} else {
		var err error
		packs, err = packpl.ScanPackDir(afs, r.Path.Data)
		if err != nil {
			return err
		}
		if len(packs) > 0 {
			packDirs = []string{r.Path.Data}
		}
	}
	pkgs := packpl.ToPackages(packs)
	slices.SortFunc(pkgs, languages.SortFn)

	allResources, err := newPrologPackageList(r.MqlRuntime, pkgs)
	if err != nil {
		return err
	}
	r.List = plugin.TValue[[]any]{Data: allResources, State: plugin.StateIsSet}

	mqlFiles := []any{}
	for _, dir := range packDirs {
		lf, err := CreateResource(r.MqlRuntime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(dir),
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

func (r *mqlPrologPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlPrologPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

func newPrologPackageList(runtime *plugin.Runtime, packages []*languages.Package) ([]any, error) {
	resources := []any{}
	for i := range packages {
		pkg, err := newPrologPackage(runtime, packages[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, pkg)
	}
	return resources, nil
}

func newPrologPackage(runtime *plugin.Runtime, pkg *languages.Package) (*mqlPrologPackage, error) {
	mqlFiles := []any{}
	for i := range pkg.EvidenceList {
		lf, err := CreateResource(runtime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(pkg.EvidenceList[i].Value),
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

	mqlPkg, err := CreateResource(runtime, "prolog.package", map[string]*llx.RawData{
		"id":      llx.StringData(pkg.Name + "@" + pkg.Version + ":" + path),
		"name":    llx.StringData(pkg.Name),
		"version": llx.StringData(pkg.Version),
		"purl":    llx.StringData(pkg.Purl),
		"files":   llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
	})
	if err != nil {
		return nil, err
	}
	return mqlPkg.(*mqlPrologPackage), nil
}

func (k *mqlPrologPackage) id() (string, error) {
	return k.Id.Data, nil
}

func (r *mqlPrologPackage) name() (string, error)    { return "", r.populateData() }
func (r *mqlPrologPackage) version() (string, error) { return "", r.populateData() }
func (r *mqlPrologPackage) purl() (string, error)    { return "", r.populateData() }
func (r *mqlPrologPackage) files() ([]any, error)    { return nil, r.populateData() }
func (r *mqlPrologPackage) populateData() error {
	return errors.New("prolog.package can only be created via prolog.packages")
}
