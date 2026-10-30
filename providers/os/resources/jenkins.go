// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/languages/jenkins"
	"go.mondoo.com/mql/types"
)

// defaultJenkinsPluginPaths are searched for Jenkins plugin files.
var defaultJenkinsPluginPaths = []string{
	"/var/lib/jenkins/plugins",
	"/var/jenkins_home/plugins",
}

func initJenkinsPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in jenkins.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlJenkinsPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "jenkins.packages/" + r.Path.Data, nil
	}
	return "jenkins.packages", nil
}

type mqlJenkinsPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlJenkinsPackages) gatherData() error {
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

	path := r.Path.Data

	var allPlugins []jenkins.JenkinsPlugin
	var filePaths []string

	if path != "" {
		plugins, err := jenkins.ScanPluginDirExtended(afs, path)
		if err == nil {
			allPlugins = append(allPlugins, plugins...)
			if len(plugins) > 0 {
				filePaths = append(filePaths, path)
			}
		}
	} else {
		for _, searchPath := range defaultJenkinsPluginPaths {
			if exists, _ := afs.DirExists(searchPath); !exists {
				continue
			}
			plugins, err := jenkins.ScanPluginDirExtended(afs, searchPath)
			if err == nil {
				allPlugins = append(allPlugins, plugins...)
				if len(plugins) > 0 {
					filePaths = append(filePaths, searchPath)
				}
			}
		}
	}

	// Build MQL resources with full metadata
	mqlPkgs := make([]any, len(allPlugins))
	for i, p := range allPlugins {
		deps := make([]any, len(p.Dependencies))
		for j, d := range p.Dependencies {
			deps[j] = d
		}

		mqlFiles := []any{}
		if p.FilePath != "" {
			lf, err := CreateResource(r.MqlRuntime, "pkgFileInfo", map[string]*llx.RawData{
				"path": llx.StringData(p.FilePath),
			})
			if err != nil {
				return err
			}
			mqlFiles = append(mqlFiles, lf)
		}

		mqlPkg, err := CreateResource(r.MqlRuntime, "jenkins.package", map[string]*llx.RawData{
			"__id":         llx.StringData(jenkinsPackageID(p)),
			"name":         llx.StringData(p.Name),
			"version":      llx.StringData(p.Version),
			"purl":         llx.StringData(jenkins.NewPackageUrl(p.Name, p.Version)),
			"longName":     llx.StringData(p.LongName),
			"url":          llx.StringData(p.Url),
			"dependencies": llx.ArrayData(deps, types.String),
			"files":        llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
		})
		if err != nil {
			return err
		}
		mqlPkgs[i] = mqlPkg
	}
	r.List = plugin.TValue[[]any]{Data: mqlPkgs, State: plugin.StateIsSet}

	// Set evidence files
	mqlFiles := []any{}
	for _, fp := range filePaths {
		lf, err := CreateResource(r.MqlRuntime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(fp),
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

func (r *mqlJenkinsPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlJenkinsPackages) files() ([]any, error) {
	return nil, r.gatherData()
}

// jenkinsPackageID is the cache key of one jenkins.package. Two plugin
// directories can hold the same plugin at the same version, so the plugin file
// is part of the key; without it, a scan of the second directory returned the
// first directory's resource and its files.
func jenkinsPackageID(p jenkins.JenkinsPlugin) string {
	return "jenkins.package/" + p.Name + "@" + p.Version + ":" + p.FilePath
}
