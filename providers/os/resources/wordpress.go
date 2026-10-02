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
	"go.mondoo.com/mql/providers/os/resources/languages/wordpress"
	"go.mondoo.com/mql/types"
)

// defaultWordPressPluginPaths are searched for WordPress plugin directories.
var defaultWordPressPluginPaths = []string{
	// SUSE's Apache document root, with WordPress in it or in a subdirectory
	"/srv/www/htdocs/wp-content/plugins",
	"/srv/www/htdocs/wordpress/wp-content/plugins",
	"/var/www/html/wp-content/plugins",
	"/var/www/wordpress/wp-content/plugins",
	"/usr/share/wordpress/wp-content/plugins",
}

func initWordpressPackages(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		_, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in wordpress.packages initialization, it must be a string")
		}
	} else {
		args["path"] = llx.StringData("")
	}
	return args, nil, nil
}

func (r *mqlWordpressPackages) id() (string, error) {
	if r.Path.Data != "" {
		return "wordpress.packages/" + r.Path.Data, nil
	}
	return "wordpress.packages", nil
}

type mqlWordpressPackagesInternal struct {
	mutex   sync.Mutex
	fetched bool
}

func (r *mqlWordpressPackages) gatherData() error {
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

	var allPlugins []wordpress.WordPressPlugin
	var filePaths []string

	if path != "" {
		plugins, err := wordpress.ScanPluginDir(afs, path)
		if err == nil {
			allPlugins = append(allPlugins, plugins...)
			if len(plugins) > 0 {
				filePaths = append(filePaths, path)
			}
		}
	} else {
		for _, searchPath := range defaultWordPressPluginPaths {
			if exists, _ := afs.DirExists(searchPath); !exists {
				continue
			}
			plugins, err := wordpress.ScanPluginDir(afs, searchPath)
			if err == nil {
				allPlugins = append(allPlugins, plugins...)
				if len(plugins) > 0 {
					filePaths = append(filePaths, searchPath)
				}
			}
		}
	}

	// Build MQL resources
	mqlPkgs := make([]any, len(allPlugins))
	for i, p := range allPlugins {
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

		mqlPkg, err := CreateResource(r.MqlRuntime, "wordpress.package", map[string]*llx.RawData{
			"__id":        llx.StringData("wordpress.package/" + p.Slug + "@" + p.Version),
			"name":        llx.StringData(p.Slug),
			"version":     llx.StringData(p.Version),
			"purl":        llx.StringData(wordpress.NewPackageUrl(p.Slug, p.Version)),
			"displayName": llx.StringData(p.DisplayName),
			"license":     llx.StringData(p.License),
			"requiresWp":  llx.StringData(p.RequiresWp),
			"testedUpTo":  llx.StringData(p.TestedUpTo),
			"files":       llx.ArrayData(mqlFiles, types.Resource("pkgFileInfo")),
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

func (r *mqlWordpressPackages) list() ([]any, error) {
	return nil, r.gatherData()
}

func (r *mqlWordpressPackages) files() ([]any, error) {
	return nil, r.gatherData()
}
