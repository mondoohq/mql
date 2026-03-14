// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"time"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/depsdev/connection"
)

type mqlDepsdevPackageInternal struct {
	fetched bool
	lock    sync.Mutex
}

type mqlDepsdevPackageVersionInternal struct {
	packageName string
}

func initDepsdevPackage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["name"]; !ok {
		return nil, nil, errors.New("missing required argument 'name'")
	}

	// Set currentVersion to empty string if not provided (e.g. when querying a single package)
	if _, ok := args["currentVersion"]; !ok {
		args["currentVersion"] = llx.StringData("")
	}

	return args, nil, nil
}

func (r *mqlDepsdevPackage) id() (string, error) {
	return "depsdev.package/" + r.Name.Data, nil
}

// fetchPackageInfo fetches all version data from deps.dev and populates
// versions, latestVersion, and latestPublished in one call.
func (r *mqlDepsdevPackage) fetchPackageInfo() error {
	if r.fetched {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched {
		return nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	// Set defaults
	r.Versions = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	r.LatestVersion = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	r.LatestPublished = plugin.TValue[*time.Time]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}

	pkg, err := fetchPackage(conn.HttpClient, r.Name.Data)
	if err != nil {
		return err
	}

	// Build version resources and find latest
	var latestTime time.Time
	var latestVer string
	var versionResources []any

	for _, v := range pkg.Versions {
		publishedAt := v.PublishedAt

		vr, err := CreateResource(r.MqlRuntime, "depsdev.packageVersion", map[string]*llx.RawData{
			"version":     llx.StringData(v.VersionKey.Version),
			"publishedAt": llx.TimeData(publishedAt),
			"isDefault":   llx.BoolData(v.IsDefault),
			"licenses":    llx.ArrayData([]any{}, "\x09"), // licenses are not in the package endpoint
		})
		if err != nil {
			return err
		}
		mqlVr := vr.(*mqlDepsdevPackageVersion)
		mqlVr.packageName = r.Name.Data
		versionResources = append(versionResources, vr)

		if publishedAt.After(latestTime) {
			latestTime = publishedAt
			latestVer = v.VersionKey.Version
		}
	}

	r.Versions = plugin.TValue[[]any]{Data: versionResources, State: plugin.StateIsSet}

	if latestVer != "" {
		r.LatestVersion = plugin.TValue[string]{Data: latestVer, State: plugin.StateIsSet}
		r.LatestPublished = plugin.TValue[*time.Time]{Data: &latestTime, State: plugin.StateIsSet}
	}

	r.fetched = true
	return nil
}

func (r *mqlDepsdevPackage) versions() ([]any, error) {
	return nil, r.fetchPackageInfo()
}

func (r *mqlDepsdevPackage) latestVersion() (string, error) {
	return "", r.fetchPackageInfo()
}

func (r *mqlDepsdevPackage) latestPublished() (*time.Time, error) {
	return nil, r.fetchPackageInfo()
}

func (r *mqlDepsdevPackage) project() (*mqlDepsdevProject, error) {
	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	// We need a version to look up the related project.
	// Use the latest version if available, otherwise the current version from go.mod.
	version := r.CurrentVersion.Data
	if r.LatestVersion.State == plugin.StateIsSet && r.LatestVersion.Data != "" {
		version = r.LatestVersion.Data
	}

	if version == "" {
		// Trigger fetch to get the latest version
		if err := r.fetchPackageInfo(); err != nil {
			return nil, err
		}
		version = r.LatestVersion.Data
	}

	if version == "" {
		r.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	ver, err := fetchVersion(conn.HttpClient, r.Name.Data, version)
	if err != nil {
		return nil, err
	}

	// Find the first related project
	for _, rp := range ver.RelatedProjects {
		projectID := rp.ProjectKey.ID
		if projectID == "" {
			continue
		}

		res, err := NewResource(r.MqlRuntime, "depsdev.project", map[string]*llx.RawData{
			"id": llx.StringData(projectID),
		})
		if err != nil {
			return nil, err
		}
		return res.(*mqlDepsdevProject), nil
	}

	r.Project.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// depsdev.packageVersion

func (r *mqlDepsdevPackageVersion) id() (string, error) {
	return "depsdev.packageVersion/" + r.packageName + "@" + r.Version.Data, nil
}
