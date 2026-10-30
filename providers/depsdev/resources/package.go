// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/depsdev/connection"
)

type mqlDepsdevPackageInternal struct {
	fetched atomic.Bool
	lock    sync.Mutex
}

type mqlDepsdevPackageVersionInternal struct {
	packageName string
	fetched     atomic.Bool
	lock        sync.Mutex
}

type mqlDepsdevRelatedProjectInternal struct {
	projectID string
	versionID string
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
	if r.fetched.Load() {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

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

		// Pass __id explicitly: CreateResource calls id() before packageName is
		// set below, so id() would otherwise build a key with an empty package
		// name and collide across packages that share a version string.
		vid := "depsdev.packageVersion/" + r.Name.Data + "@" + v.VersionKey.Version
		vr, err := CreateResource(r.MqlRuntime, "depsdev.packageVersion", map[string]*llx.RawData{
			"__id":        llx.StringData(vid),
			"version":     llx.StringData(v.VersionKey.Version),
			"publishedAt": llx.TimeData(publishedAt),
			"isDefault":   llx.BoolData(v.IsDefault),
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

	if versionResources == nil {
		versionResources = []any{}
	}
	r.Versions = plugin.TValue[[]any]{Data: versionResources, State: plugin.StateIsSet}

	if latestVer != "" {
		r.LatestVersion = plugin.TValue[string]{Data: latestVer, State: plugin.StateIsSet}
		r.LatestPublished = plugin.TValue[*time.Time]{Data: &latestTime, State: plugin.StateIsSet}
	} else {
		r.LatestVersion = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
		r.LatestPublished = plugin.TValue[*time.Time]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	}

	r.fetched.Store(true)
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

	// Prefer the source repository relation; fall back to the first related
	// project with a non-empty id.
	projectID := ""
	for _, rp := range ver.RelatedProjects {
		if rp.ProjectKey.ID == "" {
			continue
		}
		if rp.RelationType == "SOURCE_REPO" {
			projectID = rp.ProjectKey.ID
			break
		}
		if projectID == "" {
			projectID = rp.ProjectKey.ID
		}
	}

	if projectID == "" {
		r.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "depsdev.project", map[string]*llx.RawData{
		"id": llx.StringData(projectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDepsdevProject), nil
}

// depsdev.packageVersion

func (r *mqlDepsdevPackageVersion) id() (string, error) {
	return "depsdev.packageVersion/" + r.packageName + "@" + r.Version.Data, nil
}

// fetchVersionDetail fetches the version detail from deps.dev and populates
// licenses, links, registries, slsaProvenances, and relatedProjects in one call.
func (r *mqlDepsdevPackageVersion) fetchVersionDetail() error {
	if r.fetched.Load() {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	ver, err := fetchVersion(conn.HttpClient, r.packageName, r.Version.Data)
	if err != nil {
		return err
	}

	licenses := make([]any, 0, len(ver.Licenses))
	for _, l := range ver.Licenses {
		licenses = append(licenses, l)
	}
	r.Licenses = plugin.TValue[[]any]{Data: licenses, State: plugin.StateIsSet}

	links := map[string]any{}
	for _, lk := range ver.Links {
		if lk.Label == "" {
			continue
		}
		links[lk.Label] = lk.URL
	}
	r.Links = plugin.TValue[map[string]any]{Data: links, State: plugin.StateIsSet}

	registries := make([]any, 0, len(ver.Registries))
	for _, rg := range ver.Registries {
		registries = append(registries, rg)
	}
	r.Registries = plugin.TValue[[]any]{Data: registries, State: plugin.StateIsSet}

	provenances := make([]any, 0, len(ver.SlsaProvenances))
	for _, p := range ver.SlsaProvenances {
		provenances = append(provenances, map[string]any{
			"sourceRepository": p.SourceRepository,
			"commit":           p.Commit,
			"url":              p.URL,
			"verified":         p.Verified,
		})
	}
	r.SlsaProvenances = plugin.TValue[[]any]{Data: provenances, State: plugin.StateIsSet}

	versionID := r.packageName + "@" + r.Version.Data
	related := make([]any, 0, len(ver.RelatedProjects))
	for _, rp := range ver.RelatedProjects {
		// Pass __id explicitly: CreateResource calls id() before the Internal
		// fields below are set, so id() cannot build the key from them.
		id := "depsdev.relatedProject/" + versionID + "/" + rp.RelationType + "/" + rp.ProjectKey.ID
		res, err := CreateResource(r.MqlRuntime, "depsdev.relatedProject", map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"relationType":       llx.StringData(rp.RelationType),
			"relationProvenance": llx.StringData(rp.RelationProvenance),
		})
		if err != nil {
			return err
		}
		mqlRp := res.(*mqlDepsdevRelatedProject)
		mqlRp.projectID = rp.ProjectKey.ID
		mqlRp.versionID = versionID
		related = append(related, res)
	}
	r.RelatedProjects = plugin.TValue[[]any]{Data: related, State: plugin.StateIsSet}

	r.fetched.Store(true)
	return nil
}

func (r *mqlDepsdevPackageVersion) licenses() ([]any, error) {
	return nil, r.fetchVersionDetail()
}

func (r *mqlDepsdevPackageVersion) links() (map[string]any, error) {
	return nil, r.fetchVersionDetail()
}

func (r *mqlDepsdevPackageVersion) registries() ([]any, error) {
	return nil, r.fetchVersionDetail()
}

func (r *mqlDepsdevPackageVersion) slsaProvenances() ([]any, error) {
	return nil, r.fetchVersionDetail()
}

func (r *mqlDepsdevPackageVersion) relatedProjects() ([]any, error) {
	return nil, r.fetchVersionDetail()
}

// depsdev.relatedProject

func (r *mqlDepsdevRelatedProject) id() (string, error) {
	return "depsdev.relatedProject/" + r.versionID + "/" + r.RelationType.Data + "/" + r.projectID, nil
}

func (r *mqlDepsdevRelatedProject) project() (*mqlDepsdevProject, error) {
	if r.projectID == "" {
		r.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "depsdev.project", map[string]*llx.RawData{
		"id": llx.StringData(r.projectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDepsdevProject), nil
}
