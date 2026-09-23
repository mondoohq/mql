// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// id() methods
// -----------------------------------------------------------------------------

func (r *mqlGitlabProjectContainerRegistryRepository) id() (string, error) {
	return "gitlab.project.containerRegistryRepository/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (t *mqlGitlabProjectContainerRegistryRepositoryTag) id() (string, error) {
	return "gitlab.project.containerRegistryRepository.tag/" + t.Path.Data + ":" + t.Name.Data, nil
}

func (r *mqlGitlabProjectContainerRegistryProtectionRule) id() (string, error) {
	return "gitlab.project.containerRegistryProtectionRule/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (p *mqlGitlabProjectPackage) id() (string, error) {
	return "gitlab.project.package/" + strconv.FormatInt(p.Id.Data, 10), nil
}

func (f *mqlGitlabProjectPackageFile) id() (string, error) {
	return "gitlab.project.package.file/" + strconv.FormatInt(f.Id.Data, 10), nil
}

func (r *mqlGitlabProjectPackageProtectionRule) id() (string, error) {
	return "gitlab.project.packageProtectionRule/" + strconv.FormatInt(r.Id.Data, 10), nil
}

// -----------------------------------------------------------------------------
// Internal structs cache the parent projectID for typed back-refs when the
// row came in via a group-level rollup (where the parent isn't the calling
// project).
// -----------------------------------------------------------------------------

type mqlGitlabProjectContainerRegistryRepositoryInternal struct {
	containerRepoProjectID int64
}

type mqlGitlabProjectContainerExpirationPolicyInternal struct {
	containerExpirationProjectID int64
}

type mqlGitlabProjectPackageInternal struct {
	packageProjectID int64
}

// -----------------------------------------------------------------------------
// Container registry repositories
// -----------------------------------------------------------------------------

// containerRegistryRepositories lists the project's container registry
// repositories. Returns an empty list on 403/404 — projects without
// container registry enabled, or tokens without registry scope, should
// not fail the whole resource graph.
func (p *mqlGitlabProject) containerRegistryRepositories() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)
	var all []*gitlab.RegistryRepository
	page := int64(1)
	for {
		repos, resp, err := conn.Client().ContainerRegistry.ListProjectRegistryRepositories(projectID,
			&gitlab.ListProjectRegistryRepositoriesOptions{
				ListOptions: gitlab.ListOptions{Page: page, PerPage: 50},
				// GitLab omits tags_count unless it is requested, and the SDK
				// models it as a plain int64 — without this every repository
				// reports tagsCount: 0.
				TagsCount: gitlab.Ptr(true),
			})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, repos...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return containerReposToMqlResources(p.MqlRuntime, all, p.Id.Data, true)
}

func (g *mqlGitlabGroup) containerRegistryRepositories() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)
	var all []*gitlab.RegistryRepository
	page := int64(1)
	for {
		repos, resp, err := conn.Client().ContainerRegistry.ListGroupRegistryRepositories(groupID,
			&gitlab.ListGroupRegistryRepositoriesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 50}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, repos...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return containerReposToMqlResources(g.MqlRuntime, all, 0, false)
}

// containerReposToMqlResources maps SDK RegistryRepository values to MQL
// resources. When parentProjectID is 0 (group rollup), the per-row ProjectID
// is used; otherwise the parent project's ID overrides — both are correct
// since the SDK populates ProjectID consistently.
func containerReposToMqlResources(runtime *plugin.Runtime, repos []*gitlab.RegistryRepository, parentProjectID int64, hasTagsCount bool) ([]any, error) {
	out := make([]any, 0, len(repos))
	for _, r := range repos {
		ownerProjectID := parentProjectID
		if ownerProjectID == 0 {
			ownerProjectID = r.ProjectID
		}
		status := ""
		if r.Status != nil {
			status = string(*r.Status)
		}
		// The group-level list endpoint has no tags_count parameter in the
		// SDK's options struct, so we cannot ask for the value there. Report
		// null rather than the decoded zero, which would claim every
		// repository in the group holds no tags.
		tagsCount := llx.NilData
		if hasTagsCount {
			tagsCount = llx.IntData(r.TagsCount)
		}
		args := map[string]*llx.RawData{
			"id":                     llx.IntData(r.ID),
			"name":                   llx.StringData(r.Name),
			"path":                   llx.StringData(r.Path),
			"location":               llx.StringData(r.Location),
			"createdAt":              llx.TimeDataPtr(r.CreatedAt),
			"cleanupPolicyStartedAt": llx.TimeDataPtr(r.CleanupPolicyStartedAt),
			"tagsCount":              tagsCount,
			"status":                 llx.StringData(status),
		}
		res, err := CreateResource(runtime, "gitlab.project.containerRegistryRepository", args)
		if err != nil {
			return nil, err
		}
		mqlRepo := res.(*mqlGitlabProjectContainerRegistryRepository)
		mqlRepo.containerRepoProjectID = ownerProjectID
		out = append(out, mqlRepo)
	}
	return out, nil
}

// tags fetches the tags for a single container repository.
func (r *mqlGitlabProjectContainerRegistryRepository) tags() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.GitLabConnection)
	repoID := r.Id.Data
	projectID := int(r.containerRepoProjectID)

	page := int64(1)
	var all []*gitlab.RegistryRepositoryTag
	for {
		tags, resp, err := conn.Client().ContainerRegistry.ListRegistryRepositoryTags(projectID, repoID,
			&gitlab.ListRegistryRepositoryTagsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, tags...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	out := make([]any, 0, len(all))
	for _, t := range all {
		args := map[string]*llx.RawData{
			"name":          llx.StringData(t.Name),
			"path":          llx.StringData(t.Path),
			"location":      llx.StringData(t.Location),
			"digest":        llx.StringData(t.Digest),
			"revision":      llx.StringData(t.Revision),
			"shortRevision": llx.StringData(t.ShortRevision),
			"totalSize":     llx.IntData(t.TotalSize),
			"createdAt":     llx.TimeDataPtr(t.CreatedAt),
		}
		mqlTag, err := CreateResource(r.MqlRuntime, "gitlab.project.containerRegistryRepository.tag", args)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlTag)
	}
	return out, nil
}

func (r *mqlGitlabProjectContainerRegistryRepository) project() (*mqlGitlabProject, error) {
	if r.containerRepoProjectID <= 0 {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(r.containerRepoProjectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProject), nil
}

// -----------------------------------------------------------------------------
// Container expiration (cleanup) policy
// -----------------------------------------------------------------------------

// containerExpirationPolicy fetches the project's tag-retention policy via
// the projects API. Returns a null resource when the policy block is absent
// (free instances or projects with the registry disabled).
func (p *mqlGitlabProject) containerExpirationPolicy() (*mqlGitlabProjectContainerExpirationPolicy, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	project, err := p.projectDetails(conn)
	if err != nil {
		if p.detailsStatusCode == 403 || p.detailsStatusCode == 404 {
			p.ContainerExpirationPolicy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	policy := project.ContainerExpirationPolicy
	if policy == nil {
		p.ContainerExpirationPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	args := map[string]*llx.RawData{
		// Pass the key explicitly rather than letting id() derive it from
		// containerExpirationProjectID: that field is assigned after
		// CreateResource returns, so id() always saw 0 and every project's
		// policy collapsed onto one cache entry.
		"__id":            llx.StringData(projectScopedID("gitlab.project.containerExpirationPolicy", p.Id.Data)),
		"enabled":         llx.BoolData(policy.Enabled),
		"cadence":         llx.StringData(policy.Cadence),
		"keepN":           llx.IntData(int64(policy.KeepN)),
		"olderThan":       llx.StringData(policy.OlderThan),
		"nameRegexDelete": llx.StringData(policy.NameRegexDelete),
		"nameRegexKeep":   llx.StringData(policy.NameRegexKeep),
		"nextRunAt":       llx.TimeDataPtr(policy.NextRunAt),
	}
	res, err := CreateResource(p.MqlRuntime, "gitlab.project.containerExpirationPolicy", args)
	if err != nil {
		return nil, err
	}
	mqlPolicy := res.(*mqlGitlabProjectContainerExpirationPolicy)
	mqlPolicy.containerExpirationProjectID = p.Id.Data
	return mqlPolicy, nil
}

// -----------------------------------------------------------------------------
// Container registry protection rules
// -----------------------------------------------------------------------------

func (p *mqlGitlabProject) containerRegistryProtectionRules() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	// ListContainerRegistryProtectionRules doesn't accept a typed options
	// struct, but the endpoint still paginates (default 20/page). Drive the
	// next page via gitlab.WithNext, which works for offset, keyset, and
	// cursor styles uniformly.
	var all []*gitlab.ContainerRegistryProtectionRule
	var nextOpts []gitlab.RequestOptionFunc
	for {
		rules, resp, err := conn.Client().ContainerRegistryProtectionRules.ListContainerRegistryProtectionRules(projectID, nextOpts...)
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, rules...)
		next, hasNext := gitlab.WithNext(resp)
		if !hasNext {
			break
		}
		nextOpts = []gitlab.RequestOptionFunc{next}
	}

	out := make([]any, 0, len(all))
	for _, r := range all {
		args := map[string]*llx.RawData{
			"id":                          llx.IntData(r.ID),
			"repositoryPathPattern":       llx.StringData(r.RepositoryPathPattern),
			"minimumAccessLevelForPush":   llx.StringData(string(r.MinimumAccessLevelForPush)),
			"minimumAccessLevelForDelete": llx.StringData(string(r.MinimumAccessLevelForDelete)),
		}
		res, err := CreateResource(p.MqlRuntime, "gitlab.project.containerRegistryProtectionRule", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Packages
// -----------------------------------------------------------------------------

func (p *mqlGitlabProject) packages() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)
	page := int64(1)
	var all []*gitlab.Package
	for {
		pkgs, resp, err := conn.Client().Packages.ListProjectPackages(projectID,
			&gitlab.ListProjectPackagesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, pkgs...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return packagesToMqlResources(p.MqlRuntime, all, p.Id.Data)
}

func (g *mqlGitlabGroup) packages() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)
	page := int64(1)
	var all []*gitlab.GroupPackage
	for {
		pkgs, resp, err := conn.Client().Packages.ListGroupPackages(groupID,
			&gitlab.ListGroupPackagesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, pkgs...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	// Convert []*GroupPackage to []*Package while remembering the per-row
	// ProjectID for the typed back-ref.
	out := make([]any, 0, len(all))
	for _, gp := range all {
		res, err := buildMqlPackage(g.MqlRuntime, &gp.Package, gp.ProjectID)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func packagesToMqlResources(runtime *plugin.Runtime, pkgs []*gitlab.Package, projectID int64) ([]any, error) {
	out := make([]any, 0, len(pkgs))
	for _, pkg := range pkgs {
		res, err := buildMqlPackage(runtime, pkg, projectID)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildMqlPackage(runtime *plugin.Runtime, pkg *gitlab.Package, projectID int64) (*mqlGitlabProjectPackage, error) {
	tags := make([]any, 0, len(pkg.Tags))
	for _, t := range pkg.Tags {
		tags = append(tags, t.Name)
	}
	webPath := ""
	if pkg.Links != nil {
		webPath = pkg.Links.WebPath
	}
	args := map[string]*llx.RawData{
		"id":               llx.IntData(pkg.ID),
		"name":             llx.StringData(pkg.Name),
		"version":          llx.StringData(pkg.Version),
		"packageType":      llx.StringData(pkg.PackageType),
		"status":           llx.StringData(pkg.Status),
		"createdAt":        llx.TimeDataPtr(pkg.CreatedAt),
		"lastDownloadedAt": llx.TimeDataPtr(pkg.LastDownloadedAt),
		"tags":             llx.ArrayData(tags, types.String),
		"webPath":          llx.StringData(webPath),
	}
	res, err := CreateResource(runtime, "gitlab.project.package", args)
	if err != nil {
		return nil, err
	}
	mqlPkg := res.(*mqlGitlabProjectPackage)
	mqlPkg.packageProjectID = projectID
	return mqlPkg, nil
}

func (p *mqlGitlabProjectPackage) project() (*mqlGitlabProject, error) {
	if p.packageProjectID <= 0 {
		p.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(p.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(p.packageProjectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProject), nil
}

// files fetches the package's contained artifacts on demand.
func (p *mqlGitlabProjectPackage) files() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.packageProjectID)
	packageID := p.Id.Data
	if projectID <= 0 {
		return []any{}, nil
	}
	page := int64(1)
	var all []*gitlab.PackageFile
	for {
		files, resp, err := conn.Client().Packages.ListPackageFiles(projectID, packageID,
			&gitlab.ListPackageFilesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: 100}})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, files...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	out := make([]any, 0, len(all))
	for _, f := range all {
		pipelines := []any{}
		if f.Pipeline != nil {
			for _, pl := range *f.Pipeline {
				mqlPipeline, err := newMqlGitlabPipelineFromDetail(p.MqlRuntime, &pl)
				if err != nil {
					return nil, err
				}
				pipelines = append(pipelines, mqlPipeline)
			}
		}

		args := map[string]*llx.RawData{
			"id":         llx.IntData(f.ID),
			"fileName":   llx.StringData(f.FileName),
			"size":       llx.IntData(f.Size),
			"fileMD5":    llx.StringData(f.FileMD5),
			"fileSHA1":   llx.StringData(f.FileSHA1),
			"fileSHA256": llx.StringData(f.FileSHA256),
			"createdAt":  llx.TimeDataPtr(f.CreatedAt),
			"pipelines":  llx.ArrayData(pipelines, types.Resource("gitlab.project.pipeline")),
		}
		res, err := CreateResource(p.MqlRuntime, "gitlab.project.package.file", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Package protection rules
// -----------------------------------------------------------------------------

func (p *mqlGitlabProject) packageProtectionRules() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	var all []*gitlab.PackageProtectionRule
	opts := &gitlab.ListPackageProtectionRulesOptions{ListOptions: gitlab.ListOptions{PerPage: 100}}
	var nextOpts []gitlab.RequestOptionFunc
	for {
		rules, resp, err := conn.Client().ProtectedPackages.ListPackageProtectionRules(projectID, opts, nextOpts...)
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, rules...)
		next, hasNext := gitlab.WithNext(resp)
		if !hasNext {
			break
		}
		nextOpts = []gitlab.RequestOptionFunc{next}
	}

	out := make([]any, 0, len(all))
	for _, r := range all {
		args := map[string]*llx.RawData{
			"id":                          llx.IntData(r.ID),
			"packageNamePattern":          llx.StringData(r.PackageNamePattern),
			"packageType":                 llx.StringData(r.PackageType),
			"minimumAccessLevelForPush":   llx.StringData(r.MinimumAccessLevelForPush),
			"minimumAccessLevelForDelete": llx.StringData(r.MinimumAccessLevelForDelete),
		}
		res, err := CreateResource(p.MqlRuntime, "gitlab.project.packageProtectionRule", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
