// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	// GitLab tree paths are always "/"-separated, so they must be manipulated
	// with the "path" package. path/filepath rewrites separators on Windows,
	// which produced backslash directory options that the chained helm and
	// kustomize connections then failed to resolve inside the clone.
	gopath "path"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"golang.org/x/exp/slices"
)

// iacTargets is the set of chained git-clone discovery targets that scan a
// repository's contents (Terraform, k8s manifests, CloudFormation, Dockerfiles,
// Bicep, Helm charts, Kustomize configs). discoverTypes only runs when at least
// one of these is requested.
var iacTargets = []string{
	DiscoveryTerraform,
	DiscoveryK8sManifests,
	DiscoveryCloudformation,
	DiscoveryDockerfiles,
	DiscoveryBicep,
	DiscoveryHelm,
	DiscoveryKustomize,
}

func (s *Service) discover(root *inventory.Asset, conn *connection.GitLabConnection) (*inventory.Inventory, error) {
	// Targets, not just the pointer. inventory.WithoutDiscovery() clones a
	// config with Discover set to an empty &Discovery{} rather than nil, and
	// every asset this discovery emits is cloned that way -- so a nil check
	// alone let discovery run again for each of them. discoverGroups is called
	// before anything reads Targets, so each re-run cost a GetGroup, a
	// ListSubGroups and a ListDescendantGroups for a group already resolved.
	//
	// Measured on a 36-project group: 149 API calls for 37 assets, of which 110
	// were those three group URLs fetched once per asset. The azure provider
	// already guards on Targets this way.
	if conn.Conf.Discover == nil || len(conn.Conf.Discover.Targets) == 0 {
		return nil, nil
	}

	client := conn.Client()
	if client == nil {
		return nil, nil
	}

	assets := []*inventory.Asset{}

	targets := conn.Conf.Discover.Targets

	// The following calls to discover Groups and Projects will always return
	// gitlab.Group and gitlab.Project objects, no matter if we connect to only
	// one system or many. This reduces code complexity.

	platformIds := map[string]struct{}{}
	groupAssets, groups, err := s.discoverGroups(root, conn)
	if err != nil {
		return nil, err
	}
	if slices.Contains(targets, DiscoveryGroup) || slices.Contains(targets, DiscoveryAuto) {
		for _, g := range groupAssets {
			duplicate := false
			for _, platformId := range g.PlatformIds {
				if _, ok := platformIds[platformId]; ok {
					duplicate = true
					break
				}
				platformIds[platformId] = struct{}{}
			}
			if duplicate {
				continue
			}
			assets = append(assets, g)
		}
	}

	projectAssets, projects, err := s.discoverProjects(root, conn, groups)
	if err != nil {
		return nil, err
	}
	if slices.Contains(targets, DiscoveryProject) {
		for _, p := range projectAssets {
			duplicate := false
			for _, platformId := range p.PlatformIds {
				if _, ok := platformIds[platformId]; ok {
					duplicate = true
					break
				}
				platformIds[platformId] = struct{}{}
			}
			if duplicate {
				continue
			}
			assets = append(assets, p)
		}
	}

	if containsAny(targets, iacTargets) {
		repos, err := s.discoverTypes(targets, conn, projects)
		if err != nil {
			return nil, err
		}
		assets = append(assets, repos...)
	}

	if len(assets) == 0 {
		return nil, nil
	}

	return &inventory.Inventory{
		Spec: &inventory.InventorySpec{
			Assets: assets,
		},
	}, nil
}

func (s *Service) discoverGroups(root *inventory.Asset, conn *connection.GitLabConnection) ([]*inventory.Asset, []*gitlab.Group, error) {
	// If the root asset it a group, we want to use that and discover
	// the sub and descendant groups. If the root is a project, we want to additionally detect
	// the group and return it.
	// If no group or project was defined, we want to list all groups
	if !conn.IsGroup() && !conn.IsProject() {
		groups, err := listAllGroups(conn)
		if err != nil {
			return nil, nil, err
		}
		return s.convertGitlabGroupsToAssetGroups(groups, conn, ""), groups, nil
	}

	if conn.IsGroup() {
		group, err := conn.Group()
		if err != nil {
			return nil, nil, err
		}
		groups := []*gitlab.Group{group}
		assets := []*inventory.Asset{}
		// A subgroup is identified by FullPath having more than one segment;
		// Group.Name is a display name and never carries the "/", so this
		// guard used to never fire. FullPath is also what the subgroup
		// endpoints need — Path is only the leaf slug, which GitLab resolves
		// at the root namespace and could match an unrelated top-level group.
		if isSubgroup(group) {
			log.Debug().Msg("skipping subgroup discovery for subgroup")
			return assets, groups, nil
		}
		// discover subgroups and descendant groups
		subgroups, err := connection.DiscoverSubAndDescendantGroupsForGroup(conn, group.FullPath)
		if err != nil {
			log.Error().Err(err).Msg("unable to discover sub groups")
			return []*inventory.Asset{}, []*gitlab.Group{group}, err
		}
		groups = append(groups, subgroups...)
		assets = append(assets, s.convertGitlabGroupsToAssetGroups(subgroups, conn, group.Path)...)
		return assets, groups, err
	}

	group, err := conn.Group()
	if err != nil {
		return nil, nil, err
	}

	conf := conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
	conf.Type = GitlabGroupConnection
	conf.Options = map[string]string{
		"group":    group.FullPath,
		"group-id": strconv.FormatInt(group.ID, 10),
		"url":      conn.Conf.Options["url"],
	}
	asset := &inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	s.detectAsGroup(asset, group)

	groups := []*gitlab.Group{group}
	assets := []*inventory.Asset{asset}
	if isSubgroup(group) {
		log.Debug().Msg("skipping subgroup discovery for subgroup")
		return assets, groups, nil
	}
	// discover subgroups and descendant groups
	subgroups, err := connection.DiscoverSubAndDescendantGroupsForGroup(conn, group.FullPath)
	if err != nil {
		log.Error().Err(err).Msg("unable to discover sub groups")
		return []*inventory.Asset{}, []*gitlab.Group{group}, err
	}
	groups = append(groups, subgroups...)
	assets = append(assets, s.convertGitlabGroupsToAssetGroups(subgroups, conn, group.Path)...)
	return assets, groups, nil
}

func (s *Service) discoverProjects(root *inventory.Asset, conn *connection.GitLabConnection, groups []*gitlab.Group) ([]*inventory.Asset, []*gitlab.Project, error) {
	log.Debug().Msg("discover projects")
	if conn.IsProject() {
		project, err := conn.Project()
		return []*inventory.Asset{}, []*gitlab.Project{project}, err
	}

	var assets []*inventory.Asset
	projects := map[int64]*gitlab.Project{}

	for i := range groups {
		group := groups[i]
		groupProjects, err := discoverGroupProjects(conn, group.FullPath)
		if err != nil {
			return nil, nil, err
		}

		for j := range groupProjects {
			project := groupProjects[j]
			if projects[project.ID] != nil {
				continue
			}

			// Attribute the project to the namespace that owns it, not the
			// group we happened to enumerate. GitLab's group projects endpoint
			// includes projects merely *shared* into the group, and stamping
			// those with the sharing group produced a second, disjoint set of
			// platform ids for the same repository — so it was discovered,
			// scanned, and reported twice.
			ownerID, ownerPath := group.ID, group.FullPath
			if project.Namespace != nil && project.Namespace.ID > 0 {
				ownerID, ownerPath = project.Namespace.ID, project.Namespace.FullPath
			}

			conf := conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
			conf.Type = GitlabProjectConnection
			conf.Options = map[string]string{
				"group":      ownerPath,
				"group-id":   strconv.FormatInt(ownerID, 10),
				"project":    project.Name,
				"project-id": strconv.FormatInt(project.ID, 10),
				"url":        conn.Conf.Options["url"],
			}
			asset := &inventory.Asset{
				Name:        project.NameWithNamespace,
				Connections: []*inventory.Config{conf},
			}

			s.detectAsProject(asset, ownerID, ownerPath, project)

			assets = append(assets, asset)
			projects[project.ID] = project
		}
	}

	projectsArr := make([]*gitlab.Project, 0, len(projects))
	for _, project := range projects {
		projectsArr = append(projectsArr, project)
	}
	return assets, projectsArr, nil
}

func discoverGroupProjects(conn *connection.GitLabConnection, gid any) ([]*gitlab.Project, error) {
	log.Debug().Msgf("discover group projects for %v", gid)
	perPage := int64(50)
	page := int64(1)
	projects := []*gitlab.Project{}
	for {
		projs, resp, err := conn.Client().Groups.ListGroupProjects(gid, &gitlab.ListGroupProjectsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			return nil, err
		}
		projects = append(projects, projs...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	// Hand these to the connection package so the per-asset connections this
	// discovery is about to spawn do not each re-fetch their own project.
	connection.CacheDiscoveredProjects(conn.Conf.Options["url"], projects)

	return projects, nil
}

func (s *Service) convertGitlabGroupsToAssetGroups(groups []*gitlab.Group, conn *connection.GitLabConnection, rootGroupPath string) []*inventory.Asset {
	var list []*inventory.Asset
	// convert to assets
	for _, group := range groups {
		conf := conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		// Replace the map wholesale rather than merging into the parent's: a
		// root config carrying --project would otherwise leave "project" set on
		// every discovered group asset, so IsProject() reports true for a group
		// and the connection resolves the wrong thing entirely.
		conf.Options = map[string]string{
			"group":    group.FullPath,
			"group-id": strconv.FormatInt(group.ID, 10),
			"url":      conn.Conf.Options["url"],
		}
		conf.Type = GitlabGroupConnection
		asset := &inventory.Asset{
			Connections: []*inventory.Config{conf},
		}
		err := s.detectAsGroup(asset, group)
		if err != nil {
			log.Error().Err(err).Msg("cannot detect as group")
			continue
		}
		list = append(list, asset)
	}
	return list
}

func listAllGroups(conn *connection.GitLabConnection) ([]*gitlab.Group, error) {
	log.Debug().Msg("calling list all groups")
	perPage := int64(50)
	page := int64(1)
	groups := []*gitlab.Group{}
	for {
		grps, resp, err := conn.Client().Groups.ListGroups(&gitlab.ListGroupsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			return nil, err
		}
		groups = append(groups, grps...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	return groups, nil
}

func (s *Service) discoverTypes(targets []string, conn *connection.GitLabConnection, projects []*gitlab.Project) ([]*inventory.Asset, error) {
	if !containsAny(targets, iacTargets) {
		return nil, nil
	}

	creds := gitCredentials(conn.Conf.Credentials)

	var res []*inventory.Asset
	for i := range projects {
		project := projects[i]
		types, err := discoverRepoTypes(conn.Client(), project.ID)
		if err != nil {
			log.Error().Err(err).Str("project", project.PathWithNamespace).Msg("failed to discover IaC files in gitlab repo")
			continue
		}

		repoOpts := func(extra map[string]string) map[string]string {
			opts := map[string]string{
				"ssh-url":  project.SSHURLToRepo,
				"http-url": project.HTTPURLToRepo,
			}
			for k, v := range extra {
				opts[k] = v
			}
			return opts
		}

		if types.terraform && slices.Contains(targets, DiscoveryTerraform) {
			res = append(res, &inventory.Asset{
				Connections: []*inventory.Config{{
					Type:        "terraform-hcl-git",
					Options:     repoOpts(nil),
					Credentials: creds,
				}},
			})
		}

		if types.k8s && slices.Contains(targets, DiscoveryK8sManifests) {
			res = append(res, &inventory.Asset{
				Connections: []*inventory.Config{{
					Type:        "k8s",
					Options:     repoOpts(nil),
					Credentials: creds,
					Discover:    &inventory.Discovery{Targets: []string{"auto"}},
				}},
			})
		}

		if slices.Contains(targets, DiscoveryCloudformation) {
			// CloudFormation templates share the .yaml/.yml/.json extensions
			// with many other configs, so we ask GitLab's blob search for the
			// `AWSTemplateFormatVersion` marker instead of relying on the
			// extension alone. The search API requires GitLab's advanced
			// search backend (Elasticsearch); on instances where it is
			// unavailable the call returns an error and we just skip
			// CloudFormation discovery for the project.
			paths, err := cloudformationTemplatePaths(conn.Client(), project.ID)
			if err != nil {
				log.Error().Err(err).Str("project", project.PathWithNamespace).Msg("failed to discover cloudformation templates in gitlab repo")
			}
			for _, path := range paths {
				res = append(res, &inventory.Asset{
					Connections: []*inventory.Config{{
						Type:        "cloudformation",
						Options:     repoOpts(map[string]string{"path": path}),
						Credentials: creds,
					}},
				})
			}
		}

		// Each Dockerfile asset clones the repo independently on connect
		// (the dockerfile connection targets a single file), so a repo with
		// many Dockerfiles results in several clones — an accepted trade-off
		// that keeps the connection's single-file model.
		if slices.Contains(targets, DiscoveryDockerfiles) {
			for _, path := range types.dockerfiles {
				res = append(res, &inventory.Asset{
					Connections: []*inventory.Config{{
						Type:        "docker-file",
						Options:     repoOpts(map[string]string{"path": path}),
						Credentials: creds,
					}},
				})
			}
		}

		if types.bicep && slices.Contains(targets, DiscoveryBicep) {
			res = append(res, &inventory.Asset{
				Connections: []*inventory.Config{{
					Type:        "bicep",
					Options:     repoOpts(nil),
					Credentials: creds,
				}},
			})
		}

		// One asset per chart directory; same clone-per-asset trade-off as
		// Dockerfiles since the helm connection scans a single chart.
		if slices.Contains(targets, DiscoveryHelm) {
			for _, dir := range types.helmChartDirs {
				res = append(res, &inventory.Asset{
					Connections: []*inventory.Config{{
						Type:        "helm",
						Options:     repoOpts(map[string]string{"path": dir}),
						Credentials: creds,
					}},
				})
			}
		}

		// One asset per kustomize directory (base + each overlay).
		if slices.Contains(targets, DiscoveryKustomize) {
			for _, dir := range types.kustomizeDirs {
				res = append(res, &inventory.Asset{
					Connections: []*inventory.Config{{
						Type:        "kustomize",
						Options:     repoOpts(map[string]string{"path": dir}),
						Credentials: creds,
					}},
				})
			}
		}
	}
	return res, nil
}

type discoveredTypes struct {
	terraform     bool
	k8s           bool
	bicep         bool
	dockerfiles   []string
	helmChartDirs []string
	kustomizeDirs []string
}

// discoverRepoTypes walks the repository tree once and classifies blobs into
// the IaC categories we recognize. CloudFormation is intentionally absent: it
// requires content inspection (the `AWSTemplateFormatVersion` marker) and is
// handled separately via cloudformationTemplatePaths.
func discoverRepoTypes(client *gitlab.Client, pid any) (*discoveredTypes, error) {
	opts := &gitlab.ListTreeOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
		},
		Recursive: gitlab.Ptr(true),
	}

	nodes := []*gitlab.TreeNode{}
	for {
		data, resp, err := client.Repositories.ListTree(pid, opts)
		if err != nil && resp != nil && resp.StatusCode == 404 {
			// this case can happen when you have a new project with no commits / files
			break
		} else if err != nil {
			return nil, err
		}
		nodes = append(nodes, data...)

		// Exit the loop when we've seen all pages.
		if resp.NextPage == 0 {
			break
		}

		// Update the page number to get the next page.
		opts.Page = resp.NextPage
	}

	out := &discoveredTypes{}
	helmSeen := map[string]bool{}
	kustomizeSeen := map[string]bool{}
	for i := range nodes {
		node := nodes[i]
		if node.Type != "blob" || isHiddenPath(node.Path) {
			continue
		}

		base := gopath.Base(node.Path)
		switch {
		case strings.HasSuffix(node.Path, ".tf"):
			out.terraform = true
		case strings.HasSuffix(node.Path, ".bicep"):
			out.bicep = true
		case base == "Chart.yaml":
			dir := iacDir(node.Path)
			if !helmSeen[dir] {
				helmSeen[dir] = true
				out.helmChartDirs = append(out.helmChartDirs, dir)
			}
		case isKustomization(base):
			dir := iacDir(node.Path)
			if !kustomizeSeen[dir] {
				kustomizeSeen[dir] = true
				out.kustomizeDirs = append(out.kustomizeDirs, dir)
			}
		case isDockerfile(base):
			out.dockerfiles = append(out.dockerfiles, node.Path)
		case (strings.HasSuffix(node.Path, ".yaml") || strings.HasSuffix(node.Path, ".yml")) &&
			!strings.HasSuffix(node.Path, "mql.yaml") && !strings.HasSuffix(node.Path, "mql.yml"):
			out.k8s = true
		}
	}
	return out, nil
}

// cloudformationTemplatePaths uses GitLab's project-scoped blob search to find
// files containing the CloudFormation marker `AWSTemplateFormatVersion`, then
// filters to extensions used by CloudFormation/SAM templates. The search API
// returns matches in pages of 20 by default; we follow pagination so a project
// with many templates is not silently truncated.
func cloudformationTemplatePaths(client *gitlab.Client, pid any) ([]string, error) {
	opts := &gitlab.SearchOptions{ListOptions: gitlab.ListOptions{PerPage: 100}}
	var paths []string
	seen := map[string]bool{}
	for {
		blobs, resp, err := client.Search.BlobsByProject(pid, "AWSTemplateFormatVersion", opts)
		if err != nil {
			// Discard any partially-collected paths so the caller doesn't
			// create assets from an incomplete search result.
			return nil, err
		}
		for _, blob := range blobs {
			if isHiddenPath(blob.Path) || seen[blob.Path] {
				continue
			}
			switch strings.ToLower(gopath.Ext(blob.Path)) {
			case ".yaml", ".yml", ".json", ".template":
				seen[blob.Path] = true
				paths = append(paths, blob.Path)
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return paths, nil
}

// gitCredentials clones the parent GitLab connection credentials for use in a
// git clone, defaulting the user to "oauth2" so the token works over HTTPS.
func gitCredentials(in []*vault.Credential) []*vault.Credential {
	creds := make([]*vault.Credential, len(in))
	for i := range in {
		cc := in[i].CloneVT()
		if cc.User == "" {
			cc.User = "oauth2"
		}
		creds[i] = cc
	}
	return creds
}

// isHiddenPath reports whether any path segment is hidden (starts with a dot),
// e.g. files under .gitlab/ or a top-level .gitlab-ci.yml.
func isHiddenPath(p string) bool {
	for _, fragment := range strings.Split(p, "/") {
		if strings.HasPrefix(fragment, ".") {
			return true
		}
	}
	return false
}

// iacDir returns the repo-relative directory containing the given file, with a
// top-level file ("." from path.Dir) normalized to "" so it joins onto the
// clone root cleanly.
func iacDir(p string) string {
	if dir := gopath.Dir(p); dir != "." {
		return dir
	}
	return ""
}

// isSubgroup reports whether a group is nested under another group. GitLab
// group names are display names and never contain a "/", so the nesting has to
// be read off FullPath.
func isSubgroup(group *gitlab.Group) bool {
	return strings.Contains(group.FullPath, "/")
}

// isDockerfile reports whether a base file name follows a Dockerfile naming
// convention: `Dockerfile`, `Dockerfile.<suffix>` (e.g. Dockerfile.prod), or
// `<prefix>.Dockerfile`/`<prefix>.dockerfile` (e.g. app.Dockerfile).
func isDockerfile(base string) bool {
	return base == "Dockerfile" ||
		strings.HasPrefix(base, "Dockerfile.") ||
		strings.HasSuffix(base, ".Dockerfile") ||
		strings.HasSuffix(base, ".dockerfile")
}

// isKustomization reports whether a base file name is one of the recognized
// Kustomize entry-point file names.
func isKustomization(base string) bool {
	switch base {
	case "kustomization.yaml", "kustomization.yml", "Kustomization":
		return true
	}
	return false
}

// containsAny reports whether any value in needles appears in haystack.
func containsAny(haystack, needles []string) bool {
	for _, n := range needles {
		if slices.Contains(haystack, n) {
			return true
		}
	}
	return false
}
