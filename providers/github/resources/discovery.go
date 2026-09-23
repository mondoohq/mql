// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	gopath "path"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.GithubConnection)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conn.Asset().Connections[0].Discover.Targets)
	list, err := discover(runtime, targets)
	if err != nil {
		return in, err
	}

	in.Spec.Assets = list
	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) {
		// CloudFormation, Dockerfile, Bicep, Helm, and Kustomize discovery
		// each shallow-clone matched repos, so they stay opt-in via an
		// explicit --discover <type> and are deliberately left out of `all`.
		return []string{
			connection.DiscoveryRepos,
			connection.DiscoveryUsers,
			connection.DiscoveryTerraform,
			connection.DiscoveryK8sManifests,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	defer logger.FuncDur(time.Now(), "provider.github.discover")

	conn := runtime.Connection.(*connection.GithubConnection)
	conf := conn.Asset().Connections[0]
	assetList := []*inventory.Asset{}
	if orgName := conf.Options["organization"]; orgName != "" {
		orgAssets, err := org(runtime, orgName, conn, targets)
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, orgAssets...)
	}

	repoName := conf.Options["repository"]
	var owner string
	repoId := conf.Options["repository"]
	if repoId != "" {
		owner = conf.Options["owner"]
		if owner == "" {
			owner = conf.Options["organization"]
		}
		if owner == "" {
			owner = conf.Options["user"]
		}
	}
	if repoName != "" && owner != "" {
		repoAssets, err := repo(runtime, repoName, owner, conn, targets)
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, repoAssets...)
	}

	if userId := userDiscoveryTarget(conf); userId != "" {
		userAssets, err := user(runtime, userId, conn, targets)
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, userAssets...)
	}

	return assetList, nil
}

// userDiscoveryTarget returns the account to discover as a user scope, or "" for
// none. An explicit "user" option is always a user scope. "owner" is only a user
// shortcut when it stands alone (`--owner someuser`): once a "repository" is set,
// "owner" is merely that repo's namespace, not a user to scan — returning it
// there would emit a phantom user asset for the repo's owner (empty-named when
// the owner is an organization rather than a user).
func userDiscoveryTarget(conf *inventory.Config) string {
	if user := conf.Options["user"]; user != "" {
		return user
	}
	if conf.Options["repository"] == "" {
		return conf.Options["owner"]
	}
	return ""
}

func org(runtime *plugin.Runtime, orgName string, conn *connection.GithubConnection, targets []string) ([]*inventory.Asset, error) {
	conf := conn.Asset().Connections[0]
	reposFilter := NewReposFilter(conf)
	assetList := []*inventory.Asset{}
	org, err := getMqlGithubOrg(runtime, orgName)
	if err != nil {
		return nil, err
	}

	// only scan the org if the discover flag is provided, this allows you to scan all repos in an org with simply using
	// --discover repos. If users provide a repo filter, we also want to skip org scan.
	if stringx.ContainsAnyOf(targets, connection.DiscoveryOrganization, connection.DiscoveryAll, connection.DiscoveryAuto) && reposFilter.empty() {
		labels := map[string]string{}
		for j := range org.GetCustomProperties().Data {
			customProperty := org.GetCustomProperties().Data[j].(*mqlGithubOrganizationCustomProperty)
			value := ""
			if customProperty.DefaultValue.IsSet() {
				// if the default value of the org-level custom property is set, use it as the label value
				value = customProperty.DefaultValue.Data
			}
			labels[customProperty.Name.Data] = value
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{connection.NewGithubOrgIdentifier(org.Login.Data)},
			Name:        org.Name.Data,
			Platform:    connection.NewGithubOrgPlatform(org.Login.Data),
			Labels:      labels,
			Connections: []*inventory.Config{conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))},
		})
	}

	if stringx.ContainsAnyOf(targets, connection.DiscoveryRepos, connection.DiscoveryAll, connection.DiscoveryAuto) {
		for i := range org.GetRepositories().Data {
			repo := org.GetRepositories().Data[i].(*mqlGithubRepository)
			if reposFilter.skipRepo(repo.Name.Data) {
				continue
			}
			cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
			cfg.Options["repository"] = repo.Name.Data
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewGitHubRepoIdentifier(org.Login.Data, repo.Name.Data)},
				Name:        org.Login.Data + "/" + repo.Name.Data,
				Platform:    connection.NewGitHubRepoPlatform(org.Login.Data, repo.Name.Data),
				Labels:      convert.DictToTypedMap[string](repo.CustomProperties.Data),
				Connections: []*inventory.Config{cfg},
			})

			iacAssets, err := discoverRepoIac(conn, repo, targets)
			if err != nil {
				return nil, err
			}
			assetList = append(assetList, iacAssets...)
		}
	}
	if stringx.ContainsAnyOf(targets, connection.DiscoveryUsers) {
		for i := range org.GetMembers().Data {
			user := org.GetMembers().Data[i].(*mqlGithubUser)
			if user.Login.Data == "" {
				continue
			}
			// Most GitHub accounts leave the profile name blank; fall back to
			// the login so those members are still discovered.
			name := user.Name.Data
			if name == "" {
				name = user.Login.Data
			}
			cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
			cfg.Options["user"] = user.Login.Data
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewGithubUserIdentifier(user.Login.Data)},
				Name:        name,
				Platform:    connection.NewGithubUserPlatform(user.Login.Data),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{cfg},
			})
		}
	}
	return assetList, nil
}

func getMqlGithubOrg(runtime *plugin.Runtime, orgName string) (*mqlGithubOrganization, error) {
	res, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{"name": llx.StringData(orgName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganization), nil
}

func repo(runtime *plugin.Runtime, repoName string, owner string, conn *connection.GithubConnection, targets []string) ([]*inventory.Asset, error) {
	conf := conn.Asset().Connections[0]
	assetList := []*inventory.Asset{}

	repo, err := getMqlGithubRepo(runtime, repoName)
	if err != nil {
		return nil, err
	}
	if discoverRepoAsset(targets) {
		cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		cfg.Options["repository"] = repo.Name.Data
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{connection.NewGitHubRepoIdentifier(owner, repo.Name.Data)},
			Name:        owner + "/" + repo.Name.Data,
			Platform:    connection.NewGitHubRepoPlatform(owner, repo.Name.Data),
			Labels:      convert.DictToTypedMap[string](repo.CustomProperties.Data),
			Connections: []*inventory.Config{cfg},
		})
	}

	iacAssets, err := discoverRepoIac(conn, repo, targets)
	if err != nil {
		return nil, err
	}
	assetList = append(assetList, iacAssets...)

	return assetList, nil
}

func getMqlGithubRepo(runtime *plugin.Runtime, repoName string) (*mqlGithubRepository, error) {
	res, err := NewResource(runtime, "github.repository", map[string]*llx.RawData{"name": llx.StringData(repoName)})
	if err != nil {
		return nil, err
	}

	return res.(*mqlGithubRepository), nil
}

func user(runtime *plugin.Runtime, userName string, conn *connection.GithubConnection, targets []string) ([]*inventory.Asset, error) {
	conf := conn.Asset().Connections[0]
	reposFilter := NewReposFilter(conf)
	assetList := []*inventory.Asset{}

	user, err := getMqlGithubUser(runtime, userName)
	if err != nil {
		return nil, err
	}
	if discoverUserAsset(targets) {
		cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		cfg.Options["user"] = user.Login.Data
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{connection.NewGithubUserIdentifier(user.Login.Data)},
			Name:        user.Name.Data,
			Platform:    connection.NewGithubUserPlatform(user.Login.Data),
			Labels:      make(map[string]string),
			Connections: []*inventory.Config{cfg},
		})
	}

	if discoverUserRepos(conf, targets) {
		repos, err := userScopeRepos(runtime, conn, user)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			if reposFilter.skipRepo(repo.Name.Data) {
				continue
			}
			repoCfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
			repoCfg.Options["repository"] = repo.Name.Data
			// The repository resource resolves its owner from the "owner" /
			// "organization" options; a user-scoped config carries neither, so
			// without this every repo asset discovered here fails to
			// initialize github.repository.
			repoCfg.Options["owner"] = user.Login.Data
			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{connection.NewGitHubRepoIdentifier(user.Login.Data, repo.Name.Data)},
				Name:        user.Login.Data + "/" + repo.Name.Data,
				Platform:    connection.NewGitHubRepoPlatform(user.Login.Data, repo.Name.Data),
				Labels:      convert.DictToTypedMap[string](repo.CustomProperties.Data),
				Connections: []*inventory.Config{repoCfg},
			})

			iacAssets, err := discoverRepoIac(conn, repo, targets)
			if err != nil {
				return nil, err
			}
			assetList = append(assetList, iacAssets...)
		}
	}
	return assetList, nil
}

// userScopeRepos returns the repositories a user-scoped scan fans out to:
// everything the credential can see on that account. The user listing
// (GET /users/{login}/repos) is the base — for PATs it includes the private
// repositories the token can access, but for GitHub App installation tokens
// it only ever returns public repositories. So for installation tokens the
// installation's own grant (GET /installation/repositories — the private
// repositories picked in GitHub's install UI) is merged in on top; other
// tokens get a 403 on that endpoint and just use the user listing.
func userScopeRepos(runtime *plugin.Runtime, conn *connection.GithubConnection, user *mqlGithubUser) ([]*mqlGithubRepository, error) {
	login := user.Login.Data
	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var granted []*github.Repository
	for {
		repos, resp, err := conn.Client().Apps.ListRepos(conn.Context(), listOpts)
		if err != nil {
			// not an installation token — the user listing alone is complete
			granted = nil
			break
		}
		granted = append(granted, repos.Repositories...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []*mqlGithubRepository{}
	seen := map[int64]bool{}
	for _, repo := range granted {
		// an installation on this user account only grants repos the account
		// owns; guard anyway so a shared credential never leaks another
		// owner's repos into this user's scope
		if repo.GetOwner().GetLogin() != login {
			continue
		}
		r, err := newMqlGithubRepository(runtime, repo)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
		seen[repo.GetID()] = true
	}
	for _, r := range user.GetRepositories().Data {
		repo := r.(*mqlGithubRepository)
		if seen[repo.Id.Data] {
			continue
		}
		res = append(res, repo)
	}
	return res, nil
}

// discoverUserRepos reports whether a user-scoped connection fans out to the
// account's repositories, mirroring the org path (a personal-account GitHub
// App install scans through the user scope). It must stay false when an
// explicit repository is configured: discover() also reaches the user path
// through the owner fallback of single-repo scans, which must not fan out to
// every repository the owner has.
// discoverRepoAsset reports whether the repository itself should be emitted as
// an asset, mirroring the target check the organization asset already makes.
func discoverRepoAsset(targets []string) bool {
	return stringx.ContainsAnyOf(targets,
		connection.DiscoveryRepos, connection.DiscoveryAll, connection.DiscoveryAuto)
}

// discoverUserAsset reports whether the account being scanned should be emitted
// as an asset.
func discoverUserAsset(targets []string) bool {
	return stringx.ContainsAnyOf(targets,
		connection.DiscoveryUsers, connection.DiscoveryAll, connection.DiscoveryAuto)
}

func discoverUserRepos(conf *inventory.Config, targets []string) bool {
	return conf.Options["repository"] == "" &&
		stringx.ContainsAnyOf(targets, connection.DiscoveryRepos, connection.DiscoveryAll, connection.DiscoveryAuto)
}

func getMqlGithubUser(runtime *plugin.Runtime, userName string) (*mqlGithubUser, error) {
	res, err := NewResource(runtime, "github.user", map[string]*llx.RawData{"login": llx.StringData(userName)})
	if err != nil {
		return nil, err
	}

	return res.(*mqlGithubUser), nil
}

type ReposFilter struct {
	include []string
	exclude []string
}

func NewReposFilter(cfg *inventory.Config) ReposFilter {
	nsFilter := ReposFilter{}
	if include, ok := cfg.Options[connection.OPTION_REPOS]; ok && len(include) > 0 {
		nsFilter.include = strings.Split(include, ",")
	}

	if exclude, ok := cfg.Options[connection.OPTION_REPOS_EXCLUDE]; ok && len(exclude) > 0 {
		nsFilter.exclude = strings.Split(exclude, ",")
	}
	return nsFilter
}

func (f *ReposFilter) empty() bool {
	return (len(f.exclude) + len(f.include)) == 0
}

func (f *ReposFilter) skipRepo(namespace string) bool {
	// anything explicitly specified in the list of includes means accept only from that list
	if len(f.include) > 0 {
		for _, ns := range f.include {
			g, err := glob.Compile(ns)
			if err != nil {
				log.Error().Err(err).Msg("failed to compile repos glob")
				return false
			}
			if g.Match(namespace) {
				// stop looking, we found our match
				return false
			}
		}

		// didn't find it, so it must be skipped
		return true
	}

	// if nothing explicitly meant to be included, then check whether
	// it should be excluded
	for _, ns := range f.exclude {
		g, err := glob.Compile(ns)
		if err != nil {
			log.Error().Err(err).Msg("failed to compile repos exclude glob")
			return false
		}
		if g.Match(namespace) {
			return true
		}
	}

	return false
}

// gitCredentials clones the parent GitHub connection credentials for use in a
// git clone, defaulting the user to "oauth2" so the token works over HTTPS.
func gitCredentials(conf *inventory.Config) []*vault.Credential {
	creds := make([]*vault.Credential, len(conf.Credentials))
	for i := range conf.Credentials {
		cc := conf.Credentials[i].CloneVT()
		if cc.User == "" {
			cc.User = "oauth2"
		}
		creds[i] = cc
	}
	return creds
}

// isHiddenPath reports whether any path segment is hidden (starts with a dot),
// e.g. files under .github/ or a top-level .drone.yml.
func isHiddenPath(p string) bool {
	for _, fragment := range strings.Split(p, "/") {
		if strings.HasPrefix(fragment, ".") {
			return true
		}
	}
	return false
}

// searchCode runs a GitHub code search and returns every matching result,
// following pagination. The code search API returns at most 100 items per page
// (30 by default), so a repo with many matching files would otherwise be
// silently truncated to the first page.
func searchCode(ctx context.Context, client *github.Client, query string) ([]*github.CodeResult, error) {
	opts := &github.SearchOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var results []*github.CodeResult
	for {
		res, resp, err := client.Search.Code(ctx, query, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, res.CodeResults...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return results, nil
}

// discoverRepoIac runs every IaC discovery target for a single repository.
//
// Terraform (a language check) and CloudFormation (a content search for the
// AWSTemplateFormatVersion marker) each need their own API call. The remaining
// detectors — k8s manifests, Dockerfiles, Bicep, Helm, and Kustomize — are all
// filename/extension based, so they share a single recursive git-tree walk
// rather than spending one GitHub Code Search call per type. The Code Search
// API is limited to 30 requests/minute, so the previous per-type approach made
// `--discover all` start throttling at only a handful of repos per org.
func discoverRepoIac(conn *connection.GithubConnection, repo *mqlGithubRepository, targets []string) ([]*inventory.Asset, error) {
	var assetList []*inventory.Asset

	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryTerraform) {
		terraformAssets, err := discoverTerraform(conn, repo)
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, terraformAssets...)
	}
	if stringx.Contains(targets, connection.DiscoveryCloudformation) {
		cfAssets, err := discoverCloudformation(conn, repo)
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, cfAssets...)
	}

	if !stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryK8sManifests,
		connection.DiscoveryDockerfiles, connection.DiscoveryBicep, connection.DiscoveryHelm,
		connection.DiscoveryKustomize) {
		return assetList, nil
	}

	iac, err := repoIacFromTree(conn.Context(), conn.Client(), repo)
	if err != nil {
		// Tree discovery is best-effort; a missing/empty repo or permission
		// issue should not fail discovery of the rest of the org.
		log.Error().Err(err).Str("project", repo.FullName.Data).Msg("failed to walk repository tree for IaC discovery")
		return assetList, nil
	}

	creds := gitCredentials(conn.Asset().Connections[0])
	if iac.hasYaml && stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryK8sManifests) {
		k8sAsset := gitAsset("k8s", repo, "", creds)
		k8sAsset.Connections[0].Discover = &inventory.Discovery{Targets: []string{"auto"}}
		assetList = append(assetList, k8sAsset)
	}
	if stringx.Contains(targets, connection.DiscoveryDockerfiles) {
		for _, path := range iac.dockerfiles {
			assetList = append(assetList, gitAsset("docker-file", repo, path, creds))
		}
	}
	if iac.hasBicep && stringx.Contains(targets, connection.DiscoveryBicep) {
		assetList = append(assetList, gitAsset("bicep", repo, "", creds))
	}
	if stringx.Contains(targets, connection.DiscoveryHelm) {
		for _, dir := range iac.helmChartDirs {
			assetList = append(assetList, gitAsset("helm", repo, dir, creds))
		}
	}
	if stringx.Contains(targets, connection.DiscoveryKustomize) {
		for _, dir := range iac.kustomizeDirs {
			assetList = append(assetList, gitAsset("kustomize", repo, dir, creds))
		}
	}
	return assetList, nil
}

// repoIac holds the IaC entry points found by a single recursive git-tree walk.
// CloudFormation is intentionally absent: it requires file-content inspection
// (the AWSTemplateFormatVersion marker), not a path match.
type repoIac struct {
	hasYaml       bool // k8s manifests
	hasBicep      bool
	dockerfiles   []string
	helmChartDirs []string
	kustomizeDirs []string
}

// repoIacFromTree fetches the repository's default-branch tree once (recursively)
// and classifies its files into the IaC entry points each detector needs. The
// git-tree endpoint is on the generous core rate limit rather than the Code
// Search limit, so this is one cheap call per repo instead of one Code Search
// call per IaC type. The switch ordering mirrors the GitLab provider so the two
// behave identically — notably, Chart.yaml and kustomization.yaml match their
// own cases and so do not also count as k8s manifests.
func repoIacFromTree(ctx context.Context, client *github.Client, repo *mqlGithubRepository) (*repoIac, error) {
	out := &repoIac{}

	ref := repo.DefaultBranchName.Data
	if ref == "" {
		// Empty repositories have no default branch and therefore no tree.
		return out, nil
	}

	owner, err := repoOwner(repo)
	if err != nil {
		return nil, err
	}
	if owner.Login.Error != nil {
		return nil, owner.Login.Error
	}

	tree, _, err := client.Git.GetTree(ctx, owner.Login.Data, repo.Name.Data, ref, true)
	if err != nil {
		return nil, err
	}
	if tree.GetTruncated() {
		// The recursive tree endpoint truncates rather than paginating, so for
		// very large repositories some files may be missing from this walk.
		log.Warn().Str("project", repo.FullName.Data).Msg("github repository tree is truncated; some IaC files may not be discovered")
	}

	return classifyIacTree(tree.Entries), nil
}

// classifyIacTree sorts the blobs of a repository tree into the IaC entry
// points each detector needs. The switch ordering mirrors the GitLab provider
// so the two behave identically — notably, Chart.yaml and kustomization.yaml
// match their own cases and so do not also count as k8s manifests.
func classifyIacTree(entries []*github.TreeEntry) *repoIac {
	out := &repoIac{}
	helmSeen := map[string]bool{}
	kustomizeSeen := map[string]bool{}
	for _, entry := range entries {
		if entry.GetType() != "blob" {
			continue
		}
		path := entry.GetPath()
		if isHiddenPath(path) {
			continue
		}

		base := gopath.Base(path)
		switch {
		case strings.HasSuffix(path, ".bicep"):
			out.hasBicep = true
		case base == "Chart.yaml":
			dir := iacDir(path)
			if !helmSeen[dir] {
				helmSeen[dir] = true
				out.helmChartDirs = append(out.helmChartDirs, dir)
			}
		case isKustomization(base):
			dir := iacDir(path)
			if !kustomizeSeen[dir] {
				kustomizeSeen[dir] = true
				out.kustomizeDirs = append(out.kustomizeDirs, dir)
			}
		case isDockerfile(base):
			out.dockerfiles = append(out.dockerfiles, path)
		case (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) &&
			!strings.HasSuffix(path, "mql.yaml") && !strings.HasSuffix(path, "mql.yml"):
			out.hasYaml = true
		}
	}
	return out
}

// gitAsset builds a child asset that clones the repository and scans it with the
// given connection type. path is the repo-relative file or directory to scan,
// or "" when the connection scans the whole checkout.
func gitAsset(connType string, repo *mqlGithubRepository, path string, creds []*vault.Credential) *inventory.Asset {
	opts := map[string]string{
		"ssh-url":  repo.SshUrl.Data,
		"http-url": repo.CloneUrl.Data,
	}
	if path != "" {
		opts["path"] = path
	}
	return &inventory.Asset{
		Connections: []*inventory.Config{{
			Type:        connType,
			Options:     opts,
			Credentials: creds,
		}},
	}
}

func discoverTerraform(conn *connection.GithubConnection, repo *mqlGithubRepository) ([]*inventory.Asset, error) {
	creds := gitCredentials(conn.Asset().Connections[0])

	var res []*inventory.Asset
	hasTf, err := hasTerraformHcl(conn.Context(), conn.Client(), repo)
	if err != nil {
		log.Error().Err(err).Str("project", repo.FullName.Data).Msg("failed to discover terraform repo")
	} else if hasTf {
		res = append(res, &inventory.Asset{
			Connections: []*inventory.Config{{
				Type: "terraform-hcl-git",
				Options: map[string]string{
					"ssh-url":  repo.SshUrl.Data,
					"http-url": repo.CloneUrl.Data,
				},
				Credentials: creds,
			}},
		})
	}
	return res, nil
}

// hasTerraformHcl will check if the repository contains terraform files
func hasTerraformHcl(ctx context.Context, client *github.Client, repo *mqlGithubRepository) (bool, error) {
	owner, err := repoOwner(repo)
	if err != nil {
		return false, err
	}
	if owner.Login.Error != nil {
		return false, owner.Login.Error
	}

	languages, _, err := client.Repositories.ListLanguages(ctx, owner.Login.Data, repo.Name.Data)
	if err != nil {
		return false, err
	}
	if languages["HCL"] > 0 {
		return true, nil
	}
	return false, nil
}

// discoverCloudformation emits one asset per CloudFormation template found in
// the repository. The CloudFormation connection scans a single template file
// (not a directory), so each asset carries its own repo-relative path and
// performs its own shallow clone of the repo on connect. For a repo with many
// templates this means several clones of the same repo — an accepted trade-off
// that keeps the connection's single-template model and avoids a shared clone
// cache.
func discoverCloudformation(conn *connection.GithubConnection, repo *mqlGithubRepository) ([]*inventory.Asset, error) {
	creds := gitCredentials(conn.Asset().Connections[0])

	paths, err := cloudformationTemplatePaths(conn.Context(), conn.Client(), repo)
	if err != nil {
		log.Error().Err(err).Str("project", repo.FullName.Data).Msg("failed to discover cloudformation repo")
		return nil, nil
	}

	var res []*inventory.Asset
	for _, path := range paths {
		res = append(res, &inventory.Asset{
			Connections: []*inventory.Config{{
				Type: "cloudformation",
				Options: map[string]string{
					"ssh-url":  repo.SshUrl.Data,
					"http-url": repo.CloneUrl.Data,
					"path":     path,
				},
				Credentials: creds,
			}},
		})
	}
	return res, nil
}

// cloudformationTemplatePaths searches the repository for CloudFormation/SAM
// templates. Because CloudFormation templates share the .yaml/.json extensions
// with many other config files, we match on the template marker
// `AWSTemplateFormatVersion` rather than the extension alone.
func cloudformationTemplatePaths(ctx context.Context, client *github.Client, repo *mqlGithubRepository) ([]string, error) {
	query := "repo:" + repo.FullName.Data + " AWSTemplateFormatVersion"
	results, err := searchCode(ctx, client, query)
	if err != nil {
		return nil, err
	}

	var paths []string
	seen := map[string]bool{}
	for _, code := range results {
		path := code.GetPath()
		if isHiddenPath(path) || seen[path] {
			continue
		}
		switch strings.ToLower(gopath.Ext(path)) {
		case ".yaml", ".yml", ".json", ".template":
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// isDockerfile reports whether a base file name follows a Dockerfile naming
// convention: `Dockerfile`, `Dockerfile.<suffix>` (e.g. Dockerfile.prod), or
// `<prefix>.Dockerfile`/`<prefix>.dockerfile` (e.g. app.Dockerfile). It rejects
// unrelated names that merely begin with "Dockerfile", like `DockerfileLint.md`.
func isDockerfile(base string) bool {
	return base == "Dockerfile" ||
		strings.HasPrefix(base, "Dockerfile.") ||
		strings.HasSuffix(base, ".Dockerfile") ||
		strings.HasSuffix(base, ".dockerfile")
}

// iacDir returns the repo-relative directory containing the given file, with a
// top-level file (".") normalized to "" so it joins onto the clone root
// cleanly. Repository paths are always slash-separated, so this uses path
// rather than path/filepath, which on Windows would treat the whole path as a
// single segment.
func iacDir(filePath string) string {
	if dir := gopath.Dir(filePath); dir != "." {
		return dir
	}
	return ""
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
