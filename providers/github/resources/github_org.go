// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

type mqlGithubOrganizationInternal struct {
	repoCacheMap map[string]*mqlGithubRepository
}

func (g *mqlGithubOrganization) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.organization/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func initGithubOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	defer logger.FuncDur(time.Now(), "provider.github.initGithubOrganization")

	conn := runtime.Connection.(*connection.GithubConnection)

	orgId, err := conn.Organization()
	if err != nil {
		return nil, nil, err
	}

	name := orgId.Name
	if name == "" {
		if x, ok := args["name"]; ok {
			name = x.Value.(string)
		}
	}

	org, err := getOrg(conn.Context(), runtime, conn, name)
	if err != nil {
		return args, nil, err
	}

	args["id"] = llx.IntDataPtr(org.ID)
	args["name"] = llx.StringData(name)
	args["login"] = llx.StringDataPtr(org.Login)
	args["nodeId"] = llx.StringDataPtr(org.NodeID)
	args["company"] = llx.StringDataPtr(org.Company)
	args["blog"] = llx.StringDataPtr(org.Blog)
	args["location"] = llx.StringDataPtr(org.Location)
	args["email"] = llx.StringDataPtr(org.Email)
	args["twitterUsername"] = llx.StringDataPtr(org.TwitterUsername)
	args["avatarUrl"] = llx.StringDataPtr(org.AvatarURL)
	args["followers"] = llx.IntDataDefault(org.Followers, 0)
	args["following"] = llx.IntDataDefault(org.Following, 0)
	args["description"] = llx.StringDataPtr(org.Description)
	args["createdAt"] = llx.TimeDataPtr(githubTimestamp(org.CreatedAt))
	args["updatedAt"] = llx.TimeDataPtr(githubTimestamp(org.UpdatedAt))
	args["totalPrivateRepos"] = llx.IntDataPtr(org.TotalPrivateRepos)
	args["totalPublicRepos"] = llx.IntDataPtr(org.PublicRepos)
	args["ownedPrivateRepos"] = llx.IntDataPtr(org.OwnedPrivateRepos)
	args["privateGists"] = llx.IntDataDefault(org.PrivateGists, 0)
	args["diskUsage"] = llx.IntDataDefault(org.DiskUsage, 0)
	args["collaborators"] = llx.IntDataDefault(org.Collaborators, 0)
	args["billingEmail"] = llx.StringDataPtr(org.BillingEmail)

	plan, _ := convert.JsonToDict(org.Plan)
	args["plan"] = llx.MapData(plan, types.Any)

	// Use BoolDataPtr so an unset value (GitHub returns null when the caller
	// lacks org-admin scope) reads as MQL null rather than false — otherwise a
	// scoped-down token would report 2FA-not-required for an org that enforces it.
	args["twoFactorRequirementEnabled"] = llx.BoolDataPtr(org.TwoFactorRequirementEnabled)
	args["isVerified"] = llx.BoolData(convert.ToValue(org.IsVerified))

	args["hasOrganizationProjects"] = llx.BoolData(convert.ToValue(org.HasOrganizationProjects))
	args["hasRepositoryProjects"] = llx.BoolData(convert.ToValue(org.HasRepositoryProjects))

	args["defaultRepositoryPermission"] = llx.StringDataPtr(org.DefaultRepoPermission)
	args["membersCanCreateRepositories"] = llx.BoolData(convert.ToValue(org.MembersCanCreateRepos))
	args["membersCanCreatePublicRepositories"] = llx.BoolData(convert.ToValue(org.MembersCanCreatePublicRepos))
	args["membersCanCreatePrivateRepositories"] = llx.BoolData(convert.ToValue(org.MembersCanCreatePrivateRepos))
	args["membersCanCreateInternalRepositories"] = llx.BoolData(convert.ToValue(org.MembersCanCreateInternalRepos))
	args["membersCanCreatePages"] = llx.BoolData(convert.ToValue(org.MembersCanCreatePages))
	args["membersCanCreatePublicPages"] = llx.BoolData(convert.ToValue(org.MembersCanCreatePublicPages))
	args["membersCanCreatePrivatePages"] = llx.BoolData(convert.ToValue(org.MembersCanCreatePrivatePages))
	args["membersCanForkPrivateRepos"] = llx.BoolData(convert.ToValue(org.MembersCanForkPrivateRepos))

	// Security settings for new repositories
	args["dependabotAlertsEnabledForNewRepos"] = llx.BoolData(convert.ToValue(org.DependabotAlertsEnabledForNewRepos))
	args["dependabotSecurityUpdatesEnabledForNewRepos"] = llx.BoolData(convert.ToValue(org.DependabotSecurityUpdatesEnabledForNewRepos))
	args["advancedSecurityEnabledForNewRepos"] = llx.BoolData(convert.ToValue(org.AdvancedSecurityEnabledForNewRepos))
	args["secretScanningEnabledForNewRepos"] = llx.BoolData(convert.ToValue(org.SecretScanningEnabledForNewRepos))
	args["secretScanningPushProtectionEnabledForNewRepos"] = llx.BoolData(convert.ToValue(org.SecretScanningPushProtectionEnabledForNewRepos))
	args["secretScanningValidityChecksEnabled"] = llx.BoolData(convert.ToValue(org.SecretScanningValidityChecksEnabled))

	// Member permissions
	args["membersCanDeleteRepositories"] = llx.BoolData(convert.ToValue(org.MembersCanDeleteRepositories))
	args["membersCanChangeRepoVisibility"] = llx.BoolData(convert.ToValue(org.MembersCanChangeRepoVisibility))
	args["membersCanDeleteIssues"] = llx.BoolData(convert.ToValue(org.MembersCanDeleteIssues))
	args["readersCanCreateDiscussions"] = llx.BoolData(convert.ToValue(org.ReadersCanCreateDiscussions))

	// Additional security and governance fields
	args["webCommitSignoffRequired"] = llx.BoolData(convert.ToValue(org.WebCommitSignoffRequired))
	args["membersCanInviteOutsideCollaborators"] = llx.BoolData(convert.ToValue(org.MembersCanInviteOutsideCollaborators))
	args["dependencyGraphEnabledForNewRepos"] = llx.BoolData(convert.ToValue(org.DependencyGraphEnabledForNewRepos))
	args["membersCanCreateTeams"] = llx.BoolData(convert.ToValue(org.MembersCanCreateTeams))
	args["membersCanViewDependencyInsights"] = llx.BoolData(convert.ToValue(org.MembersCanViewDependencyInsights))
	args["defaultRepositoryBranch"] = llx.StringDataPtr(org.DefaultRepositoryBranch)

	return args, nil, nil
}

func (g *mqlGithubOrganizationCustomProperty) id() (string, error) {
	return "github.organization.customProperty/" + g.Name.Data, nil
}

func (g *mqlGithubOrganization) customProperties() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	// API doesn't have pagination:
	//
	// https://docs.github.com/en/rest/orgs/custom-properties?apiVersion=2022-11-28#get-all-custom-properties-for-an-organization--parameters
	customProperties, _, err := conn.Client().Organizations.GetAllCustomProperties(conn.Context(), orgLogin)
	if err != nil {
		return nil, err
	}

	resources := []any{}
	for _, property := range customProperties {
		// Convert DefaultValue from any to string
		var defaultValue string
		if property.DefaultValue != nil {
			if s, ok := property.DefaultValue.(string); ok {
				defaultValue = s
			}
		}

		r, err := CreateResource(g.MqlRuntime, "github.organization.customProperty", map[string]*llx.RawData{
			"name":             llx.StringDataPtr(property.PropertyName),
			"description":      llx.StringDataPtr(property.Description),
			"sourceType":       llx.StringDataPtr(property.SourceType),
			"valueType":        llx.StringData(string(property.ValueType)),
			"required":         llx.BoolDataPtr(property.Required),
			"defaultValue":     llx.StringData(defaultValue),
			"allowedValues":    llx.ArrayData(convert.SliceAnyToInterface[string](property.AllowedValues), types.String),
			"valuesEditableBy": llx.StringDataPtr(property.ValuesEditableBy),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, r)
	}

	return resources, nil
}

func (g *mqlGithubOrganization) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allMembers []*github.User
	for {
		members, resp, err := conn.Client().Organizations.ListMembers(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allMembers = append(allMembers, members...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allMembers {
		member := allMembers[i]

		r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataDefault(member.ID, 0),
			"login": llx.StringDataPtr(member.Login),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func (g *mqlGithubOrganization) outsideCollaborators() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListOutsideCollaboratorsOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allUsers []*github.User
	for {
		users, resp, err := conn.Client().Organizations.ListOutsideCollaborators(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
				return nil, nil
			}
			return nil, err
		}
		allUsers = append(allUsers, users...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allUsers {
		u := allUsers[i]
		r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataDefault(u.ID, 0),
			"login": llx.StringDataPtr(u.Login),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubOrganization) owners() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
		Role:        "admin",
	}
	var allMembers []*github.User
	for {
		members, resp, err := conn.Client().Organizations.ListMembers(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}

		allMembers = append(allMembers, members...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allMembers {
		member := allMembers[i]

		var id int64
		if member.ID != nil {
			id = *member.ID
		}

		r, err := CreateResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":              llx.IntData(id),
			"login":           llx.StringDataPtr(member.Login),
			"name":            llx.StringDataPtr(member.Name),
			"email":           llx.StringDataPtr(member.Email),
			"blog":            llx.StringData(member.GetBlog()),
			"location":        llx.StringData(member.GetLocation()),
			"avatarUrl":       llx.StringData(member.GetAvatarURL()),
			"followers":       llx.IntData(int64(member.GetFollowers())),
			"following":       llx.IntData(int64(member.GetFollowing())),
			"twitterUsername": llx.StringData(member.GetTwitterUsername()),
			"bio":             llx.StringDataPtr(member.Bio),
			"createdAt":       llx.TimeDataPtr(githubTimestamp(member.CreatedAt)),
			"updatedAt":       llx.TimeDataPtr(githubTimestamp(member.UpdatedAt)),
			"suspendedAt":     llx.TimeDataPtr(githubTimestamp(member.SuspendedAt)),
			"company":         llx.StringDataPtr(member.Company),
			"hireable":        llx.BoolData(member.GetHireable()),
			"siteAdmin":       llx.BoolData(member.GetSiteAdmin()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func (g *mqlGithubOrganization) teams() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allTeams []*github.Team
	for {
		teams, resp, err := conn.Client().Teams.ListTeams(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allTeams = append(allTeams, teams...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allTeams {
		team := allTeams[i]
		r, err := CreateResource(g.MqlRuntime, "github.team", map[string]*llx.RawData{
			"id":                llx.IntDataPtr(team.ID),
			"name":              llx.StringDataPtr(team.Name),
			"description":       llx.StringDataPtr(team.Description),
			"slug":              llx.StringDataPtr(team.Slug),
			"privacy":           llx.StringDataPtr(team.Privacy),
			"defaultPermission": llx.StringDataPtr(team.Permission),
			"type":              llx.StringDataPtr(team.Type),
			"organization":      llx.ResourceData(g, g.MqlName()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func (g *mqlGithubOrganization) repositories() ([]any, error) {
	defer logger.FuncDur(time.Now(), "provider.github.repositories")

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data
	listOpts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			PerPage: paginationPerPage,
			Page:    1,
		},
		Type: "all",
	}

	log.Debug().
		Str("organization", g.Name.Data).
		Msg("list repositories")

	// Paginate via resp.NextPage rather than the org's total_private_repos +
	// public_repos counters. Those counters are unreliable on GitHub Enterprise
	// and with GitHub App / fine-grained PAT auth, and trusting them caused
	// scans to silently truncate at one page (see provider regression from #6244).
	var allRepos []*github.Repository
	for {
		repos, resp, err := conn.Client().Repositories.ListByOrg(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	if g.repoCacheMap == nil {
		g.repoCacheMap = make(map[string]*mqlGithubRepository)
	}

	res := make([]any, 0, len(allRepos))
	for i := range allRepos {
		repo := allRepos[i]
		r, err := newMqlGithubRepository(g.MqlRuntime, repo)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
		g.repoCacheMap[repo.GetName()] = r
	}

	return res, nil
}

func (g *mqlGithubOrganization) webhooks() ([]any, error) {
	defer logger.FuncDur(time.Now(), "provider.github.webhooks")

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	ownerLogin := g.Login.Data

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allHooks []*github.Hook
	for {
		hooks, resp, err := conn.Client().Organizations.ListHooks(conn.Context(), ownerLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allHooks = append(allHooks, hooks...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allHooks {
		h := allHooks[i]
		config, err := convert.JsonToDict(h.Config)
		if err != nil {
			return nil, err
		}

		mqlUser, err := CreateResource(g.MqlRuntime, "github.webhook", map[string]*llx.RawData{
			"id":          llx.IntDataPtr(h.ID),
			"name":        llx.StringDataPtr(h.Name),
			"events":      llx.ArrayData(convert.SliceAnyToInterface[string](h.Events), types.String),
			"config":      llx.MapData(config, types.Any),
			"contentType": llx.StringData(h.Config.GetContentType()),
			"insecureSsl": llx.BoolData(h.Config.GetInsecureSSL() == "1"),
			"url":         llx.StringDataPtr(h.URL),
			"active":      llx.BoolDataPtr(h.Active),
			"createdAt":   llx.TimeDataPtr(githubTimestamp(h.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(githubTimestamp(h.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}

	return res, nil
}

func (g *mqlGithubRepositoryFineGrainedPermission) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return "github.repositoryFineGrainedPermission/" + g.Name.Data, nil
}

func (g *mqlGithubOrganization) repositoryFineGrainedPermissions() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	perms, _, err := conn.Client().Organizations.ListRepositoryFineGrainedPermissions(conn.Context(), orgLogin)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(perms))
	for _, p := range perms {
		r, err := CreateResource(g.MqlRuntime, "github.repositoryFineGrainedPermission", map[string]*llx.RawData{
			"name":        llx.StringData(p.Name),
			"description": llx.StringData(p.Description),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

type mqlGithubPackageInternal struct {
	packageRepository string
	parentResource    *mqlGithubOrganization
}

func (g *mqlGithubOrganization) packages() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	ownerLogin := g.Login.Data

	pkgTypes := []string{"npm", "maven", "rubygems", "docker", "nuget", "container"}
	res := []any{}
	for i := range pkgTypes {
		listOpts := &github.PackageListOptions{
			ListOptions: github.ListOptions{PerPage: paginationPerPage},
			PackageType: github.String(pkgTypes[i]),
		}

		var allPackages []*github.Package
		for {
			packages, resp, err := conn.Client().Organizations.ListPackages(conn.Context(), ownerLogin, listOpts)
			if err != nil {
				if strings.Contains(err.Error(), "404") {
					return nil, nil
				}
				return nil, err
			}
			allPackages = append(allPackages, packages...)
			if resp.NextPage == 0 {
				break
			}
			listOpts.Page = resp.NextPage
		}

		for i := range allPackages {
			p := allPackages[i]

			owner, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntData(p.GetOwner().GetID()),
				"login": llx.StringData(p.GetOwner().GetLogin()),
			})
			if err != nil {
				return nil, err
			}

			mqlGhPackage, err := CreateResource(g.MqlRuntime, "github.package", map[string]*llx.RawData{
				"id":           llx.IntDataPtr(p.ID),
				"name":         llx.StringDataPtr(p.Name),
				"packageType":  llx.StringDataPtr(p.PackageType),
				"owner":        llx.ResourceData(owner, owner.MqlName()),
				"createdAt":    llx.TimeDataPtr(githubTimestamp(p.CreatedAt)),
				"updatedAt":    llx.TimeDataPtr(githubTimestamp(p.UpdatedAt)),
				"versionCount": llx.IntDataPtr(p.VersionCount),
				"visibility":   llx.StringDataPtr(p.Visibility),
			})
			if err != nil {
				return nil, err
			}
			pkg := mqlGhPackage.(*mqlGithubPackage)
			pkg.parentResource = g

			// NOTE: we need to fetch repo separately because the Github repo object is not complete, instead of
			// call the repo fetching all the time, we make this lazy loading
			if p.Repository != nil && p.Repository.Name != nil {
				pkg.packageRepository = convert.ToValue(p.Repository.Name)
			}
			res = append(res, pkg)
		}
	}

	return res, nil
}

func (g *mqlGithubPackage) repository() (*mqlGithubRepository, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.packageRepository == "" {
		// Container and other registry packages are not always attached to a
		// repository; that is a valid empty state, not a failure.
		g.Repository.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	repoName := g.packageRepository

	// When the package was discovered via an organization, the org's repo
	// list is already cached. Reuse it before falling back to a per-package
	// Repositories.Get call.
	if g.parentResource != nil {
		if cached, ok := g.parentResource.repoCacheMap[repoName]; ok && cached != nil {
			return cached, nil
		}
	}

	if g.Owner.Error != nil {
		return nil, g.Owner.Error
	}
	owner := g.Owner.Data
	if owner == nil {
		g.Repository.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	if owner.Login.Error != nil {
		return nil, owner.Login.Error
	}
	ownerLogin := owner.Login.Data

	repo, _, err := conn.Client().Repositories.Get(conn.Context(), ownerLogin, repoName)
	if err != nil {
		return nil, err
	}
	return newMqlGithubRepository(g.MqlRuntime, repo)
}

func (g *mqlGithubOrganization) installations() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListOptions{
		PerPage: paginationPerPage,
	}
	var allOrgInstallations []*github.Installation
	for {
		orgInstallations, resp, err := conn.Client().Organizations.ListInstallations(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allOrgInstallations = append(allOrgInstallations, orgInstallations.Installations...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allOrgInstallations {
		app := allOrgInstallations[i]

		var id int64
		if app.ID != nil {
			id = *app.ID
		}

		permsDict, _ := convert.JsonToDict(app.Permissions)

		var suspendedBy plugin.Resource
		if app.SuspendedBy != nil && app.SuspendedBy.GetID() != 0 {
			sb, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntData(app.SuspendedBy.GetID()),
				"login": llx.StringData(app.SuspendedBy.GetLogin()),
			})
			if err != nil {
				return nil, err
			}
			suspendedBy = sb
		}

		args := map[string]*llx.RawData{
			"id":                  llx.IntData(id),
			"appId":               llx.IntDataPtr(app.AppID),
			"appSlug":             llx.StringDataPtr(app.AppSlug),
			"createdAt":           llx.TimeDataPtr(githubTimestamp(app.CreatedAt)),
			"updatedAt":           llx.TimeDataPtr(githubTimestamp(app.UpdatedAt)),
			"targetType":          llx.StringDataPtr(app.TargetType),
			"repositorySelection": llx.StringDataPtr(app.RepositorySelection),
			"events":              llx.ArrayData(convert.SliceAnyToInterface[string](app.Events), types.String),
			"permissions":         llx.MapData(permsDict, types.Any),
			"suspendedAt":         llx.TimeDataPtr(githubTimestamp(app.SuspendedAt)),
		}
		if suspendedBy != nil {
			args["suspendedBy"] = llx.ResourceData(suspendedBy, suspendedBy.MqlName())
		}

		r, err := CreateResource(g.MqlRuntime, "github.installation", args)
		if err != nil {
			return nil, err
		}
		mqlInst := r.(*mqlGithubInstallation)
		if suspendedBy == nil {
			mqlInst.SuspendedBy.State = plugin.StateIsSet | plugin.StateIsNull
		}
		mqlInst.cacheOrgLogin = orgLogin
		mqlInst.cacheInstallationID = id
		res = append(res, mqlInst)
	}

	return res, nil
}

func (g *mqlGithubOrganizationActionsSettings) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubOrganization) actionsSettings() (*mqlGithubOrganizationActionsSettings, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	perms, _, err := conn.Client().Organizations.GetActionsPermissions(conn.Context(), orgLogin)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
			g.ActionsSettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	wfPerms, _, err := conn.Client().Actions.GetDefaultWorkflowPermissionsInOrganization(conn.Context(), orgLogin)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "403") {
			g.ActionsSettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var defaultWfPerms string
	var canApprove bool
	if wfPerms != nil {
		defaultWfPerms = wfPerms.GetDefaultWorkflowPermissions()
		canApprove = wfPerms.GetCanApprovePullRequestReviews()
	}

	res, err := CreateResource(g.MqlRuntime, "github.organizationActionsSettings", map[string]*llx.RawData{
		"__id":                         llx.StringData("github.organizationActionsSettings/" + orgLogin),
		"enabledRepositories":          llx.StringDataPtr(perms.EnabledRepositories),
		"allowedActions":               llx.StringDataPtr(perms.AllowedActions),
		"shaPinningRequired":           llx.BoolDataPtr(perms.SHAPinningRequired),
		"defaultWorkflowPermissions":   llx.StringData(defaultWfPerms),
		"canApprovePullRequestReviews": llx.BoolData(canApprove),
	})
	if err != nil {
		return nil, err
	}
	settings := res.(*mqlGithubOrganizationActionsSettings)
	settings.orgLogin = orgLogin
	return settings, nil
}
