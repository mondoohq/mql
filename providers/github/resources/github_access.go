// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// ---------- Cache keys ----------
//
// Each of these keys a resource that is only unique within an organization or
// a repository. They are passed to CreateResource as an explicit "__id":
// the generated constructor computes a missing __id by calling id() from
// inside CreateResource, before the caller can assign anything to the
// resource, so a key built from a field assigned afterwards would resolve
// against an empty string for every instance.

func organizationMembershipID(orgLogin, login string) string {
	return "github.organization.membership/" + orgLogin + "/" + login
}

func organizationInvitationID(orgLogin string, id int64) string {
	return "github.organization.invitation/" + orgLogin + "/" + strconv.FormatInt(id, 10)
}

func repositoryTeamID(repoFullName, slug string) string {
	return "github.repository.team/" + repoFullName + "/" + slug
}

// ---------- Organization memberships ----------

func (g *mqlGithubOrganizationMembership) id() (string, error) {
	return g.__id, nil
}

// organizationResource resolves the organization with the given login so that
// team resources carry the organization their member and repository lookups
// need. It reports null when the organization cannot be resolved, which leaves
// those lookups reporting that no organization was specified rather than
// failing the listing that produced the team.
func organizationResource(runtime *plugin.Runtime, login string) *llx.RawData {
	if login == "" {
		return llx.NilData
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{
		"name": llx.StringData(login),
	})
	if err != nil {
		log.Debug().Err(err).Str("org", login).
			Msg("could not resolve the organization owning a team")
		return llx.NilData
	}
	return llx.ResourceData(org, org.MqlName())
}

// loginSet indexes a list of accounts by login for membership tests.
func loginSet(users []*github.User) map[string]struct{} {
	set := make(map[string]struct{}, len(users))
	for _, user := range users {
		set[user.GetLogin()] = struct{}{}
	}
	return set
}

// membershipRole reports the role a member holds in the organization, which is
// admin for organization owners and member for everyone else. It returns nil
// when the owner list could not be read, since reporting every member as
// "member" would understate the access of an owner we simply could not see.
func membershipRole(login string, adminLogins map[string]struct{}, known bool) *string {
	if !known {
		return nil
	}
	role := "member"
	if _, ok := adminLogins[login]; ok {
		role = "admin"
	}
	return &role
}

// membershipTwoFactorEnabled reports whether the member's account has
// two-factor authentication enabled, deriving it from the set of accounts
// GitHub reported as lacking it. It returns nil when that set could not be
// read, so an unreadable state stays unknown instead of being reported as
// enabled.
func membershipTwoFactorEnabled(login string, noTwoFactorLogins map[string]struct{}, known bool) *bool {
	if !known {
		return nil
	}
	_, disabled := noTwoFactorLogins[login]
	enabled := !disabled
	return &enabled
}

// listOrgMembers pages through the organization member list with the given
// options and returns every member.
func listOrgMembers(conn *connection.GithubConnection, orgLogin string, opts *github.ListMembersOptions) ([]*github.User, error) {
	opts.ListOptions = github.ListOptions{PerPage: paginationPerPage}
	var all []*github.User
	for {
		members, resp, err := conn.Client().Organizations.ListMembers(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, members...)
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

// memberships pairs every organization member with the role they hold and
// whether their account has two-factor authentication enabled.
//
// Both facts are derived from filtered member listings rather than a
// per-member membership lookup: asking GitHub for the owners and for the
// accounts without two-factor authentication costs two requests regardless of
// how many members the organization has, where GetOrgMembership would cost one
// request per member.
func (g *mqlGithubOrganization) memberships() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	allMembers, err := listOrgMembers(conn, orgLogin, &github.ListMembersOptions{})
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Str("org", orgLogin).Msg("organization members are not accessible")
			return nil, nil
		}
		return nil, err
	}

	// The owner and two-factor listings are each narrower than the plain member
	// listing, so either can be refused on a token that can still see the
	// membership itself. Losing one of them degrades that fact to unknown
	// rather than failing the whole listing.
	rolesKnown := true
	admins, err := listOrgMembers(conn, orgLogin, &github.ListMembersOptions{Role: "admin"})
	if err != nil {
		if !isAccessDeniedOrNotFound(err) {
			return nil, err
		}
		log.Debug().Err(err).Str("org", orgLogin).
			Msg("organization owners are not accessible, member roles stay unknown")
		rolesKnown = false
	}
	adminLogins := loginSet(admins)

	// Listing members without two-factor authentication requires organization
	// owner access. When the token does not have it, the two-factor state of
	// every member stays unknown rather than being reported as enabled.
	twoFactorKnown := true
	without2FA, err := listOrgMembers(conn, orgLogin, &github.ListMembersOptions{Filter: "2fa_disabled"})
	if err != nil {
		if !isAccessDeniedOrNotFound(err) {
			return nil, err
		}
		log.Debug().Err(err).Str("org", orgLogin).
			Msg("two-factor authentication status is not accessible (requires organization owner access)")
		twoFactorKnown = false
	}
	noTwoFactorLogins := loginSet(without2FA)

	res := []any{}
	for _, member := range allMembers {
		login := member.GetLogin()

		user, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataDefault(member.ID, 0),
			"login": llx.StringData(login),
		})
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(g.MqlRuntime, "github.organization.membership", map[string]*llx.RawData{
			"__id":             llx.StringData(organizationMembershipID(orgLogin, login)),
			"user":             llx.ResourceData(user, user.MqlName()),
			"login":            llx.StringData(login),
			"role":             llx.StringDataPtr(membershipRole(login, adminLogins, rolesKnown)),
			"twoFactorEnabled": llx.BoolDataPtr(membershipTwoFactorEnabled(login, noTwoFactorLogins, twoFactorKnown)),
			"siteAdmin":        llx.BoolData(member.GetSiteAdmin()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

// ---------- Organization invitations ----------

func (g *mqlGithubOrganizationInvitation) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubOrganization) pendingInvitations() ([]any, error) {
	return g.listInvitations(func(conn *connection.GithubConnection, orgLogin string, opts *github.ListOptions) ([]*github.Invitation, *github.Response, error) {
		return conn.Client().Organizations.ListPendingOrgInvitations(conn.Context(), orgLogin, opts)
	})
}

func (g *mqlGithubOrganization) failedInvitations() ([]any, error) {
	return g.listInvitations(func(conn *connection.GithubConnection, orgLogin string, opts *github.ListOptions) ([]*github.Invitation, *github.Response, error) {
		return conn.Client().Organizations.ListFailedOrgInvitations(conn.Context(), orgLogin, opts)
	})
}

func (g *mqlGithubOrganization) listInvitations(
	list func(*connection.GithubConnection, string, *github.ListOptions) ([]*github.Invitation, *github.Response, error),
) ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allInvitations []*github.Invitation
	for {
		invitations, resp, err := list(conn, orgLogin, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("org", orgLogin).
					Msg("organization invitations are not accessible (requires organization owner access)")
				return nil, nil
			}
			return nil, err
		}
		allInvitations = append(allInvitations, invitations...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for _, invitation := range allInvitations {
		args := map[string]*llx.RawData{
			"__id":         llx.StringData(organizationInvitationID(orgLogin, invitation.GetID())),
			"id":           llx.IntDataDefault(invitation.ID, 0),
			"login":        llx.StringData(invitation.GetLogin()),
			"email":        llx.StringData(invitation.GetEmail()),
			"role":         llx.StringData(invitation.GetRole()),
			"createdAt":    llx.TimeDataPtr(githubTimestamp(invitation.CreatedAt)),
			"failedAt":     llx.TimeDataPtr(githubTimestamp(invitation.FailedAt)),
			"failedReason": llx.StringData(invitation.GetFailedReason()),
			"teamCount":    llx.IntData(int64(invitation.GetTeamCount())),
		}

		if invitation.Inviter != nil {
			inviter, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataDefault(invitation.Inviter.ID, 0),
				"login": llx.StringDataPtr(invitation.Inviter.Login),
			})
			if err != nil {
				return nil, err
			}
			args["inviter"] = llx.ResourceData(inviter, inviter.MqlName())
		} else {
			args["inviter"] = llx.NilData
		}

		r, err := CreateResource(g.MqlRuntime, "github.organization.invitation", args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

// ---------- Repository team access grants ----------

func (g *mqlGithubRepositoryTeam) id() (string, error) {
	return g.__id, nil
}

// teamPermissionLevels returns the permission names a grant satisfies, ordered
// from the highest level down. GitHub reports these as a map of level to
// boolean; a grant satisfies every level at or below the one it confers.
func teamPermissionLevels(permissions map[string]bool) []string {
	// Ordered from most to least privileged so the resulting list reads the
	// same way for every grant.
	ordered := []string{"admin", "maintain", "push", "triage", "pull"}
	levels := []string{}
	for _, name := range ordered {
		if permissions[name] {
			levels = append(levels, name)
		}
	}
	return levels
}

func (g *mqlGithubRepository) teams() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}
	repoFullName := ownerLogin + "/" + repoName

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allTeams []*github.Team
	for {
		teams, resp, err := conn.Client().Repositories.ListTeams(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("repo", repoFullName).
					Msg("repository team grants are not accessible (requires push access to the repository)")
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

	// The teams all belong to the repository's owning organization, so it is
	// resolved once and shared. Without it their member and repository
	// lookups have no organization to query against.
	organization := organizationResource(g.MqlRuntime, ownerLogin)

	res := []any{}
	for _, team := range allTeams {
		mqlTeam, err := CreateResource(g.MqlRuntime, "github.team", map[string]*llx.RawData{
			"id":                llx.IntDataPtr(team.ID),
			"name":              llx.StringDataPtr(team.Name),
			"description":       llx.StringDataPtr(team.Description),
			"slug":              llx.StringDataPtr(team.Slug),
			"privacy":           llx.StringDataPtr(team.Privacy),
			"defaultPermission": llx.StringDataPtr(team.Permission),
			"type":              llx.StringDataPtr(team.Type),
			"organization":      organization,
		})
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(g.MqlRuntime, "github.repository.team", map[string]*llx.RawData{
			"__id":         llx.StringData(repositoryTeamID(repoFullName, team.GetSlug())),
			"team":         llx.ResourceData(mqlTeam, mqlTeam.MqlName()),
			"slug":         llx.StringData(team.GetSlug()),
			"permission":   llx.StringData(team.GetPermission()),
			"accessSource": llx.StringData(team.GetAccessSource()),
			"permissions":  llx.ArrayData(convert.SliceAnyToInterface(teamPermissionLevels(team.Permissions)), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

// ---------- Organization role assignments ----------

type mqlGithubOrganizationCustomRoleInternal struct {
	cacheOrgLogin string
}

// users returns the accounts the organization role is assigned to directly.
func (g *mqlGithubOrganizationCustomRole) users() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgLogin, roleID, err := g.roleLookupKeys()
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	res := []any{}
	for {
		users, resp, err := conn.Client().Organizations.ListUsersAssignedToOrgRole(conn.Context(), orgLogin, roleID, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("org", orgLogin).Int64("role", roleID).
					Msg("organization role user assignments are not accessible")
				return nil, nil
			}
			return nil, err
		}
		for _, user := range users {
			r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataDefault(user.ID, 0),
				"login": llx.StringDataPtr(user.Login),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	return res, nil
}

// teams returns the teams the organization role is assigned to.
func (g *mqlGithubOrganizationCustomRole) teams() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgLogin, roleID, err := g.roleLookupKeys()
	if err != nil {
		return nil, err
	}

	organization := organizationResource(g.MqlRuntime, orgLogin)

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	res := []any{}
	for {
		teams, resp, err := conn.Client().Organizations.ListTeamsAssignedToOrgRole(conn.Context(), orgLogin, roleID, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("org", orgLogin).Int64("role", roleID).
					Msg("organization role team assignments are not accessible")
				return nil, nil
			}
			return nil, err
		}
		for _, team := range teams {
			r, err := CreateResource(g.MqlRuntime, "github.team", map[string]*llx.RawData{
				"id":                llx.IntDataPtr(team.ID),
				"name":              llx.StringDataPtr(team.Name),
				"description":       llx.StringDataPtr(team.Description),
				"slug":              llx.StringDataPtr(team.Slug),
				"privacy":           llx.StringDataPtr(team.Privacy),
				"defaultPermission": llx.StringDataPtr(team.Permission),
				"type":              llx.StringDataPtr(team.Type),
				"organization":      organization,
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	return res, nil
}

// roleLookupKeys returns the organization login and role ID needed to query the
// role's assignments.
func (g *mqlGithubOrganizationCustomRole) roleLookupKeys() (string, int64, error) {
	if g.Id.Error != nil {
		return "", 0, g.Id.Error
	}
	orgLogin := g.cacheOrgLogin
	if orgLogin == "" {
		// The role was reached directly rather than through the organization
		// that owns it, so fall back to the connected organization.
		org, err := NewResource(g.MqlRuntime, "github.organization", map[string]*llx.RawData{})
		if err != nil {
			return "", 0, err
		}
		login := org.(*mqlGithubOrganization).GetLogin()
		if login.Error != nil {
			return "", 0, login.Error
		}
		orgLogin = strings.TrimSpace(login.Data)
	}
	return orgLogin, g.Id.Data, nil
}
