// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// This file models identity at group scope: the credentials individual members
// carry, the non-human accounts the group runs automation with, the authorities
// it trusts for SSH, the identity-provider links behind its membership, and the
// requests waiting to join it.
//
// Most of these endpoints are Ultimate-only and owner-only. GitLab answers 403
// or 404 rather than distinguishing "not licensed" from "not permitted", and in
// both cases the honest result is an empty list rather than a failed scan --
// see isTierOrPermissionGated.
//
// Token secrets are not modeled. PersonalAccessToken.Token carries a live
// credential on some responses and is omitted everywhere.

// isTierOrPermissionGated reports whether a failed request should degrade to an
// empty result. GitLab returns 403 when the caller's role is too low and 404
// when the feature is not licensed (and sometimes the reverse), so neither code
// can be read as "this definitely does not exist" -- but both mean the caller
// cannot see the data, which is not a scan failure.
func isTierOrPermissionGated(resp *gitlab.Response) bool {
	return resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404)
}

//
// Enterprise user credentials
//

func (t *mqlGitlabGroupEnterpriseAccessToken) id() (string, error) {
	return groupScopedID("gitlab.group.enterpriseAccessToken", t.groupID, strconv.FormatInt(t.Id.Data, 10)), nil
}

// mqlGitlabGroupEnterpriseAccessTokenInternal carries the owning group (for the
// cache key) and the user id the typed accessor resolves lazily.
type mqlGitlabGroupEnterpriseAccessTokenInternal struct {
	groupID     int64
	cacheUserID int64
}

func (t *mqlGitlabGroupEnterpriseAccessToken) user() (*mqlGitlabUser, error) {
	if t.cacheUserID <= 0 {
		t.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(t.MqlRuntime, t.cacheUserID)
}

// enterpriseAccessTokens lists the personal access tokens held by enterprise
// users of the group. Ultimate, and only for group owners.
func (g *mqlGitlabGroup) enterpriseAccessTokens() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)

	var all []*gitlab.GroupPersonalAccessToken
	page := int64(1)
	for {
		tokens, resp, err := conn.Client().GroupCredentials.ListGroupPersonalAccessTokens(groupID, &gitlab.ListGroupPersonalAccessTokensOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Int("group", groupID).
					Msg("gitlab> enterprise access tokens unavailable for this tier or token")
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, tokens...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, token := range all {
		mqlToken, err := CreateResource(g.MqlRuntime, "gitlab.group.enterpriseAccessToken", map[string]*llx.RawData{
			"id":          llx.IntData(token.ID),
			"name":        llx.StringData(token.Name),
			"description": llx.StringData(token.Description),
			"scopes":      llx.ArrayData(convert.SliceAnyToInterface(token.Scopes), types.String),
			"active":      llx.BoolData(token.Active),
			"revoked":     llx.BoolData(token.Revoked),
			"createdAt":   llx.TimeDataPtr(token.CreatedAt),
			"expiresAt":   llx.TimeDataPtr(isoTimePtr(token.ExpiresAt)),
			"lastUsedAt":  llx.TimeDataPtr(token.LastUsedAt),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlToken.(*mqlGitlabGroupEnterpriseAccessToken)
		internal.groupID = g.Id.Data
		internal.cacheUserID = token.UserID

		res = append(res, mqlToken)
	}

	return res, nil
}

func (k *mqlGitlabGroupEnterpriseSshKey) id() (string, error) {
	return groupScopedID("gitlab.group.enterpriseSshKey", k.groupID, strconv.FormatInt(k.Id.Data, 10)), nil
}

type mqlGitlabGroupEnterpriseSshKeyInternal struct {
	groupID     int64
	cacheUserID int64
}

func (k *mqlGitlabGroupEnterpriseSshKey) user() (*mqlGitlabUser, error) {
	if k.cacheUserID <= 0 {
		k.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(k.MqlRuntime, k.cacheUserID)
}

// enterpriseSshKeys lists the SSH keys held by enterprise users of the group.
func (g *mqlGitlabGroup) enterpriseSshKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)

	var all []*gitlab.GroupSSHKey
	page := int64(1)
	for {
		keys, resp, err := conn.Client().GroupCredentials.ListGroupSSHKeys(groupID, &gitlab.ListGroupSSHKeysOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Int("group", groupID).
					Msg("gitlab> enterprise SSH keys unavailable for this tier or token")
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, keys...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, key := range all {
		mqlKey, err := CreateResource(g.MqlRuntime, "gitlab.group.enterpriseSshKey", map[string]*llx.RawData{
			"id":         llx.IntData(key.ID),
			"title":      llx.StringData(key.Title),
			"createdAt":  llx.TimeDataPtr(key.CreatedAt),
			"expiresAt":  llx.TimeDataPtr(key.ExpiresAt),
			"lastUsedAt": llx.TimeDataPtr(key.LastUsedAt),
			"usageType":  llx.StringData(key.UsageType),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlKey.(*mqlGitlabGroupEnterpriseSshKey)
		internal.groupID = g.Id.Data
		internal.cacheUserID = key.UserID

		res = append(res, mqlKey)
	}

	return res, nil
}

//
// Service accounts
//

func (a *mqlGitlabGroupServiceAccount) id() (string, error) {
	return groupScopedID("gitlab.group.serviceAccount", a.groupID, strconv.FormatInt(a.Id.Data, 10)), nil
}

type mqlGitlabGroupServiceAccountInternal struct {
	groupID int64
}

// accessTokens lists the credentials the service account authenticates with.
// This is one API call per account, so it stays lazy.
func (a *mqlGitlabGroupServiceAccount) accessTokens() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.GitLabConnection)

	var all []*gitlab.PersonalAccessToken
	page := int64(1)
	for {
		tokens, resp, err := conn.Client().Groups.ListServiceAccountPersonalAccessTokens(int(a.groupID), a.Id.Data,
			&gitlab.ListServiceAccountPersonalAccessTokensOptions{
				ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
			})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Int64("serviceAccount", a.Id.Data).
					Msg("gitlab> service account tokens unavailable for this tier or token")
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, tokens...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, token := range all {
		// Token is intentionally omitted: it carries a live credential.
		mqlToken, err := CreateResource(a.MqlRuntime, "gitlab.group.enterpriseAccessToken", map[string]*llx.RawData{
			"id":          llx.IntData(token.ID),
			"name":        llx.StringData(token.Name),
			"description": llx.StringData(token.Description),
			"scopes":      llx.ArrayData(convert.SliceAnyToInterface(token.Scopes), types.String),
			"active":      llx.BoolData(token.Active),
			"revoked":     llx.BoolData(token.Revoked),
			"createdAt":   llx.TimeDataPtr(token.CreatedAt),
			"expiresAt":   llx.TimeDataPtr(isoTimePtr(token.ExpiresAt)),
			"lastUsedAt":  llx.TimeDataPtr(token.LastUsedAt),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlToken.(*mqlGitlabGroupEnterpriseAccessToken)
		internal.groupID = a.groupID
		internal.cacheUserID = token.UserID

		res = append(res, mqlToken)
	}

	return res, nil
}

// serviceAccounts lists the non-human identities created at group scope.
func (g *mqlGitlabGroup) serviceAccounts() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)

	var all []*gitlab.GroupServiceAccount
	page := int64(1)
	for {
		accounts, resp, err := conn.Client().Groups.ListServiceAccounts(groupID, &gitlab.ListServiceAccountsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Int("group", groupID).
					Msg("gitlab> service accounts unavailable for this tier or token")
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, accounts...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, account := range all {
		mqlAccount, err := CreateResource(g.MqlRuntime, "gitlab.group.serviceAccount", map[string]*llx.RawData{
			"id":       llx.IntData(account.ID),
			"name":     llx.StringData(account.Name),
			"username": llx.StringData(account.UserName),
			"email":    llx.StringData(account.Email),
		})
		if err != nil {
			return nil, err
		}

		mqlAccount.(*mqlGitlabGroupServiceAccount).groupID = g.Id.Data
		res = append(res, mqlAccount)
	}

	return res, nil
}

//
// SSH certificate authorities
//

func (c *mqlGitlabGroupSshCertificate) id() (string, error) {
	return groupScopedID("gitlab.group.sshCertificate", c.groupID, strconv.FormatInt(c.Id.Data, 10)), nil
}

type mqlGitlabGroupSshCertificateInternal struct {
	groupID int64
}

// sshCertificates lists the certificate authorities trusted for SSH access to
// the group. The endpoint takes no options struct but still paginates, so this
// drives it with gitlab.WithNext the way memberRoles does.
func (g *mqlGitlabGroup) sshCertificates() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)

	var all []*gitlab.GroupSSHCertificate
	var nextOpts []gitlab.RequestOptionFunc
	for {
		certificates, resp, err := conn.Client().GroupSSHCertificates.ListGroupSSHCertificates(groupID, nextOpts...)
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Int("group", groupID).
					Msg("gitlab> SSH certificate authorities unavailable for this tier or token")
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, certificates...)
		next, hasNext := gitlab.WithNext(resp)
		if !hasNext {
			break
		}
		nextOpts = []gitlab.RequestOptionFunc{next}
	}

	res := make([]any, 0, len(all))
	for _, certificate := range all {
		mqlCertificate, err := CreateResource(g.MqlRuntime, "gitlab.group.sshCertificate", map[string]*llx.RawData{
			"id":        llx.IntData(certificate.ID),
			"title":     llx.StringData(certificate.Title),
			"key":       llx.StringData(certificate.Key),
			"createdAt": llx.TimeDataPtr(certificate.CreatedAt),
		})
		if err != nil {
			return nil, err
		}

		mqlCertificate.(*mqlGitlabGroupSshCertificate).groupID = g.Id.Data
		res = append(res, mqlCertificate)
	}

	return res, nil
}

//
// SCIM identities
//

func (i *mqlGitlabGroupScimIdentity) id() (string, error) {
	// A provider that reports an empty external_uid would collapse every
	// member's identity onto one resource, so the user id is part of the key.
	return groupScopedID("gitlab.group.scimIdentity", i.groupID,
		strconv.FormatInt(i.cacheUserID, 10), i.ExternalUid.Data), nil
}

type mqlGitlabGroupScimIdentityInternal struct {
	groupID     int64
	cacheUserID int64
}

func (i *mqlGitlabGroupScimIdentity) user() (*mqlGitlabUser, error) {
	if i.cacheUserID <= 0 {
		i.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(i.MqlRuntime, i.cacheUserID)
}

// scimIdentities lists the identity provider links behind the group's
// membership. Members absent from this list were created outside the identity
// provider and survive deprovisioning there.
func (g *mqlGitlabGroup) scimIdentities() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)

	// The endpoint returns every identity in one response; it takes no
	// pagination options.
	identities, resp, err := conn.Client().GroupSCIM.GetSCIMIdentitiesForGroup(groupID)
	if err != nil {
		if isTierOrPermissionGated(resp) {
			log.Debug().Int("group", groupID).
				Msg("gitlab> SCIM identities unavailable for this tier or token")
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(identities))
	for _, identity := range identities {
		mqlIdentity, err := CreateResource(g.MqlRuntime, "gitlab.group.scimIdentity", map[string]*llx.RawData{
			"externalUid": llx.StringData(identity.ExternalUID),
			"active":      llx.BoolData(identity.Active),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlIdentity.(*mqlGitlabGroupScimIdentity)
		internal.groupID = g.Id.Data
		internal.cacheUserID = identity.UserID

		res = append(res, mqlIdentity)
	}

	return res, nil
}

//
// Access requests
//

func (r *mqlGitlabGroupAccessRequest) id() (string, error) {
	return groupScopedID("gitlab.group.accessRequest", r.groupID, strconv.FormatInt(r.Id.Data, 10)), nil
}

type mqlGitlabGroupAccessRequestInternal struct {
	groupID int64
}

// user returns the requesting account. AccessRequest.ID is the user id.
func (r *mqlGitlabGroupAccessRequest) user() (*mqlGitlabUser, error) {
	if r.Id.Data <= 0 {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(r.MqlRuntime, r.Id.Data)
}

// accessRequests lists requests to join the group.
func (g *mqlGitlabGroup) accessRequests() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := int(g.Id.Data)

	requests, err := listAccessRequests(func(opt *gitlab.ListAccessRequestsOptions) ([]*gitlab.AccessRequest, *gitlab.Response, error) {
		return conn.Client().AccessRequests.ListGroupAccessRequests(groupID, opt)
	}, "group", int64(groupID))
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(requests))
	for _, request := range requests {
		mqlRequest, err := CreateResource(g.MqlRuntime, "gitlab.group.accessRequest", accessRequestFields(request))
		if err != nil {
			return nil, err
		}

		mqlRequest.(*mqlGitlabGroupAccessRequest).groupID = g.Id.Data
		res = append(res, mqlRequest)
	}

	return res, nil
}

func (r *mqlGitlabProjectAccessRequest) id() (string, error) {
	return projectScopedID("gitlab.project.accessRequest", r.projectID, strconv.FormatInt(r.Id.Data, 10)), nil
}

type mqlGitlabProjectAccessRequestInternal struct {
	projectID int64
}

func (r *mqlGitlabProjectAccessRequest) user() (*mqlGitlabUser, error) {
	if r.Id.Data <= 0 {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(r.MqlRuntime, r.Id.Data)
}

// accessRequests lists requests to join the project.
func (p *mqlGitlabProject) accessRequests() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	requests, err := listAccessRequests(func(opt *gitlab.ListAccessRequestsOptions) ([]*gitlab.AccessRequest, *gitlab.Response, error) {
		return conn.Client().AccessRequests.ListProjectAccessRequests(projectID, opt)
	}, "project", int64(projectID))
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(requests))
	for _, request := range requests {
		mqlRequest, err := CreateResource(p.MqlRuntime, "gitlab.project.accessRequest", accessRequestFields(request))
		if err != nil {
			return nil, err
		}

		mqlRequest.(*mqlGitlabProjectAccessRequest).projectID = p.Id.Data
		res = append(res, mqlRequest)
	}

	return res, nil
}

// listAccessRequests paginates either access-request endpoint. Listing requests
// needs the Owner role, so a lower-privileged token degrades to an empty list.
func listAccessRequests(
	list func(*gitlab.ListAccessRequestsOptions) ([]*gitlab.AccessRequest, *gitlab.Response, error),
	scope string, scopeID int64,
) ([]*gitlab.AccessRequest, error) {
	var all []*gitlab.AccessRequest
	page := int64(1)
	for {
		requests, resp, err := list(&gitlab.ListAccessRequestsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			if isTierOrPermissionGated(resp) {
				log.Debug().Str("scope", scope).Int64("id", scopeID).
					Msg("gitlab> access requests unavailable for this token")
				return nil, nil
			}
			return nil, err
		}
		all = append(all, requests...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return all, nil
}

// accessRequestFields maps the shared shape of group and project access
// requests. AccessRequest.ID is the requesting user's id.
func accessRequestFields(request *gitlab.AccessRequest) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":          llx.IntData(request.ID),
		"username":    llx.StringData(request.Username),
		"name":        llx.StringData(request.Name),
		"state":       llx.StringData(request.State),
		"createdAt":   llx.TimeDataPtr(request.CreatedAt),
		"requestedAt": llx.TimeDataPtr(request.RequestedAt),
		"accessLevel": llx.IntData(int64(request.AccessLevel)),
	}
}
