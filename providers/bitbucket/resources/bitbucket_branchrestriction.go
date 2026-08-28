// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitbucket/connection"
)

// mqlBitbucketRepositoryBranchRestrictionInternal caches the identifiers
// needed to resolve this restriction's typed repository() reference and its
// exempted users()/groups() references.
type mqlBitbucketRepositoryBranchRestrictionInternal struct {
	cacheRepoFullName  string
	cacheWorkspaceSlug string
	usersData          []connection.User
	groupsData         []connection.GroupRef
}

// newMqlBitbucketBranchRestriction maps a single API branch restriction to
// its MQL resource. The restriction's numeric id is only unique within a
// single repository, not globally, so the cache key composes it with the
// owning repository's full name.
func newMqlBitbucketBranchRestriction(runtime *plugin.Runtime, repoFullName, workspaceSlug string, br *connection.BranchRestriction) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.repository.branchRestriction", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("%s/branch-restrictions/%d", repoFullName, br.ID)),
		"id":           llx.IntData(br.ID),
		"kind":         llx.StringData(br.Kind),
		"pattern":      llx.StringData(br.Pattern),
		"minApprovals": llx.IntDataPtr(br.Value),
	})
	if err != nil {
		return nil, err
	}

	mqlBr := res.(*mqlBitbucketRepositoryBranchRestriction)
	mqlBr.cacheRepoFullName = repoFullName
	mqlBr.cacheWorkspaceSlug = workspaceSlug
	mqlBr.usersData = br.Users
	mqlBr.groupsData = br.Groups
	return res, nil
}

// repository resolves the repository this restriction applies to.
func (b *mqlBitbucketRepositoryBranchRestriction) repository() (*mqlBitbucketRepository, error) {
	res, err := NewResource(b.MqlRuntime, "bitbucket.repository", map[string]*llx.RawData{
		"fullName": llx.StringData(b.cacheRepoFullName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketRepository), nil
}

// users lists the users exempted from this restriction. Bitbucket does not
// attach a permission level to an exemption, so it is left empty.
func (b *mqlBitbucketRepositoryBranchRestriction) users() ([]any, error) {
	all := make([]any, 0, len(b.usersData))
	for _, u := range b.usersData {
		res, err := newMqlBitbucketMember(b.MqlRuntime, u, "")
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// groups lists the groups exempted from this restriction.
func (b *mqlBitbucketRepositoryBranchRestriction) groups() ([]any, error) {
	all := make([]any, 0, len(b.groupsData))
	for _, g := range b.groupsData {
		res, err := NewResource(b.MqlRuntime, "bitbucket.group", map[string]*llx.RawData{
			"workspace": llx.StringData(b.cacheWorkspaceSlug),
			"slug":      llx.StringData(g.Slug),
		})
		if err != nil {
			// A group referenced by a branch restriction that can no longer
			// be resolved (deleted, or the legacy groups API is unavailable
			// for this workspace) should not fail the whole restriction.
			log.Debug().Err(err).Str("group", g.Slug).Msg("bitbucket> unable to resolve exempted group")
			continue
		}
		all = append(all, res)
	}
	return all, nil
}
