// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestAccessControlListReadsOneToken(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))
	token := RepositorySecurityToken(fakeado.ProjectScanTestID, fakeado.RepoIacID)

	acl, err := c.AccessControlList(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, acl)
	assert.Equal(t, token, acl.Token)
	assert.True(t, acl.InheritPermissions)
	assert.Equal(t, int64(32904), acl.Aces[fakeado.ContributorsDescriptor].Allow)

	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "/_apis/accesscontrollists/"+GitRepositoriesNamespace+"?")
	assert.Contains(t, reqs[0], "recurse=false")
}

func TestAccessControlListOfATokenWithNoListIsNil(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	acl, err := c.AccessControlList(context.Background(), ProjectSecurityToken(fakeado.ProjectLegacyAppsID))
	require.NoError(t, err)
	assert.Nil(t, acl)
}

func TestAccessControlListIsReadOncePerToken(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))
	token := ProjectSecurityToken(fakeado.ProjectScanTestID)

	for range 3 {
		_, err := c.AccessControlList(context.Background(), token)
		require.NoError(t, err)
	}
	assert.Len(t, srv.Requests(), 1)
}

func TestAccessControlListTheCredentialCannotReadIsForbidden(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))
	srv.Deny("/accesscontrollists/" + GitRepositoriesNamespace)

	_, err := c.AccessControlList(context.Background(), ProjectSecurityToken(fakeado.ProjectScanTestID))
	assert.True(t, IsForbidden(err))
}

func TestSecurityTokensAreLowerCase(t *testing.T) {
	assert.Equal(t, "repoV2/1a000000-0000-4000-8000-00000000000a", ProjectSecurityToken("1A000000-0000-4000-8000-00000000000A"))
	assert.Equal(t, "repoV2/1a/2b", RepositorySecurityToken("1A", "2B"))
}

func TestEffectiveAllow(t *testing.T) {
	const who = "Microsoft.TeamFoundation.Identity;S-1-9-1"
	list := func(inherit bool, allow, deny int64) *AccessControlList {
		return &AccessControlList{InheritPermissions: inherit, Aces: map[string]AccessControlEntry{
			who: {Descriptor: who, Allow: allow, Deny: deny},
		}}
	}
	cases := []struct {
		name  string
		chain []*AccessControlList
		want  int64
	}{
		{"inherited from the project", []*AccessControlList{list(true, 16, 0), nil}, 16},
		{"repository deny beats project allow", []*AccessControlList{list(true, 16|8, 0), list(true, 0, 16)}, 8},
		{"repository allow beats project deny", []*AccessControlList{list(true, 0, 8), list(true, 8, 0)}, 8},
		{"deny beats allow in one list", []*AccessControlList{list(true, 8, 8)}, 0},
		{"project grant adds to repository grant", []*AccessControlList{list(true, 16, 0), list(true, 8, 0)}, 24},
		{"a list that does not inherit ends the walk", []*AccessControlList{list(true, 16, 0), list(false, 8, 0)}, 8},
		{"no lists", []*AccessControlList{nil, nil}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, EffectiveAllow(tc.chain)[strings.ToLower(who)])
		})
	}
}

func TestEffectiveAllowKeepsOneIdentitysDenyFromAnother(t *testing.T) {
	const a = "Microsoft.TeamFoundation.Identity;S-1-9-1"
	const b = "Microsoft.TeamFoundation.Identity;S-1-9-2"
	chain := []*AccessControlList{{InheritPermissions: true, Aces: map[string]AccessControlEntry{
		a: {Descriptor: a, Allow: 0, Deny: 8},
		b: {Descriptor: b, Allow: 8, Deny: 0},
	}}}

	got := EffectiveAllow(chain)
	assert.Equal(t, int64(0), got[strings.ToLower(a)], "the denied identity is not allowed")
	assert.Equal(t, int64(8), got[strings.ToLower(b)], "another identity's deny does not reach it")
}

func TestEffectiveAllowFoldsDescriptorsOfDifferentCaseToOneKey(t *testing.T) {
	const project = "Microsoft.TeamFoundation.Identity;S-1-9-1-ABC"
	const repo = "microsoft.teamfoundation.identity;s-1-9-1-abc"
	chain := []*AccessControlList{
		{InheritPermissions: true, Aces: map[string]AccessControlEntry{project: {Descriptor: project, Allow: 16 | 8}}},
		{InheritPermissions: true, Aces: map[string]AccessControlEntry{repo: {Descriptor: repo, Deny: 16}}},
	}

	got := EffectiveAllow(chain)
	assert.Len(t, got, 1, "one identity, one key")
	assert.Equal(t, int64(8), got[strings.ToLower(project)], "the repository deny beats the project allow")
}

func TestIsServiceIdentity(t *testing.T) {
	assert.True(t, IsServiceIdentity(fakeado.BuildServiceDescriptor))
	assert.True(t, IsServiceIdentity(strings.ToLower(fakeado.BuildServiceDescriptor)))
	assert.False(t, IsServiceIdentity(fakeado.ContributorsDescriptor))
}

func TestProjectGroupFindsTheGroupByName(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	for range 2 {
		group, err := c.ProjectGroup(context.Background(), "scan-test", "Contributors")
		require.NoError(t, err)
		require.NotNil(t, group)
		assert.Equal(t, fakeado.ContributorsDescriptor, group.Descriptor)
	}

	reqs := srv.Requests()
	require.Len(t, reqs, 1, "read once per client")
	assert.Contains(t, reqs[0], "/vssps/"+fakeado.Org+"/_apis/identities?")
	assert.Contains(t, reqs[0], "searchFilter=General")
}

func TestProjectGroupTheSearchDoesNotFindIsNil(t *testing.T) {
	c, _, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	group, err := c.ProjectGroup(context.Background(), "legacy-apps", "Contributors")
	require.NoError(t, err)
	assert.Nil(t, group)
}
