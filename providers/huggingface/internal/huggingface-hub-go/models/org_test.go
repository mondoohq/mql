// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: members shaped after GET /api/organizations/{name}/members in the
// Hub OpenAPI document; no live account was checked.
func TestOrgMemberDecode(t *testing.T) {
	data := []byte(`[
		{"_id":"0123456789abcdef01234567","user":"alice","fullname":"Alice","avatarUrl":"a","isPro":false,"type":"user",
		 "role":"admin","twoFaEnabled":false,"isExternalCollaborator":true,"verifiedEmail":"alice@example.com",
		 "resourceGroups":[{"id":"rg1","name":"research","numUsers":3,"role":"write","assignedRole":"inherit"}]},
		{"_id":"0123456789abcdef01234568","user":"bob","fullname":"Bob","avatarUrl":"b","isPro":true,"type":"user"}
	]`)

	var members []OrgMember
	require.NoError(t, json.Unmarshal(data, &members))
	require.Len(t, members, 2)

	a := members[0]
	assert.Equal(t, "0123456789abcdef01234567", a.ID)
	assert.Equal(t, "alice", a.User)
	assert.Equal(t, "admin", a.Role)
	require.NotNil(t, a.TwoFaEnabled)
	assert.False(t, *a.TwoFaEnabled)
	require.NotNil(t, a.IsExternalCollaborator)
	assert.True(t, *a.IsExternalCollaborator)
	require.NotNil(t, a.VerifiedEmail)
	assert.Equal(t, "alice@example.com", *a.VerifiedEmail)
	require.Len(t, a.ResourceGroups, 1)
	assert.Equal(t, OrgMemberResourceGroup{ID: "rg1", Name: "research", Role: "write", AssignedRole: "inherit"}, a.ResourceGroups[0])

	// Fields a non-administrator does not see stay nil, not false.
	b := members[1]
	assert.Nil(t, b.TwoFaEnabled)
	assert.Nil(t, b.IsExternalCollaborator)
	assert.Nil(t, b.VerifiedEmail)
	assert.Empty(t, b.Role)
}

// Synthetic: settings shaped after GET .../settings/network-security in the
// Hub OpenAPI document; no live account was checked.
func TestOrgNetworkSecurityDecode(t *testing.T) {
	data := []byte(`{"enforceAuth":true,"areCidrRangesApproved":false,"enforceIpRestriction":true,
		"highRateLimits":false,"ipRanges":["10.0.0.0/8"],
		"blockedContents":[{"resource":"*","scope":"evil-org"}],
		"allowedContents":[{"resource":"model","scope":"acme"}],"keepReposMetadataVisible":false}`)

	var ns OrgNetworkSecurity
	require.NoError(t, json.Unmarshal(data, &ns))
	require.NotNil(t, ns.EnforceAuth)
	assert.True(t, *ns.EnforceAuth)
	require.NotNil(t, ns.EnforceIPRestriction)
	assert.True(t, *ns.EnforceIPRestriction)
	require.NotNil(t, ns.AreCidrRangesApproved)
	assert.False(t, *ns.AreCidrRangesApproved)
	assert.Equal(t, []string{"10.0.0.0/8"}, ns.IPRanges)
	assert.Equal(t, []ContentRef{{Resource: "*", Scope: "evil-org"}}, ns.BlockedContents)
	assert.Equal(t, []ContentRef{{Resource: "model", Scope: "acme"}}, ns.AllowedContents)
}

// Synthetic: tokens shaped after GET .../settings/tokens in the Hub OpenAPI
// document; no live account was checked.
func TestOrgMemberTokenDecode(t *testing.T) {
	data := []byte(`[
		{"_id":"aaaaaaaaaaaaaaaaaaaaaaaa","displayName":"ci","role":"fineGrained","last4":"wxyz",
		 "createdAt":"2026-01-01T00:00:00.000Z","lastUsedAt":"2026-02-01T00:00:00.000Z",
		 "owner":{"_id":"0123456789abcdef01234567","name":"alice","fullname":"Alice","avatarUrl":"a"},
		 "authorization":{"status":"approved","requestedAt":"2026-01-01T00:00:00.000Z"},
		 "fineGrained":{"scoped":[{"entity":{"_id":"bbbbbbbbbbbbbbbbbbbbbbbb","type":"org"},"permissions":["repo.content.read"]}]}},
		{"_id":"cccccccccccccccccccccccc","role":"write","createdAt":"2026-01-01T00:00:00.000Z",
		 "owner":{"_id":"0123456789abcdef01234568","name":"bob","fullname":"Bob","avatarUrl":"b"}}
	]`)

	var tokens []OrgMemberToken
	require.NoError(t, json.Unmarshal(data, &tokens))
	require.Len(t, tokens, 2)

	a := tokens[0]
	require.NotNil(t, a.DisplayName)
	assert.Equal(t, "ci", *a.DisplayName)
	assert.Equal(t, "fineGrained", a.Role)
	assert.Equal(t, "2026-02-01T00:00:00.000Z", a.LastUsedAt)
	assert.Equal(t, "0123456789abcdef01234567", a.Owner.ID)
	require.NotNil(t, a.Authorization)
	assert.Equal(t, "approved", a.Authorization.Status)
	require.NotNil(t, a.FineGrained)
	require.Len(t, a.FineGrained.Scoped, 1)
	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbb", a.FineGrained.Scoped[0].Entity.ID)
	assert.Equal(t, []string{"repo.content.read"}, a.FineGrained.Scoped[0].Permissions)

	// The token suffix must not survive decoding.
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "wxyz")

	b := tokens[1]
	assert.Nil(t, b.DisplayName)
	assert.Nil(t, b.Authorization)
	assert.Nil(t, b.FineGrained, "a write token carries no permission list")
	assert.Empty(t, b.LastUsedAt)
}
