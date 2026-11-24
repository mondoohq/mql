// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	hfmodels "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

// Synthetic: a member shaped after GET /api/organizations/{name}/members in the
// Hub OpenAPI document; no live account was checked.
//
// One account belongs to many organizations with a different role in each, so
// its id must carry the organization. Fields a non-administrator cannot see
// stay null rather than reading as false.
func TestOrgMemberArgs(t *testing.T) {
	no := false
	m := hfmodels.OrgMember{ID: "u1", User: "alice", Fullname: "Alice", Role: "admin", TwoFaEnabled: &no}

	a := orgMemberArgs("org1", m)
	b := orgMemberArgs("org2", m)
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
	assert.Equal(t, "alice", a["name"].Value)
	assert.Equal(t, "admin", a["role"].Value)
	assert.Equal(t, false, a["twoFaEnabled"].Value)
	assert.Nil(t, a["isExternalCollaborator"].Value)
	assert.Nil(t, a["verifiedEmail"].Value)

	unknown := orgMemberArgs("org1", hfmodels.OrgMember{ID: "u2", User: "bob"})
	assert.Nil(t, unknown["twoFaEnabled"].Value, "an unreported 2FA state must not read as disabled")
	assert.Nil(t, unknown["role"].Value)
}

// Synthetic: tokens shaped after GET /api/organizations/{name}/settings/tokens
// in the Hub OpenAPI document; no live account was checked.
func TestOrgMemberTokenArgs(t *testing.T) {
	name := "ci"
	tok := hfmodels.OrgMemberToken{
		ID: "t1", DisplayName: &name, Role: "fineGrained",
		CreatedAt:     "2026-01-01T00:00:00.000Z",
		LastUsedAt:    "2026-02-01T00:00:00.000Z",
		Owner:         hfmodels.OrgTokenOwner{ID: "u1", Name: "alice"},
		Authorization: &hfmodels.OrgTokenAuthorization{Status: "pending"},
	}
	args := orgMemberTokenArgs("org1", tok)
	assert.Equal(t, "t1", args["id"].Value)
	assert.Equal(t, "ci", args["displayName"].Value)
	assert.Equal(t, "fineGrained", args["role"].Value)
	assert.Equal(t, new(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)), args["lastUsedAt"].Value)
	assert.Equal(t, "pending", args["authorizationStatus"].Value)
	assert.NotEqual(t, args["__id"].Value, orgMemberTokenArgs("org2", tok)["__id"].Value)

	// A never-used token outside an approval flow: no name, no last use, no
	// status. Each stays null.
	bare := orgMemberTokenArgs("org1", hfmodels.OrgMemberToken{ID: "t2", Role: "write"})
	assert.Nil(t, bare["displayName"].Value)
	assert.Nil(t, bare["lastUsedAt"].Value)
	assert.Nil(t, bare["authorizationStatus"].Value)
}

// Synthetic: a read or write token carries no permission list; no live
// account was checked. The scopes field stays null without touching the
// runtime.
func TestCreateTokenScopesAbsent(t *testing.T) {
	data, err := createTokenScopes(nil, "huggingface.organization.memberToken/org1/t1", nil)
	assert.NoError(t, err)
	assert.Nil(t, data.Value)
}
