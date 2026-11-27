// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
)

// Synthetic: invite shapes from the Admin API reference; no live organization
// was checked.
func TestInviteProjectGrants(t *testing.T) {
	inv := decodeJSON[openai.Invite](t, `{
		"id": "invite-abc", "email": "new@example.com", "role": "reader",
		"status": "pending",
		"projects": [
			{"id": "proj_b", "role": "owner"},
			{"id": "proj_a", "role": "member"}
		]
	}`)
	g := inviteProjectGrants(inv.Projects)
	assert.Equal(t, []string{"proj_b", "proj_a"}, g.ids)
	assert.Equal(t, map[string]any{"proj_b": "owner", "proj_a": "member"}, g.roles)

	// an invite to the organization only grants no project and reads as an
	// empty set, not a null one
	none := inviteProjectGrants(decodeJSON[openai.Invite](t, `{"id": "invite-def", "projects": []}`).Projects)
	assert.Empty(t, none.ids)
	assert.Equal(t, map[string]any{}, none.roles)

	// an entry without a project id names nothing to resolve
	blank := inviteProjectGrants([]openai.InviteProject{{ID: "", Role: "member"}, {ID: "proj_c", Role: "member"}})
	assert.Equal(t, []string{"proj_c"}, blank.ids)
	assert.Equal(t, map[string]any{"proj_c": "member"}, blank.roles)
}
