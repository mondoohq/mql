// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantsApplyingTo(t *testing.T) {
	// Synthetic: a user with a direct grant, a grant through a role-assignable
	// group, and grants to another user and to a group the user is not in.
	grants := []directoryRoleGrant{
		{principalID: "USER-1", principalType: "user"},
		{principalID: "group-admins", principalType: "group"},
		{principalID: "user-2", principalType: "user"},
		{principalID: "group-other", principalType: "group"},
		{principalID: "", principalType: "user"},
	}
	asked := []string{}
	isMember := func(groupID string) (bool, error) {
		asked = append(asked, groupID)
		return groupID == "group-admins", nil
	}
	self := func(g directoryRoleGrant) directoryRoleGrant { return g }

	got, err := grantsApplyingTo(grants, self, "user-1", true, isMember)
	require.NoError(t, err)
	assert.Equal(t, []any{grants[0], grants[1]}, got, "direct grant (any case) and the grant through the group")
	assert.Equal(t, []string{"group-admins", "group-other"}, asked, "membership is only asked of groups holding a grant")

	asked = nil
	direct, err := grantsApplyingTo(grants, self, "group-admins", false, isMember)
	require.NoError(t, err)
	assert.Equal(t, []any{grants[1]}, direct)
	assert.Empty(t, asked, "a group's own grants never ask about membership")

	none, err := grantsApplyingTo(grants, self, "", true, isMember)
	require.NoError(t, err)
	assert.Empty(t, none, "an empty principal holds nothing")

	_, err = grantsApplyingTo(grants, self, "user-3", true, func(string) (bool, error) {
		return false, errors.New("membership refused")
	})
	assert.Error(t, err, "a membership lookup that fails is an error, not a missing grant")
}

func TestPrivilegedByID(t *testing.T) {
	// Synthetic: definitions shaped like the beta roleDefinitions response.
	priv := betamodels.NewUnifiedRoleDefinition()
	id1, yes := "62E90394-69F5-4237-9190-012177145E10", true
	priv.SetId(&id1)
	priv.SetIsPrivileged(&yes)
	plain := betamodels.NewUnifiedRoleDefinition()
	id2, no := "88d8e3e3-8f55-4a1e-953a-9b9898b8876b", false
	plain.SetId(&id2)
	plain.SetIsPrivileged(&no)
	unset := betamodels.NewUnifiedRoleDefinition()
	id3 := "custom-role"
	unset.SetId(&id3)

	got := privilegedByID([]betamodels.UnifiedRoleDefinitionable{priv, nil, plain, unset, betamodels.NewUnifiedRoleDefinition()})
	require.Len(t, got, 3)
	assert.True(t, *got["62e90394-69f5-4237-9190-012177145e10"], "keys are lower-cased")
	assert.False(t, *got["88d8e3e3-8f55-4a1e-953a-9b9898b8876b"])
	assert.Nil(t, got["custom-role"], "an unclassified role is null, not false")
}
