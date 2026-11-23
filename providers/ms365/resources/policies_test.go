// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationPolicyArgs(t *testing.T) {
	// Synthetic: a hardened tenant (guests restricted, users cannot create
	// apps or consent) and a policy Graph returned without default user
	// permissions.
	p := models.NewAuthorizationPolicy()
	id := "authorizationPolicy"
	p.SetId(&id)
	invites := models.ADMINSANDGUESTINVITERS_ALLOWINVITESFROM
	p.SetAllowInvitesFrom(&invites)
	restricted := uuid.MustParse("2af84b1e-32c8-42b7-82bc-daa82404023b")
	p.SetGuestUserRoleId(&restricted)
	no := false
	perms := models.NewDefaultUserRolePermissions()
	perms.SetAllowedToCreateApps(&no)
	perms.SetAllowedToCreateTenants(&no)
	perms.SetPermissionGrantPoliciesAssigned([]string{})
	p.SetDefaultUserRolePermissions(perms)

	args := authorizationPolicyArgs(p)
	assert.Equal(t, "adminsAndGuestInviters", args["allowInvitesFrom"].Value)
	assert.Equal(t, "2af84b1e-32c8-42b7-82bc-daa82404023b", args["guestUserRoleId"].Value)
	assert.Equal(t, false, args["defaultUserAllowedToCreateApps"].Value)
	assert.Equal(t, false, args["defaultUserAllowedToCreateTenants"].Value)
	assert.Nil(t, args["defaultUserAllowedToCreateSecurityGroups"].Value, "a setting Graph left out is null, not false")
	assert.Equal(t, []any{}, args["defaultUserPermissionGrantPoliciesAssigned"].Value, "no assigned grant policy means users cannot consent")
	assert.Nil(t, args["blockMsolPowerShell"].Value)

	bare := authorizationPolicyArgs(models.NewAuthorizationPolicy())
	assert.Nil(t, bare["defaultUserAllowedToCreateApps"].Value, "absent default user permissions read null")
	assert.Nil(t, bare["allowInvitesFrom"].Value)
	assert.Nil(t, bare["guestUserRoleId"].Value)
}
