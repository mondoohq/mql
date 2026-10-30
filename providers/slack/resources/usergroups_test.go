// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserGroupArgsFlags(t *testing.T) {
	flags := []string{"isIdpGroup", "autoProvision", "isMembershipLocked", "isEditingRestricted", "isOrgLevel"}

	cases := []struct {
		name string
		body string
		want map[string]bool
	}{
		{
			name: "IdP group, locked membership, org level",
			body: `{"id":"S1","team_id":"T1","is_external":false,"user_count":3,
				"is_idp_group":true,"auto_provision":false,"is_membership_locked":true,
				"is_editing_restricted":false,"is_org_level":true}`,
			want: map[string]bool{
				"isIdpGroup": true, "autoProvision": false, "isMembershipLocked": true,
				"isEditingRestricted": false, "isOrgLevel": true,
			},
		},
		{
			name: "auto-provisioned, editing restricted",
			body: `{"id":"S2","team_id":"T1","is_external":false,"user_count":0,
				"is_idp_group":false,"auto_provision":true,"is_membership_locked":false,
				"is_editing_restricted":true,"is_org_level":false}`,
			want: map[string]bool{
				"isIdpGroup": false, "autoProvision": true, "isMembershipLocked": false,
				"isEditingRestricted": true, "isOrgLevel": false,
			},
		},
		{
			name: "flags not returned",
			body: `{"id":"S3","team_id":"T1","is_external":true,"user_count":1}`,
			want: map[string]bool{
				"isIdpGroup": false, "autoProvision": false, "isMembershipLocked": false,
				"isEditingRestricted": false, "isOrgLevel": false,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var g slack.UserGroup
			require.NoError(t, json.Unmarshal([]byte(tc.body), &g))

			args := userGroupArgs(g)
			for _, f := range flags {
				require.Contains(t, args, f)
				assert.Equal(t, tc.want[f], args[f].Value, f)
			}
		})
	}
}

func TestUserGroupArgsListingFields(t *testing.T) {
	var g slack.UserGroup
	require.NoError(t, json.Unmarshal([]byte(`{"id":"S1","team_id":"T1","name":"Admins",
		"description":"All admins","handle":"admins","is_external":true,
		"date_create":1446598059,"date_update":1446670362,"date_delete":0,"user_count":4}`), &g))

	args := userGroupArgs(g)
	assert.Equal(t, "S1", args["id"].Value)
	assert.Equal(t, "T1", args["teamId"].Value)
	assert.Equal(t, "Admins", args["name"].Value)
	assert.Equal(t, "All admins", args["description"].Value)
	assert.Equal(t, "admins", args["handle"].Value)
	assert.Equal(t, true, args["isExternal"].Value)
	assert.Equal(t, int64(4), args["userCount"].Value)
}
