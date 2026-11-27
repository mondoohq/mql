// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: member entries shaped per the API schema; no live Codesphere
// account was available.
func TestOrgMemberArgs(t *testing.T) {
	var deleted cs.OrganizationsListOrgMembers200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"userId":7,"organizationId":"org-1","role":"admin","pending":false,"createdAt":"2026-01-02T03:04:05Z","name":"Ada","email":"ada@example.com","deletedAt":"2026-06-01T00:00:00Z"}`), &deleted))
	args := orgMemberArgs(deleted)
	assert.Equal(t, "org-1/7", args["__id"].Value)
	assert.Equal(t, "admin", args["role"].Value)
	assert.Equal(t, "ada@example.com", args["email"].Value)
	assert.Equal(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), *args["deletedAt"].Value.(*time.Time))

	var invited cs.OrganizationsListOrgMembers200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"userId":8,"organizationId":"org-1","role":"member","pending":true,"createdAt":"2026-01-02T03:04:05Z"}`), &invited))
	args = orgMemberArgs(invited)
	assert.Equal(t, true, args["pending"].Value)
	assert.Nil(t, args["name"].Value)
	assert.Nil(t, args["deletedAt"].Value)
}
