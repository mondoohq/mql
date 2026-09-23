// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// GitLab sends a SCIM identity's external id as extern_uid. client-go before
// v3.2.0 tagged the field external_uid, so gitlab.group.scimIdentity.externalUid
// decoded to an empty string for every identity.
func TestDecodeGroupSCIMIdentityExternUID(t *testing.T) {
	var ids []*gitlab.GroupSCIMIdentity
	require.NoError(t, json.Unmarshal([]byte(`[
		{"extern_uid": "okta|00u1", "user_id": 10, "active": true}
	]`), &ids))
	require.Len(t, ids, 1)
	assert.Equal(t, "okta|00u1", ids[0].ExternalUID)
	assert.Equal(t, int64(10), ids[0].UserID)
	assert.True(t, ids[0].Active)
}
