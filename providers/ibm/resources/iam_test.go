// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyArgs(t *testing.T) {
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "p-1", "type": "access", "state": "active",
		"subjects": [{"attributes": [{"name": "access_group_id", "value": "AccessGroupId-1"}]}],
		"roles": [{"role_id": "crn:v1:bluemix:public:iam::::role:Administrator", "display_name": "Administrator"}],
		"resources": [{"attributes": [{"name": "accountId", "value": "acc"}, {"name": "serviceName", "value": "is", "operator": "stringEquals"}]}]
	}`), &raw))
	var p *iampolicymanagementv1.PolicyTemplateMetaData
	require.NoError(t, iampolicymanagementv1.UnmarshalPolicyTemplateMetaData(raw, &p))

	args := policyArgs(*p)
	assert.Equal(t, []any{"Administrator"}, args["roles"].Value)
	assert.Equal(t, []any{"crn:v1:bluemix:public:iam::::role:Administrator"}, args["roleIds"].Value)
	assert.Equal(t, map[string]any{"access_group_id": "AccessGroupId-1"}, args["subjectAttributes"].Value)
	assert.Equal(t, map[string]any{"accountId": "acc", "serviceName": "is"}, args["resourceAttributes"].Value)
}

func TestAPIKeyArgs(t *testing.T) {
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "ApiKey-1", "name": "ci", "iam_id": "iam-ServiceId-1", "locked": false, "disabled": true,
		"created_at": "2026-10-07T08:44:00Z", "expires_at": "2027-01-01T00:00:00Z",
		"action_when_leaked": "disable", "apikey": "",
		"activity": {"last_authn": "2026-10-07T09:00:00Z", "authn_count": 4}
	}`), &raw))
	var k *iamidentityv1.APIKey
	require.NoError(t, iamidentityv1.UnmarshalAPIKey(raw, &k))

	args := apiKeyArgs(*k)
	assert.Equal(t, true, args["disabled"].Value)
	assert.NotNil(t, args["expiresAt"].Value)
	assert.NotNil(t, args["lastAuthentication"].Value)
	assert.Equal(t, int64(4), args["authenticationCount"].Value)
	_, hasSecret := args["apikey"]
	assert.False(t, hasSecret, "the key value must never be mapped")
}

func TestAPIKeyArgsWithoutActivity(t *testing.T) {
	args := apiKeyArgs(iamidentityv1.APIKey{})
	// Without activity tracking there is no last authentication: null, not
	// the zero time.
	assert.Nil(t, args["lastAuthentication"].Value)
	assert.Nil(t, args["authenticationCount"].Value)
	assert.Nil(t, args["expiresAt"].Value)
}
