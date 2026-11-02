// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	ramclient "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: a GetRole body shaped after the example values in the RAM API
// reference; no account was scanned.
func TestRamRoleDetailFields(t *testing.T) {
	body := `{
		"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368",
		"Role": {
			"RoleName": "AliyunServiceRoleForECS",
			"IsServiceLinkedRole": true,
			"AllowConsoleLogin": false,
			"RolePrincipalName": "AliyunServiceRoleForECS@role.123456.onaliyunservice.com"
		}
	}`
	var resp ramclient.GetRoleResponseBody
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.NotNil(t, resp.Role)

	linked := ramRoleIsServiceLinked(resp.Role)
	require.NotNil(t, linked)
	assert.True(t, *linked)

	name := ramRolePrincipalName(resp.Role)
	require.NotNil(t, name)
	assert.Equal(t, "AliyunServiceRoleForECS@role.123456.onaliyunservice.com", *name)

	// A role the account created carries an explicit false, which must read as
	// false rather than as absent.
	require.NotNil(t, resp.Role.AllowConsoleLogin)
	assert.False(t, *resp.Role.AllowConsoleLogin)
}

// Synthetic: GetRole responses that leave the detail-only fields out; no account
// was scanned.
func TestRamRoleDetailFieldsAbsent(t *testing.T) {
	assert.Nil(t, ramRoleIsServiceLinked(nil))
	assert.Nil(t, ramRolePrincipalName(nil))

	var resp ramclient.GetRoleResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{"Role": {"RoleName": "deploy", "RolePrincipalName": ""}}`), &resp))
	assert.Nil(t, ramRoleIsServiceLinked(resp.Role))
	assert.Nil(t, ramRolePrincipalName(resp.Role), "an empty principal name is absent, not a name")
	assert.Nil(t, resp.Role.AllowConsoleLogin)
}
