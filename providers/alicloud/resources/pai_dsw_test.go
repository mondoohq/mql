// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	dswclient "github.com/alibabacloud-go/pai-dsw-20220101/v2/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeDswInstance decodes one ListInstances record the way the SDK does.
func decodeDswInstance(t *testing.T, doc string) *dswclient.ListInstancesResponseBodyInstances {
	t.Helper()
	var inst dswclient.ListInstancesResponseBodyInstances
	require.NoError(t, json.Unmarshal([]byte(doc), &inst))
	return &inst
}

func TestDswRamRoleArns(t *testing.T) {
	t.Run("collects role ARNs and never the user credentials", func(t *testing.T) {
		// Synthetic: shape from the CredentialConfig model; no target showed this.
		inst := decodeDswInstance(t, `{"CredentialConfig": {"Enable": true, "Configs": [
			{"Key": "0", "Type": "Role", "Roles": [
				{"RoleArn": "acs:ram::111:role/notebook", "RoleType": "service",
				 "UserInfo": {"AccessKeyId": "LTAIexample", "SecurityToken": "token-value"}},
				{"RoleArn": " acs:ram::222:role/cross-account "}
			]},
			{"Key": "1", "Type": "Role", "Roles": [
				{"RoleArn": "acs:ram::111:role/notebook"},
				{"RoleArn": ""}
			]}
		]}}`)
		got := dswRamRoleArns(inst.CredentialConfig)
		assert.Equal(t, []string{"acs:ram::111:role/notebook", "acs:ram::222:role/cross-account"}, got)
		for _, arn := range got {
			assert.NotContains(t, arn, "LTAI")
			assert.NotContains(t, arn, "token-value")
		}
	})

	t.Run("no credential config yields an empty list", func(t *testing.T) {
		// Synthetic: no target showed this.
		assert.Equal(t, []string{}, dswRamRoleArns(nil))
		assert.Equal(t, []string{}, dswRamRoleArns(&dswclient.CredentialConfig{}))
	})
}

func TestRamRoleNameInAccount(t *testing.T) {
	// Synthetic: ARN forms from the RAM documentation; no target showed these.
	assert.Equal(t, "notebook", ramRoleNameInAccount("acs:ram::111:role/notebook", "111"))
	assert.Equal(t, "", ramRoleNameInAccount("acs:ram::222:role/notebook", "111"), "role in another account")
	assert.Equal(t, "", ramRoleNameInAccount("acs:ram::111:user/alice", "111"), "not a role")
	assert.Equal(t, "", ramRoleNameInAccount("acs:oss::111:role/notebook", "111"), "not a RAM ARN")
	assert.Equal(t, "", ramRoleNameInAccount("", "111"))
}

func TestEnvVarNames(t *testing.T) {
	// Synthetic: no target showed this.
	v := "sk-secret"
	got := envVarNames(map[string]*string{"OPENAI_API_KEY": &v, "HOME": &v, "EMPTY": nil})
	assert.Equal(t, []string{"EMPTY", "HOME", "OPENAI_API_KEY"}, got)
	assert.NotContains(t, got, v)
	assert.Equal(t, []string{}, envVarNames(nil))
}

func TestDswForwardIsPublic(t *testing.T) {
	decode := func(doc string) *dswclient.ForwardInfoResponse {
		var f dswclient.ForwardInfoResponse
		require.NoError(t, json.Unmarshal([]byte(doc), &f))
		return &f
	}

	// Synthetic: forward shapes from the ForwardInfoResponse model; no target showed these.
	cases := []struct {
		name string
		doc  string
		want bool
	}{
		{"public access type", `{"Enable": true, "AccessType": ["public"], "Name": "ssh", "ForwardPort": "22"}`, true},
		{"EIP bound", `{"Enable": true, "EipAllocationId": "eip-1", "NatGatewayId": "ngw-1"}`, true},
		{"public connect endpoint", `{"Enable": true, "ConnectInfo": {"Internet": {"Endpoint": "47.0.0.1", "Port": "22"}}}`, true},
		{"private only", `{"Enable": true, "AccessType": ["PRIVATE"], "ConnectInfo": {"Intranet": {"Endpoint": "dsw.internal", "Port": "22"}}}`, false},
		{"disabled public forward", `{"Enable": false, "AccessType": ["PUBLIC"], "EipAllocationId": "eip-1"}`, false},
		{"enable absent", `{"AccessType": ["PUBLIC"]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dswForwardIsPublic(decode(tc.doc)))
		})
	}
	assert.False(t, dswForwardIsPublic(nil))
}
