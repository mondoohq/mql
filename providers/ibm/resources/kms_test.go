// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstancePolicyArgs(t *testing.T) {
	var p instancePolicies
	require.NoError(t, json.Unmarshal([]byte(`{"resources": [
		{"policy_type": "metrics", "policy_data": {"enabled": true}},
		{"policy_type": "keyCreateImportAccess", "policy_data": {"enabled": true, "attributes": {
			"create_root_key": true, "create_standard_key": true, "import_root_key": false, "import_standard_key": true, "enforce_token": false}}},
		{"policy_type": "rotation", "policy_data": {"enabled": true, "attributes": {"interval_month": 6}}},
		{"policy_type": "dualAuthDelete", "policy_data": {"enabled": true}},
		{"policy_type": "allowedNetwork", "policy_data": {"enabled": true, "attributes": {"allowed_network": "private-only"}}},
		{"policy_type": "allowedIP", "policy_data": {"enabled": true, "attributes": {"allowed_ip": ["10.0.0.0/8"]}}}
	]}`), &p))
	args := instancePolicyArgs(p)
	assert.Equal(t, true, args["metricsEnabled"].Value)
	assert.Equal(t, true, args["rotationEnabled"].Value)
	assert.Equal(t, int64(6), args["rotationIntervalMonth"].Value)
	assert.Equal(t, true, args["dualAuthDeleteEnabled"].Value)
	assert.Equal(t, "private-only", args["allowedNetwork"].Value)
	assert.Equal(t, true, args["allowedIpEnabled"].Value)
	assert.Equal(t, []any{"10.0.0.0/8"}, args["allowedIps"].Value)
	assert.Equal(t, true, args["keyCreateImportAccessEnabled"].Value)
	assert.Equal(t, false, args["importRootKey"].Value)
	assert.Equal(t, true, args["importStandardKey"].Value)
}

func TestInstancePolicyArgsAbsentPolicies(t *testing.T) {
	args := instancePolicyArgs(instancePolicies{})
	// A policy that was never set is off.
	assert.Equal(t, false, args["dualAuthDeleteEnabled"].Value)
	assert.Equal(t, false, args["rotationEnabled"].Value)
	assert.Equal(t, false, args["allowedIpEnabled"].Value)
	// Its attributes say nothing.
	assert.Nil(t, args["rotationIntervalMonth"].Value)
	assert.Nil(t, args["allowedNetwork"].Value)
	assert.Nil(t, args["createRootKey"].Value)
}

func TestRotationOf(t *testing.T) {
	var p keyPolicies
	require.NoError(t, json.Unmarshal([]byte(`{"resources": [{"rotation": {"enabled": true, "interval_month": 3}, "id": "p1"}]}`), &p))
	rot := rotationOf(p)
	require.NotNil(t, rot)
	assert.True(t, rot.enabled)
	assert.Equal(t, int64(3), *rot.intervalMonth)

	assert.Nil(t, rotationOf(keyPolicies{}), "a key without a rotation policy has none")

	var dual keyPolicies
	require.NoError(t, json.Unmarshal([]byte(`{"resources": [{"dualAuthDelete": {"enabled": true}}]}`), &dual))
	assert.Nil(t, rotationOf(dual), "a dual authorization policy is not a rotation policy")
}

func TestKeyArgs(t *testing.T) {
	var k ibmkeyprotectapiv2.KeyFullRepresentation
	require.NoError(t, json.Unmarshal([]byte(`{"id": "k1", "crn": "crn:k1", "name": "root", "state": 1, "extractable": false,
		"imported": false, "creationDate": "2026-10-07T09:19:08Z", "dualAuthDelete": {"enabled": true}}`), &k))
	args := keyArgs(k)
	assert.Equal(t, "active", args["state"].Value)
	assert.Equal(t, false, args["standardKey"].Value)
	assert.Equal(t, true, args["dualAuthDeleteEnabled"].Value)
	assert.Nil(t, args["expiresAt"].Value, "a key without expiration does not expire")
	assert.Nil(t, args["lastRotatedAt"].Value)

	assert.Equal(t, false, keyArgs(ibmkeyprotectapiv2.KeyFullRepresentation{})["dualAuthDeleteEnabled"].Value)
}

func TestKeyStateName(t *testing.T) {
	five := int64(5)
	assert.Equal(t, "destroyed", keyStateName(&five))
	assert.Equal(t, "", keyStateName(nil))
}

func TestKmsEndpoint(t *testing.T) {
	hpcs := resourcecontrollerv2.ResourceInstance{Extensions: map[string]any{
		"endpoints": map[string]any{"public": "https://api.us-south.hs-crypto.cloud.ibm.com:8888"},
	}}
	u, err := kmsEndpoint(hpcs)
	require.NoError(t, err)
	assert.Equal(t, "https://api.us-south.hs-crypto.cloud.ibm.com:8888", u, "the instance's own endpoint wins")

	region := "eu-de"
	u, err = kmsEndpoint(resourcecontrollerv2.ResourceInstance{RegionID: &region})
	require.NoError(t, err)
	assert.Equal(t, "https://eu-de.kms.cloud.ibm.com", u)

	_, err = kmsEndpoint(resourcecontrollerv2.ResourceInstance{})
	assert.Error(t, err)
}
