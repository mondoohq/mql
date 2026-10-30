// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func decodeExternalKey(t *testing.T, payload string) openai.ExternalKey {
	t.Helper()
	var k openai.ExternalKey
	require.NoError(t, json.Unmarshal([]byte(payload), &k))
	return k
}

func TestExternalKeyArgsAWS(t *testing.T) {
	// Synthetic: AWS key configuration shaped after the SDK's ExternalKey
	// struct tags; no organization with a registered key was available.
	k := decodeExternalKey(t, `{
		"id": "ekey_aws0",
		"object": "organization.external_key",
		"name": "prod-kms",
		"type": "aws",
		"purpose": "ekm",
		"workspace_id": "ws_0",
		"api_project_ids": ["proj_a", "proj_b"],
		"created_at": 1761868800,
		"kms_arn": "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000",
		"role_arn": "arn:aws:iam::000000000000:role/openai-ekm",
		"external_id": "confused-deputy-token"
	}`)

	args := externalKeyArgs(k)
	assert.Equal(t, "ekey_aws0", args["__id"].Value)
	assert.Equal(t, "ekey_aws0", args["id"].Value)
	assert.Equal(t, "prod-kms", args["name"].Value)
	assert.Equal(t, "aws", args["provider"].Value)
	assert.Equal(t, "ekm", args["purpose"].Value)
	assert.Equal(t, "ws_0", args["workspaceId"].Value)
	assert.Equal(t, "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000", args["kmsArn"].Value)
	assert.Equal(t, "arn:aws:iam::000000000000:role/openai-ekm", args["roleArn"].Value)
	require.NotNil(t, args["createdAt"].Value)
	assert.Equal(t, int64(1761868800), args["createdAt"].Value.(*time.Time).Unix())

	// the other services' location fields stay null, not ""
	for _, f := range []string{"kmsProjectId", "kmsKeyName", "kmsKeyVersion", "audience", "vaultUri", "keyName", "keyVersion", "tenantId"} {
		assert.Nil(t, args[f].Value, f)
	}
	// the AWS external id is never passed through
	_, ok := args["externalId"]
	assert.False(t, ok)
}

func TestExternalKeyArgsGCP(t *testing.T) {
	// Synthetic: GCP key configuration without a pinned key version.
	k := decodeExternalKey(t, `{
		"id": "ekey_gcp0",
		"object": "organization.external_key",
		"name": "gcp-kms",
		"type": "gcp",
		"workspace_id": "ws_0",
		"api_project_ids": [],
		"created_at": 1761868800,
		"audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/openai/providers/openai",
		"kms_project_id": "kms-project",
		"kms_key_location": "us-east1",
		"kms_key_ring_name": "ring",
		"kms_key_name": "key",
		"workload_identity_pool_id": "openai",
		"workload_identity_project_number": "123",
		"workload_identity_provider_id": "openai-provider"
	}`)

	args := externalKeyArgs(k)
	assert.Equal(t, "gcp", args["provider"].Value)
	assert.Equal(t, "kms-project", args["kmsProjectId"].Value)
	assert.Equal(t, "us-east1", args["kmsKeyLocation"].Value)
	assert.Equal(t, "ring", args["kmsKeyRingName"].Value)
	assert.Equal(t, "key", args["kmsKeyName"].Value)
	assert.Equal(t, "123", args["workloadIdentityProjectNumber"].Value)
	assert.Equal(t, "openai", args["workloadIdentityPoolId"].Value)
	assert.Equal(t, "openai-provider", args["workloadIdentityProviderId"].Value)
	assert.Equal(t, "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/openai/providers/openai", args["audience"].Value)
	// an unpinned version and an absent purpose read as null
	assert.Nil(t, args["kmsKeyVersion"].Value)
	assert.Nil(t, args["purpose"].Value)
	assert.Nil(t, args["kmsArn"].Value)
}

func TestExternalKeyArgsAzure(t *testing.T) {
	// Synthetic: Azure Key Vault configuration with a pinned key version.
	k := decodeExternalKey(t, `{
		"id": "ekey_az0",
		"object": "organization.external_key",
		"name": "vault",
		"type": "azure",
		"purpose": "psp_decryption",
		"workspace_id": "ws_0",
		"api_project_ids": ["proj_a"],
		"created_at": 0,
		"vault_uri": "https://example.vault.azure.net",
		"key_name": "openai",
		"key_version": "0123456789abcdef",
		"tenant_id": "00000000-0000-0000-0000-000000000001"
	}`)

	args := externalKeyArgs(k)
	assert.Equal(t, "azure", args["provider"].Value)
	assert.Equal(t, "psp_decryption", args["purpose"].Value)
	assert.Equal(t, "https://example.vault.azure.net", args["vaultUri"].Value)
	assert.Equal(t, "openai", args["keyName"].Value)
	assert.Equal(t, "0123456789abcdef", args["keyVersion"].Value)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", args["tenantId"].Value)
	// a zero timestamp is null, not the Unix epoch
	assert.Nil(t, args["createdAt"].Value)
}

func testProject(id string) *mqlOpenaiProject {
	return &mqlOpenaiProject{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
}

func testExternalKey(id string, projects ...string) *mqlOpenaiExternalKey {
	k := &mqlOpenaiExternalKey{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
	k.cacheProjectIds = projects
	return k
}

func TestProjectsWithIds(t *testing.T) {
	// Synthetic: binding resolution against an organization project list.
	a, b, c := testProject("proj_a"), testProject("proj_b"), testProject("proj_c")
	all := []any{a, b, c}

	assert.Equal(t, []any{a, c}, projectsWithIds(all, []string{"proj_a", "proj_c"}))
	// a bound project that no longer exists is left out
	assert.Equal(t, []any{b}, projectsWithIds(all, []string{"proj_b", "proj_deleted"}))
	assert.Empty(t, projectsWithIds(all, nil))
}

func TestExternalKeysBoundTo(t *testing.T) {
	// Synthetic: one project bound to two keys, one key bound to none.
	ekm := testExternalKey("ekey_1", "proj_a", "proj_b")
	psp := testExternalKey("ekey_2", "proj_a")
	unbound := testExternalKey("ekey_3")
	keys := []any{ekm, psp, unbound}

	assert.Equal(t, []any{ekm, psp}, externalKeysBoundTo(keys, "proj_a"))
	assert.Equal(t, []any{ekm}, externalKeysBoundTo(keys, "proj_b"))
	assert.Empty(t, externalKeysBoundTo(keys, "proj_c"))
	assert.Empty(t, externalKeysBoundTo(keys, ""))
}
