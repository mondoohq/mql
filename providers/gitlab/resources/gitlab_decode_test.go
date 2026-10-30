// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

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

// gitlab.project.deployKey.lastUsedAt and usageType read last_used_at and
// usage_type, which client-go only decodes from v3.6.0 on. A key that has
// never been used carries last_used_at: null and must stay nil, not a zero
// time, so lastUsedAt reads null rather than year 1.
func TestDecodeProjectDeployKeyLastUsedAndUsageType(t *testing.T) {
	var keys []*gitlab.ProjectDeployKey
	require.NoError(t, json.Unmarshal([]byte(`[
		{
			"id": 1,
			"title": "ci-push",
			"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample",
			"created_at": "2026-01-02T03:04:05.000Z",
			"expires_at": null,
			"can_push": true,
			"last_used_at": "2026-09-01T10:00:00.000Z",
			"usage_type": "auth"
		},
		{
			"id": 2,
			"title": "never-used",
			"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther",
			"created_at": "2026-01-02T03:04:05.000Z",
			"can_push": false,
			"last_used_at": null,
			"usage_type": "auth_and_signing"
		}
	]`), &keys))
	require.Len(t, keys, 2)

	require.NotNil(t, keys[0].LastUsedAt)
	assert.Equal(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), keys[0].LastUsedAt.UTC())
	assert.Equal(t, "auth", keys[0].UsageType)

	assert.Nil(t, keys[1].LastUsedAt)
	assert.Equal(t, "auth_and_signing", keys[1].UsageType)
}

// gitlab.project.clusterAgent.isReceptive reads is_receptive, which client-go
// only decodes from v3.3.0 on.
func TestDecodeClusterAgentIsReceptive(t *testing.T) {
	var agents []*gitlab.Agent
	require.NoError(t, json.Unmarshal([]byte(`[
		{"id": 1, "name": "inbound", "created_at": "2026-01-02T03:04:05.000Z", "created_by_user_id": 7, "is_receptive": true},
		{"id": 2, "name": "outbound", "created_at": "2026-01-02T03:04:05.000Z", "created_by_user_id": 7, "is_receptive": false}
	]`), &agents))
	require.Len(t, agents, 2)
	assert.True(t, agents[0].IsReceptive)
	assert.False(t, agents[1].IsReceptive)
}

// gitlab.project.package.creator reads creator_id (decoded from client-go
// v3.14.0) and pipeline reads the package's last build pipeline. A package
// with creator_id: null and no pipeline key must resolve both to null, and the
// deprecated pipelines array must not stand in for pipeline.
func TestPackageProvenance(t *testing.T) {
	var pkgs []*gitlab.Package
	require.NoError(t, json.Unmarshal([]byte(`[
		{
			"id": 1,
			"name": "com/mycompany/my-app",
			"version": "1.0-SNAPSHOT",
			"package_type": "maven",
			"creator_id": 7,
			"pipeline": {"id": 123, "status": "success", "ref": "main", "web_url": "https://gitlab.example.com/acme/app/-/pipelines/123"},
			"pipelines": []
		},
		{
			"id": 2,
			"name": "legacy",
			"version": "0.1.0",
			"package_type": "npm",
			"creator_id": null,
			"pipelines": [{"id": 99}]
		}
	]`), &pkgs))
	require.Len(t, pkgs, 2)

	creator, pipeline := packageProvenance(pkgs[0])
	assert.Equal(t, int64(7), creator)
	require.NotNil(t, pipeline)
	assert.Equal(t, int64(123), pipeline.ID)
	assert.Equal(t, "https://gitlab.example.com/acme/app/-/pipelines/123", pipeline.WebURL)

	creator, pipeline = packageProvenance(pkgs[1])
	assert.Equal(t, int64(0), creator)
	assert.Nil(t, pipeline)

	creator, pipeline = packageProvenance(nil)
	assert.Equal(t, int64(0), creator)
	assert.Nil(t, pipeline)
}

func TestPipelineProjectPath(t *testing.T) {
	cases := map[string]string{
		"https://gitlab.example.com/acme/app/-/pipelines/123":        "acme/app",
		"https://gitlab.example.com/acme/sub/deep/app/-/pipelines/1": "acme/sub/deep/app",
		"https://gitlab.example.com/acme/app/-/pipelines/123/":       "acme/app",
		"https://gitlab.example.com/acme/app/-/jobs/5":               "",
		"https://gitlab.example.com/-/pipelines/5":                   "",
		"":             "",
		"://not a url": "",
	}
	for in, want := range cases {
		assert.Equal(t, want, pipelineProjectPath(in), in)
	}
}
