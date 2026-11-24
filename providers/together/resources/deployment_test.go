// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// envValueMarker stands in for an environment variable value. No field of the
// schema may carry it.
const envValueMarker = "ENV-VALUE-MUST-NOT-LEAK"

// jigDeploymentsFixture is shaped like the documented GET v1/deployments
// response. Synthetic: the values are invented; no live account was checked.
//
// DB_PASSWORD and SECOND_KEY read the same secret, by name and by ID, which
// must yield that secret once. MISSING_KEY names a secret the secret list does
// not carry. The data mount names its volume by name, the cache mount by ID.
const jigDeploymentsFixture = `{"data": [{
  "id": "deploy-0000",
  "name": "example-deployment",
  "image": "registry.example.invalid/app:1",
  "status": "Ready",
  "capacity_type": "preemptible",
  "command": ["python", "serve.py"],
  "args": ["--port", "8000"],
  "environment_variables": [
    {"name": "LOG_LEVEL", "value": "debug"},
    {"name": "HF_TOKEN", "value": "` + envValueMarker + `"},
    {"name": "DB_PASSWORD", "value_from_secret": "db-password"},
    {"name": "SECOND_KEY", "value_from_secret": "sec-1111"},
    {"name": "MISSING_KEY", "value_from_secret": "not-listed"}
  ],
  "volumes": [
    {"name": "datasets", "mount_path": "/data", "version": 3},
    {"name": "vol-cache", "mount_path": "/cache"}
  ],
  "model_mounts": [
    {"model_id": "ml_0000", "mount_path": "/models", "revision_id": "rv_0001"},
    {"model_id": "ml_0002", "mount_path": "/draft"}
  ]
}, {
  "id": "deploy-0001",
  "name": "bare-deployment",
  "image": "registry.example.invalid/app:2",
  "status": "Ready"
}]}`

const jigSecretsFixture = `{"data": [
  {"id": "sec-0000", "name": "unrelated"},
  {"id": "sec-1111", "name": "db-password"}
]}`

const jigVolumesFixture = `{"data": [
  {"id": "vol-data", "name": "datasets", "type": "readOnly"},
  {"id": "vol-cache", "name": "cache", "type": "readOnly"}
]}`

func jigDeployments(t *testing.T) map[string]*mqlTogetherDeployment {
	t.Helper()

	r := newRoutedTogether(t, map[string]string{
		"/v1/deployments":                 jigDeploymentsFixture,
		"/v1/deployments/secrets":         jigSecretsFixture,
		"/v1/deployments/storage/volumes": jigVolumesFixture,
	})
	list, err := r.deployments()
	require.NoError(t, err)

	byName := map[string]*mqlTogetherDeployment{}
	for _, raw := range list {
		d := raw.(*mqlTogetherDeployment)
		byName[d.Name.Data] = d
	}
	require.Len(t, byName, 2)
	return byName
}

func TestDeploymentPlaintextEnvironmentVariableNames(t *testing.T) {
	// Synthetic: jigDeploymentsFixture; no live account was checked.
	d := jigDeployments(t)["example-deployment"]

	assert.Equal(t, []any{"LOG_LEVEL", "HF_TOKEN"}, d.PlaintextEnvironmentVariableNames.Data)
	assert.Equal(t, []any{"LOG_LEVEL", "HF_TOKEN", "DB_PASSWORD", "SECOND_KEY", "MISSING_KEY"}, d.EnvironmentVariableNames.Data)
}

func TestDeploymentSecretsResolveByNameOrID(t *testing.T) {
	// Synthetic: jigDeploymentsFixture; no live account was checked.
	d := jigDeployments(t)["example-deployment"]

	secrets, err := d.secrets()
	require.NoError(t, err)
	require.Len(t, secrets, 1, "two references to one secret yield it once, and an unlisted secret is left out")
	assert.Equal(t, "sec-1111", secrets[0].(*mqlTogetherSecret).Id.Data)
}

func TestDeploymentWithoutSecretReferencesHasNoSecrets(t *testing.T) {
	// Synthetic: jigDeploymentsFixture's bare deployment; no live account was checked.
	secrets, err := jigDeployments(t)["bare-deployment"].secrets()
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestDeploymentVolumeMountsResolveVolumes(t *testing.T) {
	// Synthetic: jigDeploymentsFixture; no live account was checked.
	d := jigDeployments(t)["example-deployment"]
	require.Len(t, d.VolumeMounts.Data, 2)

	data := d.VolumeMounts.Data[0].(*mqlTogetherDeploymentVolumeMount)
	assert.Equal(t, "/data", data.Path.Data)
	assert.Equal(t, int64(3), data.Version.Data)
	vol, err := data.volume()
	require.NoError(t, err)
	require.NotNil(t, vol)
	assert.Equal(t, "vol-data", vol.Id.Data, "the volume named by name")

	cache := d.VolumeMounts.Data[1].(*mqlTogetherDeploymentVolumeMount)
	assert.Equal(t, "/cache", cache.Path.Data)
	assertNull(t, cache.Version, "version")
	vol, err = cache.volume()
	require.NoError(t, err)
	require.NotNil(t, vol)
	assert.Equal(t, "cache", vol.Name.Data, "the volume named by ID")
}

func TestDeploymentModelMounts(t *testing.T) {
	// Synthetic: jigDeploymentsFixture; no live account was checked.
	d := jigDeployments(t)["example-deployment"]
	require.Len(t, d.ModelMounts.Data, 2)

	pinned := d.ModelMounts.Data[0].(*mqlTogetherDeploymentModelMount)
	assert.Equal(t, "/models", pinned.Path.Data)
	assert.Equal(t, "ml_0000", pinned.ModelId.Data)
	assert.Equal(t, "rv_0001", pinned.RevisionId.Data)

	latest := d.ModelMounts.Data[1].(*mqlTogetherDeploymentModelMount)
	assert.Equal(t, "ml_0002", latest.ModelId.Data)
	assertNull(t, latest.RevisionId, "revisionId")
}

func TestDeploymentContainerSettings(t *testing.T) {
	// Synthetic: jigDeploymentsFixture; no live account was checked.
	deployments := jigDeployments(t)

	d := deployments["example-deployment"]
	assert.Equal(t, "preemptible", d.CapacityType.Data)

	bare := deployments["bare-deployment"]
	assertNull(t, bare.CapacityType, "capacityType")
	assert.Empty(t, bare.VolumeMounts.Data)
	assert.Empty(t, bare.ModelMounts.Data)
}

func TestDeploymentEnvironmentValuesNeverReachTheSchema(t *testing.T) {
	// Synthetic: jigDeploymentsFixture, whose HF_TOKEN carries a marker value; no live account was checked.
	d := jigDeployments(t)["example-deployment"]

	fields := 0
	for field, get := range getDataFields {
		if !strings.HasPrefix(field, "together.deployment.") || strings.Count(field, ".") != 2 {
			continue
		}
		fields++
		assert.NotContains(t, dataResText(get(d)), envValueMarker, "%s leaked an environment variable value", field)
	}
	assert.Greater(t, fields, 20, "the deployment fields were not enumerated")
}

func TestSelectVolumePrefersTheID(t *testing.T) {
	// Synthetic: a volume whose name equals another volume's ID; no live account was checked.
	volume := func(id, name string) *mqlTogetherVolume {
		return &mqlTogetherVolume{
			Id:   plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
			Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		}
	}
	volumes := []any{volume("vol-a", "vol-b"), volume("vol-b", "other")}

	got := selectVolume(volumes, "vol-b")
	require.NotNil(t, got)
	assert.Equal(t, "other", got.Name.Data)
	assert.Nil(t, selectVolume(volumes, "missing"))
}
