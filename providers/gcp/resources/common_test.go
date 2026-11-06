// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestBoolValueToPtr(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := boolValueToPtr(nil)
		assert.Nil(t, result)
	})

	t.Run("true value", func(t *testing.T) {
		result := boolValueToPtr(wrapperspb.Bool(true))
		require.NotNil(t, result)
		assert.True(t, *result)
	})

	t.Run("false value", func(t *testing.T) {
		result := boolValueToPtr(wrapperspb.Bool(false))
		require.NotNil(t, result)
		assert.False(t, *result)
	})
}

func TestRegionNameFromRegionUrl(t *testing.T) {
	assert.Equal(t, "us-central1", RegionNameFromRegionUrl("https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1"))
	assert.Equal(t, "europe-west1", RegionNameFromRegionUrl("europe-west1"))
	assert.Equal(t, "", RegionNameFromRegionUrl(""))
}

func TestParseSubnetworkURL(t *testing.T) {
	t.Run("www.googleapis.com host", func(t *testing.T) {
		project, region, name, ok := parseSubnetworkURL("https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/subnetworks/subnet-1")
		require.True(t, ok)
		assert.Equal(t, "my-project", project)
		assert.Equal(t, "us-central1", region)
		assert.Equal(t, "subnet-1", name)
	})
	t.Run("compute.googleapis.com host", func(t *testing.T) {
		project, region, name, ok := parseSubnetworkURL("https://compute.googleapis.com/compute/v1/projects/my-project/regions/europe-west1/subnetworks/subnet-2")
		require.True(t, ok)
		assert.Equal(t, "my-project", project)
		assert.Equal(t, "europe-west1", region)
		assert.Equal(t, "subnet-2", name)
	})
	t.Run("empty url", func(t *testing.T) {
		_, _, _, ok := parseSubnetworkURL("")
		assert.False(t, ok)
	})
	t.Run("malformed / too short does not panic", func(t *testing.T) {
		_, _, _, ok := parseSubnetworkURL("https://www.googleapis.com/compute/v1/projects/my-project")
		assert.False(t, ok)
	})
	t.Run("wrong resource kind", func(t *testing.T) {
		_, _, _, ok := parseSubnetworkURL("https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/disks/disk-1")
		assert.False(t, ok)
	})
}

func TestGetDiskIdByUrl(t *testing.T) {
	okCases := []struct {
		url                   string
		project, region, name string
	}{
		{
			"https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/disks/disk-1",
			"p1", "us-central1-a", "disk-1",
		},
		{
			"https://compute.googleapis.com/compute/v1/projects/p2/regions/us-east1/disks/rdisk",
			"p2", "us-east1", "rdisk",
		},
	}
	for _, c := range okCases {
		id, err := getDiskIdByUrl(c.url)
		require.NoError(t, err)
		assert.Equal(t, c.project, id.Project)
		assert.Equal(t, c.region, id.Region)
		assert.Equal(t, c.name, id.Name)
	}

	// Malformed URLs must return an error, not panic on an out-of-range index.
	for _, u := range []string{"", "not-a-url", "https://www.googleapis.com/compute/v1/projects/p1"} {
		_, err := getDiskIdByUrl(u)
		assert.Error(t, err, "getDiskIdByUrl(%q) should error", u)
	}
}

func TestProjectFromResourceName(t *testing.T) {
	cases := map[string]string{
		"projects/my-proj/topics/t1":              "my-proj",
		"projects/p2/locations/us/backupVaults/v": "p2",
		"projects/only-project":                   "only-project",
		"organizations/123/folders/456":           "",
		"no-projects-segment/here":                "",
		"":                                        "",
	}
	for in, want := range cases {
		assert.Equal(t, want, projectFromResourceName(in), "projectFromResourceName(%q)", in)
	}
}

// envNamesAndValues returns the name and (possibly absent) value of every
// entry in a dict's env list.
func envNamesAndValues(t *testing.T, env any) map[string]any {
	t.Helper()
	list, ok := env.([]any)
	require.True(t, ok, "env is not a list: %#v", env)
	res := map[string]any{}
	for _, e := range list {
		m := e.(map[string]any)
		res[m["name"].(string)] = m["value"]
	}
	return res
}

func secretEnv() []*aiplatformpb.EnvVar {
	return []*aiplatformpb.EnvVar{
		{Name: "API_TOKEN", Value: "s3cr3t"},
		{Name: "MODE", Value: "prod"},
	}
}

func TestProtoToDictRedactsReasoningEngineSpec(t *testing.T) {
	// Synthetic: a source-code deployment with an inline archive, plain env
	// vars, a secret-backed env var and image build args.
	spec := &aiplatformpb.ReasoningEngineSpec{
		DeploymentSpec: &aiplatformpb.ReasoningEngineSpec_DeploymentSpec{
			Env: secretEnv(),
			SecretEnv: []*aiplatformpb.SecretEnvVar{{
				Name:      "DB_PASSWORD",
				SecretRef: &aiplatformpb.SecretRef{Secret: "db-password", Version: "3"},
			}},
		},
		DeploymentSource: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_{
			SourceCodeSpec: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec{
				Source: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_InlineSource_{
					InlineSource: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_InlineSource{
						SourceArchive: []byte("PK\x03\x04 agent source with a hardcoded key"),
					},
				},
				LanguageSpec: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_ImageSpec_{
					ImageSpec: &aiplatformpb.ReasoningEngineSpec_SourceCodeSpec_ImageSpec{
						BuildArgs: map[string]string{"PIP_INDEX_TOKEN": "tok"},
					},
				},
			},
		},
	}

	d, err := protoToDict(spec)
	require.NoError(t, err)

	dep := d["deploymentSpec"].(map[string]any)
	env := envNamesAndValues(t, dep["env"])
	assert.Contains(t, env, "API_TOKEN")
	assert.Contains(t, env, "MODE")
	assert.Nil(t, env["API_TOKEN"])
	assert.Nil(t, env["MODE"])

	// The secret reference names a Secret Manager secret, not its value.
	secretEnv := dep["secretEnv"].([]any)[0].(map[string]any)
	assert.Equal(t, "db-password", secretEnv["secretRef"].(map[string]any)["secret"])

	src := d["sourceCodeSpec"].(map[string]any)
	assert.NotContains(t, src["inlineSource"], "sourceArchive")
	assert.Equal(t, map[string]any{"PIP_INDEX_TOKEN": ""}, src["imageSpec"].(map[string]any)["buildArgs"])

	// The caller's message is untouched.
	assert.Equal(t, "s3cr3t", spec.DeploymentSpec.Env[0].Value)
	assert.NotEmpty(t, spec.GetSourceCodeSpec().GetInlineSource().GetSourceArchive())
	assert.Equal(t, "tok", spec.GetSourceCodeSpec().GetImageSpec().GetBuildArgs()["PIP_INDEX_TOKEN"])
}

func TestProtoToDictRedactsCustomJobEnv(t *testing.T) {
	// Synthetic: a custom job with a container worker pool and a Python
	// package worker pool, each with env vars.
	spec := &aiplatformpb.CustomJobSpec{
		WorkerPoolSpecs: []*aiplatformpb.WorkerPoolSpec{
			{Task: &aiplatformpb.WorkerPoolSpec_ContainerSpec{ContainerSpec: &aiplatformpb.ContainerSpec{
				ImageUri: "gcr.io/p/trainer", Env: secretEnv(),
			}}},
			{Task: &aiplatformpb.WorkerPoolSpec_PythonPackageSpec{PythonPackageSpec: &aiplatformpb.PythonPackageSpec{
				PythonModule: "trainer.task", Env: secretEnv(),
			}}},
		},
	}

	d, err := protoToDict(spec)
	require.NoError(t, err)
	pools := d["workerPoolSpecs"].([]any)

	container := pools[0].(map[string]any)["containerSpec"].(map[string]any)
	assert.Equal(t, "gcr.io/p/trainer", container["imageUri"])
	assert.Equal(t, map[string]any{"API_TOKEN": nil, "MODE": nil}, envNamesAndValues(t, container["env"]))

	python := pools[1].(map[string]any)["pythonPackageSpec"].(map[string]any)
	assert.Equal(t, map[string]any{"API_TOKEN": nil, "MODE": nil}, envNamesAndValues(t, python["env"]))
}

func TestProtoToDictRedactsHyperparameterTuningTrialJobEnv(t *testing.T) {
	// Synthetic: the trial job spec of a hyperparameter tuning job.
	job := &aiplatformpb.HyperparameterTuningJob{
		TrialJobSpec: &aiplatformpb.CustomJobSpec{
			WorkerPoolSpecs: []*aiplatformpb.WorkerPoolSpec{
				{Task: &aiplatformpb.WorkerPoolSpec_ContainerSpec{ContainerSpec: &aiplatformpb.ContainerSpec{Env: secretEnv()}}},
			},
		},
	}

	d, err := protoToDict(job.TrialJobSpec)
	require.NoError(t, err)
	container := d["workerPoolSpecs"].([]any)[0].(map[string]any)["containerSpec"].(map[string]any)
	assert.Equal(t, map[string]any{"API_TOKEN": nil, "MODE": nil}, envNamesAndValues(t, container["env"]))
}

func TestProtoToDictRedactsModelContainerEnv(t *testing.T) {
	// Synthetic: a model serving container with env vars.
	spec := &aiplatformpb.ModelContainerSpec{ImageUri: "gcr.io/p/serve", Env: secretEnv()}

	d, err := protoToDict(spec)
	require.NoError(t, err)
	assert.Equal(t, "gcr.io/p/serve", d["imageUri"])
	assert.Equal(t, map[string]any{"API_TOKEN": nil, "MODE": nil}, envNamesAndValues(t, d["env"]))
}

func TestProtoToDictRedactsNotebookSoftwareConfigEnv(t *testing.T) {
	// Synthetic: a Colab Enterprise runtime's software config.
	cfg := &aiplatformpb.NotebookSoftwareConfig{Env: secretEnv()}

	d, err := protoToDict(cfg)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"API_TOKEN": nil, "MODE": nil}, envNamesAndValues(t, d["env"]))
}

func TestRedactSecretFieldsLeavesCleanMessagesAlone(t *testing.T) {
	// Synthetic: nothing to redact, so no clone is made.
	msg := &aiplatformpb.EncryptionSpec{KmsKeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k"}
	assert.Same(t, msg, redactSecretFields(msg))

	// Synthetic: an env var without a value needs nothing removed either.
	empty := &aiplatformpb.ModelContainerSpec{Env: []*aiplatformpb.EnvVar{{Name: "ONLY_NAME"}}}
	assert.Same(t, empty, redactSecretFields(empty))
}
