// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/pipelines"
)

func TestClusterSpecID(t *testing.T) {
	t.Run("names inline compute rather than trailing the separator", func(t *testing.T) {
		got := clusterSpecID("databricks.job/1/task/etl", "")
		want := "databricks.job/1/task/etl/clusterSpec/inline"
		if got != want {
			t.Fatalf("clusterSpecID() = %q, want %q", got, want)
		}
	})

	t.Run("uses the key when the compute has one", func(t *testing.T) {
		got := clusterSpecID("databricks.job/1", "shared-etl")
		want := "databricks.job/1/clusterSpec/shared-etl"
		if got != want {
			t.Fatalf("clusterSpecID() = %q, want %q", got, want)
		}
	})

	t.Run("every compute definition of one job gets a distinct id", func(t *testing.T) {
		// A job declares reusable job clusters and each task may declare its own
		// inline compute. A duplicate id would collapse two definitions into one
		// in the resource cache, so a task would report another task's compute.
		ids := []string{
			clusterSpecID("databricks.job/1", "shared-etl"),
			clusterSpecID("databricks.job/1", "shared-ml"),
			clusterSpecID("databricks.job/1/task/ingest", ""),
			clusterSpecID("databricks.job/1/task/transform", ""),
			clusterSpecID("databricks.pipeline/p-1", "default"),
			clusterSpecID("databricks.pipeline/p-1", "maintenance"),
		}

		seen := map[string]struct{}{}
		for _, id := range ids {
			if _, dup := seen[id]; dup {
				t.Fatalf("duplicate id %q, one compute definition would be lost", id)
			}
			seen[id] = struct{}{}
		}
	})

	t.Run("a job cluster key cannot collide with a task's inline compute", func(t *testing.T) {
		// The literal "inline" is a plausible job cluster key, so check that the
		// prefixes keep the two apart on their own.
		jobCluster := clusterSpecID("databricks.job/1", "inline")
		taskInline := clusterSpecID("databricks.job/1/task/inline", "")
		if jobCluster == taskInline {
			t.Fatalf("job cluster and inline task compute share the id %q", jobCluster)
		}
	})
}

func TestJobClusterSpecFieldsCarriesEveryField(t *testing.T) {
	// The adapter is the only thing standing between the SDK's cluster
	// specification and what a scan reports, so a dropped field is invisible:
	// the resource still renders, just with a blank where a shared Spark
	// configuration or an SSH key should be.
	spec := compute.ClusterSpec{
		SparkVersion:              "14.3.x-scala2.12",
		DataSecurityMode:          compute.DataSecurityModeUserIsolation,
		SingleUserName:            "ada@example.com",
		RuntimeEngine:             compute.RuntimeEnginePhoton,
		NodeTypeId:                "i3.xlarge",
		NumWorkers:                4,
		SparkConf:                 map[string]string{"spark.sql.shuffle.partitions": "200"},
		SparkEnvVars:              map[string]string{"SECRET_REF": "{{secrets/scope/key}}"},
		CustomTags:                map[string]string{"env": "prod"},
		EnableLocalDiskEncryption: true,
		InitScripts: []compute.InitScriptInfo{
			{Workspace: &compute.WorkspaceStorageInfo{Destination: "/Shared/init.sh"}},
		},
		DockerImage:   &compute.DockerImage{Url: "registry.example.com/img:1"},
		SshPublicKeys: []string{"ssh-ed25519 AAAA"},
		GcpAttributes: &compute.GcpAttributes{GoogleServiceAccount: "sa@project.iam.gserviceaccount.com"},
		PolicyId:      "policy-1",
		AwsAttributes: &compute.AwsAttributes{InstanceProfileArn: "arn:aws:iam::123456789012:instance-profile/etl"},
	}

	got := jobClusterSpecFields("etl", spec)

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"key", got.key, "etl"},
		{"sparkVersion", got.sparkVersion, "14.3.x-scala2.12"},
		{"dataSecurityMode", got.dataSecurityMode, "USER_ISOLATION"},
		{"singleUserName", got.singleUserName, "ada@example.com"},
		{"runtimeEngine", got.runtimeEngine, "PHOTON"},
		{"nodeTypeId", got.nodeTypeId, "i3.xlarge"},
		{"numWorkers", got.numWorkers, int64(4)},
		{"localDiskEncryptionEnabled", got.localDiskEncryptionEnabled, true},
		{"dockerImageUrl", got.dockerImageUrl, "registry.example.com/img:1"},
		{"googleServiceAccount", got.googleServiceAccount, "sa@project.iam.gserviceaccount.com"},
		{"policyId", got.policyId, "policy-1"},
		{"instanceProfileArn", got.instanceProfileArn, "arn:aws:iam::123456789012:instance-profile/etl"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if !reflect.DeepEqual(got.sparkConf, spec.SparkConf) {
		t.Errorf("sparkConf = %v, want %v", got.sparkConf, spec.SparkConf)
	}
	// Spark environment variables routinely hold secret references, so losing
	// them would hide exactly what an audit is looking for.
	if !reflect.DeepEqual(got.sparkEnvVars, spec.SparkEnvVars) {
		t.Errorf("sparkEnvVars = %v, want %v", got.sparkEnvVars, spec.SparkEnvVars)
	}
	if !reflect.DeepEqual(got.customTags, spec.CustomTags) {
		t.Errorf("customTags = %v, want %v", got.customTags, spec.CustomTags)
	}
	if !reflect.DeepEqual(got.sshPublicKeys, spec.SshPublicKeys) {
		t.Errorf("sshPublicKeys = %v, want %v", got.sshPublicKeys, spec.SshPublicKeys)
	}
	if len(got.initScripts) != 1 || got.initScripts[0].Workspace == nil {
		t.Errorf("initScripts = %v, want the workspace script carried through", got.initScripts)
	}
}

func TestPipelineClusterSpecFieldsCarriesEveryField(t *testing.T) {
	cluster := pipelines.PipelineCluster{
		Label:                     "maintenance",
		NodeTypeId:                "i3.xlarge",
		NumWorkers:                2,
		SparkConf:                 map[string]string{"spark.databricks.delta.preview.enabled": "true"},
		SparkEnvVars:              map[string]string{"SECRET_REF": "{{secrets/scope/key}}"},
		CustomTags:                map[string]string{"env": "prod"},
		EnableLocalDiskEncryption: true,
		InitScripts: []compute.InitScriptInfo{
			{Volumes: &compute.VolumesStorageInfo{Destination: "/Volumes/main/default/vol/init.sh"}},
		},
		SshPublicKeys: []string{"ssh-ed25519 AAAA"},
		GcpAttributes: &compute.GcpAttributes{GoogleServiceAccount: "sa@project.iam.gserviceaccount.com"},
		PolicyId:      "policy-2",
		AwsAttributes: &compute.AwsAttributes{InstanceProfileArn: "arn:aws:iam::123456789012:instance-profile/dlt"},
	}

	got := pipelineClusterSpecFields(cluster)

	if got.key != "maintenance" {
		t.Errorf("key = %q, want the pipeline cluster label", got.key)
	}
	if got.nodeTypeId != "i3.xlarge" || got.numWorkers != 2 {
		t.Errorf("node shape = (%q, %d), want (i3.xlarge, 2)", got.nodeTypeId, got.numWorkers)
	}
	if !got.localDiskEncryptionEnabled {
		t.Error("localDiskEncryptionEnabled = false, want true")
	}
	if got.policyId != "policy-2" {
		t.Errorf("policyId = %q, want policy-2", got.policyId)
	}
	if got.instanceProfileArn != "arn:aws:iam::123456789012:instance-profile/dlt" {
		t.Errorf("instanceProfileArn = %q, want the AWS attributes ARN", got.instanceProfileArn)
	}
	if got.googleServiceAccount != "sa@project.iam.gserviceaccount.com" {
		t.Errorf("googleServiceAccount = %q, want the GCP attributes account", got.googleServiceAccount)
	}
	if !reflect.DeepEqual(got.sparkConf, cluster.SparkConf) {
		t.Errorf("sparkConf = %v, want %v", got.sparkConf, cluster.SparkConf)
	}
	if !reflect.DeepEqual(got.sparkEnvVars, cluster.SparkEnvVars) {
		t.Errorf("sparkEnvVars = %v, want %v", got.sparkEnvVars, cluster.SparkEnvVars)
	}
	if !reflect.DeepEqual(got.customTags, cluster.CustomTags) {
		t.Errorf("customTags = %v, want %v", got.customTags, cluster.CustomTags)
	}
	if !reflect.DeepEqual(got.sshPublicKeys, cluster.SshPublicKeys) {
		t.Errorf("sshPublicKeys = %v, want %v", got.sshPublicKeys, cluster.SshPublicKeys)
	}
	if len(got.initScripts) != 1 || got.initScripts[0].Volumes == nil {
		t.Errorf("initScripts = %v, want the volumes script carried through", got.initScripts)
	}

	// A pipeline cluster carries no Spark version, access mode, execution
	// engine, or container image. These must stay empty rather than be given a
	// default, because the pipeline API has no value for them and a default
	// would report a posture the platform never declared.
	if got.sparkVersion != "" {
		t.Errorf("sparkVersion = %q, want empty", got.sparkVersion)
	}
	if got.dataSecurityMode != "" {
		t.Errorf("dataSecurityMode = %q, want empty", got.dataSecurityMode)
	}
	if got.runtimeEngine != "" {
		t.Errorf("runtimeEngine = %q, want empty", got.runtimeEngine)
	}
	if got.dockerImageUrl != "" {
		t.Errorf("dockerImageUrl = %q, want empty", got.dockerImageUrl)
	}
	if got.singleUserName != "" {
		t.Errorf("singleUserName = %q, want empty", got.singleUserName)
	}
}
