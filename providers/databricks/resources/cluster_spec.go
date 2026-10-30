// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/pipelines"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlDatabricksClusterSpecInternal keeps the policy and instance profile the
// specification references so both resolve through the root resource's shared
// listings rather than one lookup per specification.
type mqlDatabricksClusterSpecInternal struct {
	cachePolicyId           string
	cacheInstanceProfileArn string
}

// clusterSpecFields is the common shape behind the two compute definitions a
// job or pipeline can declare. Jobs use compute.ClusterSpec; pipelines use
// pipelines.PipelineCluster, which models a strict subset (a pipeline takes its
// runtime from the release channel rather than a Spark version, and supports no
// access mode, execution engine, or custom container).
type clusterSpecFields struct {
	key                        string
	sparkVersion               string
	dataSecurityMode           string
	singleUserName             string
	runtimeEngine              string
	nodeTypeId                 string
	numWorkers                 int64
	sparkConf                  map[string]string
	sparkEnvVars               map[string]string
	customTags                 map[string]string
	localDiskEncryptionEnabled bool
	initScripts                []compute.InitScriptInfo
	dockerImageUrl             string
	sshPublicKeys              []string
	googleServiceAccount       string
	policyId                   string
	instanceProfileArn         string
}

// jobClusterSpecFields adapts a job's cluster definition. The key is the job
// cluster key, or empty for compute declared inline on a single task.
func jobClusterSpecFields(key string, spec compute.ClusterSpec) clusterSpecFields {
	f := clusterSpecFields{
		key:                        key,
		sparkVersion:               spec.SparkVersion,
		dataSecurityMode:           string(spec.DataSecurityMode),
		singleUserName:             spec.SingleUserName,
		runtimeEngine:              string(spec.RuntimeEngine),
		nodeTypeId:                 spec.NodeTypeId,
		numWorkers:                 int64(spec.NumWorkers),
		sparkConf:                  spec.SparkConf,
		sparkEnvVars:               spec.SparkEnvVars,
		customTags:                 spec.CustomTags,
		localDiskEncryptionEnabled: spec.EnableLocalDiskEncryption,
		initScripts:                spec.InitScripts,
		dockerImageUrl:             dockerImageUrl(spec.DockerImage),
		sshPublicKeys:              spec.SshPublicKeys,
		googleServiceAccount:       googleServiceAccount(spec.GcpAttributes),
		policyId:                   spec.PolicyId,
	}
	if spec.AwsAttributes != nil {
		f.instanceProfileArn = spec.AwsAttributes.InstanceProfileArn
	}
	return f
}

// pipelineClusterSpecFields adapts a pipeline's cluster definition. The fields a
// PipelineCluster does not model stay empty rather than being given a default,
// because the pipeline API genuinely carries no value for them.
func pipelineClusterSpecFields(c pipelines.PipelineCluster) clusterSpecFields {
	f := clusterSpecFields{
		key:                        c.Label,
		nodeTypeId:                 c.NodeTypeId,
		numWorkers:                 int64(c.NumWorkers),
		sparkConf:                  c.SparkConf,
		sparkEnvVars:               c.SparkEnvVars,
		customTags:                 c.CustomTags,
		localDiskEncryptionEnabled: c.EnableLocalDiskEncryption,
		initScripts:                c.InitScripts,
		sshPublicKeys:              c.SshPublicKeys,
		googleServiceAccount:       googleServiceAccount(c.GcpAttributes),
		policyId:                   c.PolicyId,
	}
	if c.AwsAttributes != nil {
		f.instanceProfileArn = c.AwsAttributes.InstanceProfileArn
	}
	return f
}

// clusterSpecID composes the cache key of a compute definition from the owning
// job, task, or pipeline and the key the definition is registered under.
// Compute declared inline on a task has no key of its own, so it is named for
// what it is rather than left as a trailing separator, which keeps the id
// self-describing even if a future caller shares a prefix.
func clusterSpecID(idPrefix string, key string) string {
	if key == "" {
		key = "inline"
	}
	return idPrefix + "/clusterSpec/" + key
}

// newMqlDatabricksClusterSpec maps a compute definition to its resource. The id
// prefix identifies the owning job task or pipeline, which together with the key
// keeps every specification in a scan distinct.
func newMqlDatabricksClusterSpec(runtime *plugin.Runtime, idPrefix string, f clusterSpecFields) (*mqlDatabricksClusterSpec, error) {
	res, err := CreateResource(runtime, "databricks.clusterSpec", map[string]*llx.RawData{
		"__id":                       llx.StringData(clusterSpecID(idPrefix, f.key)),
		"key":                        llx.StringData(f.key),
		"sparkVersion":               llx.StringData(f.sparkVersion),
		"dataSecurityMode":           llx.StringData(f.dataSecurityMode),
		"singleUserName":             llx.StringData(f.singleUserName),
		"runtimeEngine":              llx.StringData(f.runtimeEngine),
		"nodeTypeId":                 llx.StringData(f.nodeTypeId),
		"numWorkers":                 llx.IntData(f.numWorkers),
		"sparkConf":                  llx.MapData(strMap(f.sparkConf), types.String),
		"sparkEnvVars":               llx.MapData(strMap(f.sparkEnvVars), types.String),
		"customTags":                 llx.MapData(strMap(f.customTags), types.String),
		"localDiskEncryptionEnabled": llx.BoolData(f.localDiskEncryptionEnabled),
		"initScripts":                llx.ArrayData(initScriptsToDict(f.initScripts), types.Dict),
		"dockerImageUrl":             llx.StringData(f.dockerImageUrl),
		"sshPublicKeys":              llx.ArrayData(strSlice(f.sshPublicKeys), types.String),
		"googleServiceAccount":       llx.StringData(f.googleServiceAccount),
	})
	if err != nil {
		return nil, err
	}
	mqlSpec := res.(*mqlDatabricksClusterSpec)
	mqlSpec.cachePolicyId = f.policyId
	mqlSpec.cacheInstanceProfileArn = f.instanceProfileArn
	return mqlSpec, nil
}

func (r *mqlDatabricksClusterSpec) policy() (*mqlDatabricksClusterPolicy, error) {
	if r.cachePolicyId == "" {
		r.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	byID, err := cachedClusterPolicies(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.cachePolicyId]
	if !ok {
		r.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksClusterPolicy(r.MqlRuntime, p)
}

// instanceProfile resolves the AWS instance profile the compute assumes. Only
// AWS definitions carry one, so a job or pipeline on another cloud never reaches
// the lookup.
func (r *mqlDatabricksClusterSpec) instanceProfile() (*mqlDatabricksInstanceProfile, error) {
	if r.cacheInstanceProfileArn == "" {
		r.InstanceProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	byARN, err := cachedInstanceProfiles(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	p, ok := byARN[r.cacheInstanceProfileArn]
	if !ok {
		r.InstanceProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksInstanceProfile(r.MqlRuntime, p)
}
