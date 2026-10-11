// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/sql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlDatabricksClusterInternal struct {
	cachePolicyId           string
	cacheInstanceProfileArn string
	cacheInstancePoolId     string

	// policyCompliant and policyViolations come from one call, fetched at most
	// once per cluster.
	policyComplianceOnce sync.Once
	policyCompliance     clusterCompliance
}

// initScriptsToDict normalizes the cluster init scripts into a list of dicts,
// one per script, preserving the configured order. InitScriptInfo is a union in
// which exactly one storage field is set, so each entry is flattened to the
// storage type plus its destination. Only JSON-native values are used, as llx
// dicts accept nothing else.
func initScriptsToDict(scripts []compute.InitScriptInfo) []any {
	out := make([]any, 0, len(scripts))
	for i := range scripts {
		s := scripts[i]
		var entry map[string]any
		switch {
		case s.Workspace != nil:
			entry = map[string]any{"type": "workspace", "destination": s.Workspace.Destination}
		case s.Volumes != nil:
			entry = map[string]any{"type": "volumes", "destination": s.Volumes.Destination}
		case s.S3 != nil:
			entry = map[string]any{
				"type":             "s3",
				"destination":      s.S3.Destination,
				"region":           s.S3.Region,
				"endpoint":         s.S3.Endpoint,
				"enableEncryption": s.S3.EnableEncryption,
			}
		case s.Abfss != nil:
			entry = map[string]any{"type": "abfss", "destination": s.Abfss.Destination}
		case s.Gcs != nil:
			entry = map[string]any{"type": "gcs", "destination": s.Gcs.Destination}
		case s.Dbfs != nil:
			entry = map[string]any{"type": "dbfs", "destination": s.Dbfs.Destination}
		case s.File != nil:
			entry = map[string]any{"type": "file", "destination": s.File.Destination}
		default:
			// A script whose storage type this SDK version does not model still
			// needs to appear, otherwise the list silently under-reports.
			entry = map[string]any{"type": "", "destination": ""}
		}
		out = append(out, entry)
	}
	return out
}

// dockerImageUrl returns the custom container image URL, or an empty string when
// the cluster boots a stock runtime. The basic-auth credentials that may
// accompany the image are deliberately not exposed, as they include a password.
func dockerImageUrl(img *compute.DockerImage) string {
	if img == nil {
		return ""
	}
	return img.Url
}

// googleServiceAccount returns the service account a GCP cluster impersonates,
// or an empty string on clusters that are not on GCP or that use no account.
func googleServiceAccount(attrs *compute.GcpAttributes) string {
	if attrs == nil {
		return ""
	}
	return attrs.GoogleServiceAccount
}

// cachedInstanceProfiles lists the workspace instance profiles at most once per
// scan, caching them on the root databricks resource keyed by ARN so that
// per-cluster resolutions (databricks.clusters { instanceProfile }) share a
// single ListAll rather than one lookup per cluster.
func cachedInstanceProfiles(runtime *plugin.Runtime) (map[string]compute.InstanceProfile, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.instanceProfilesOnce.Do(func() {
		ws, err := workspaceClient(runtime)
		if err != nil {
			root.instanceProfilesErr = err
			return
		}
		profiles, err := ws.InstanceProfiles.ListAll(context.Background())
		if err != nil {
			root.instanceProfilesErr = err
			return
		}
		byARN := make(map[string]compute.InstanceProfile, len(profiles))
		for i := range profiles {
			byARN[profiles[i].InstanceProfileArn] = profiles[i]
		}
		root.instanceProfilesByARN = byARN
	})
	return root.instanceProfilesByARN, root.instanceProfilesErr
}

// cachedClusterPolicies lists the workspace cluster policies at most once per
// scan, caching the result on the root databricks resource keyed by policy id so
// that per-cluster policy resolutions (databricks.clusters { policy }) share a
// single ListAll rather than one Get per cluster.
func cachedClusterPolicies(runtime *plugin.Runtime) (map[string]compute.Policy, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.policiesOnce.Do(func() {
		ws, err := workspaceClient(runtime)
		if err != nil {
			root.policiesErr = err
			return
		}
		policies, err := ws.ClusterPolicies.ListAll(context.Background(), compute.ListClusterPoliciesRequest{})
		if err != nil {
			root.policiesErr = err
			return
		}
		byID := make(map[string]compute.Policy, len(policies))
		for i := range policies {
			byID[policies[i].PolicyId] = policies[i]
		}
		root.policiesByID = byID
	})
	return root.policiesByID, root.policiesErr
}

func (r *mqlDatabricks) clusterPolicies() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	policies, err := ws.ClusterPolicies.ListAll(context.Background(), compute.ListClusterPoliciesRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range policies {
		mqlPolicy, err := newMqlDatabricksClusterPolicy(r.MqlRuntime, policies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, mqlPolicy)
	}
	return out, nil
}

func newMqlDatabricksClusterPolicy(runtime *plugin.Runtime, p compute.Policy) (*mqlDatabricksClusterPolicy, error) {
	res, err := CreateResource(runtime, "databricks.clusterPolicy", map[string]*llx.RawData{
		"__id":               llx.StringData("databricks.clusterPolicy/" + p.PolicyId),
		"id":                 llx.StringData(p.PolicyId),
		"name":               llx.StringData(p.Name),
		"description":        llx.StringData(p.Description),
		"definition":         llx.StringData(p.Definition),
		"maxClustersPerUser": llx.IntData(p.MaxClustersPerUser),
		"isDefault":          llx.BoolData(p.IsDefault),
		"creatorUserName":    llx.StringData(p.CreatorUserName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksClusterPolicy), nil
}

func (r *mqlDatabricks) clusters() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	clusters, err := ws.Clusters.ListAll(context.Background(), compute.ListClustersRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range clusters {
		mqlCluster, err := newMqlDatabricksCluster(r.MqlRuntime, clusters[i])
		if err != nil {
			return nil, err
		}
		out = append(out, mqlCluster)
	}
	return out, nil
}

// newMqlDatabricksCluster maps a cluster to its resource. Shared by the list
// path and the init lookup so a cluster hydrated by id carries the same fields
// as a listed one.
func newMqlDatabricksCluster(runtime *plugin.Runtime, c compute.ClusterDetails) (*mqlDatabricksCluster, error) {
	res, err := CreateResource(runtime, "databricks.cluster", map[string]*llx.RawData{
		"__id":                       llx.StringData("databricks.cluster/" + c.ClusterId),
		"id":                         llx.StringData(c.ClusterId),
		"clusterName":                llx.StringData(c.ClusterName),
		"state":                      llx.StringData(string(c.State)),
		"dataSecurityMode":           llx.StringData(string(c.DataSecurityMode)),
		"singleUserName":             llx.StringData(c.SingleUserName),
		"sparkVersion":               llx.StringData(c.SparkVersion),
		"runtimeEngine":              llx.StringData(string(c.RuntimeEngine)),
		"sparkConf":                  llx.MapData(strMap(c.SparkConf), types.String),
		"sparkEnvVars":               llx.MapData(strMap(c.SparkEnvVars), types.String),
		"localDiskEncryptionEnabled": llx.BoolData(c.EnableLocalDiskEncryption),
		"autoterminationMinutes":     llx.IntData(c.AutoterminationMinutes),
		"creatorUserName":            llx.StringData(c.CreatorUserName),
		"customTags":                 llx.MapData(strMap(c.CustomTags), types.String),
		"initScripts":                llx.ArrayData(initScriptsToDict(c.InitScripts), types.Dict),
		"dockerImageUrl":             llx.StringData(dockerImageUrl(c.DockerImage)),
		"sshPublicKeys":              llx.ArrayData(strSlice(c.SshPublicKeys), types.String),
		"dependencyMode":             llx.StringData(string(c.DependencyMode)),
		"googleServiceAccount":       llx.StringData(googleServiceAccount(c.GcpAttributes)),
	})
	if err != nil {
		return nil, err
	}
	mqlCluster := res.(*mqlDatabricksCluster)
	mqlCluster.cachePolicyId = c.PolicyId
	mqlCluster.cacheInstancePoolId = c.InstancePoolId
	if c.AwsAttributes != nil {
		mqlCluster.cacheInstanceProfileArn = c.AwsAttributes.InstanceProfileArn
	}
	return mqlCluster, nil
}

// initDatabricksCluster resolves a single cluster by id so references from a job
// task can hydrate a full cluster from just its id.
func initDatabricksCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, fmt.Errorf("databricks.cluster requires a non-empty id")
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	cluster, err := ws.Clusters.GetByClusterId(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	if cluster == nil {
		return nil, nil, fmt.Errorf("databricks.cluster with id %q not found", id)
	}

	res, err := newMqlDatabricksCluster(runtime, *cluster)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricksCluster) policy() (*mqlDatabricksClusterPolicy, error) {
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

func (r *mqlDatabricksCluster) instanceProfile() (*mqlDatabricksInstanceProfile, error) {
	// Only AWS clusters carry an instance profile, so a workspace on another
	// cloud never reaches the lookup below.
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

// warehouseStatementTimeoutSeconds reports the warehouse's own statement
// timeout, or null when it sets none. The API treats 0 as "no warehouse
// timeout", so the workspace STATEMENT_TIMEOUT applies; reporting 0 would read
// as "statements never time out".
func warehouseStatementTimeoutSeconds(w sql.EndpointInfo) *llx.RawData {
	if w.StatementTimeout <= 0 {
		return llx.NilData
	}
	return llx.IntData(int64(w.StatementTimeout))
}

// warehouseFields maps one warehouse list record to its MQL fields.
func warehouseFields(w sql.EndpointInfo) map[string]*llx.RawData {
	channel := ""
	if w.Channel != nil {
		channel = string(w.Channel.Name)
	}
	return map[string]*llx.RawData{
		"__id":                    llx.StringData("databricks.warehouse/" + w.Id),
		"id":                      llx.StringData(w.Id),
		"name":                    llx.StringData(w.Name),
		"state":                   llx.StringData(string(w.State)),
		"warehouseType":           llx.StringData(string(w.WarehouseType)),
		"photonEnabled":           llx.BoolData(w.EnablePhoton),
		"serverlessEnabled":       llx.BoolData(w.EnableServerlessCompute),
		"channel":                 llx.StringData(channel),
		"clusterSize":             llx.StringData(w.ClusterSize),
		"autoStopMinutes":         llx.IntData(w.AutoStopMins),
		"creatorName":             llx.StringData(w.CreatorName),
		"statementTimeoutSeconds": warehouseStatementTimeoutSeconds(w),
	}
}

func (r *mqlDatabricks) warehouses() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	warehouses, err := ws.Warehouses.ListAll(context.Background(), sql.ListWarehousesRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range warehouses {
		res, err := CreateResource(r.MqlRuntime, "databricks.warehouse", warehouseFields(warehouses[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
