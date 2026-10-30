// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/databricks/databricks-sdk-go/service/catalog"
	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/workspace"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlDatabricks) repos() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	repos, err := ws.Repos.ListAll(context.Background(), workspace.ListReposRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range repos {
		repo := repos[i]
		patterns := []string{}
		if repo.SparseCheckout != nil {
			patterns = repo.SparseCheckout.Patterns
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.repo", map[string]*llx.RawData{
			"__id":                   llx.StringData("databricks.repo/" + strconv.FormatInt(repo.Id, 10)),
			"id":                     llx.IntData(repo.Id),
			"path":                   llx.StringData(repo.Path),
			"url":                    llx.StringData(repo.Url),
			"provider":               llx.StringData(repo.Provider),
			"branch":                 llx.StringData(repo.Branch),
			"headCommitId":           llx.StringData(repo.HeadCommitId),
			"sparseCheckoutPatterns": llx.ArrayData(strSlice(patterns), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksRepo) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectRepo, strconv.FormatInt(r.Id.Data, 10))
}

func (r *mqlDatabricks) gitCredentials() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	creds, err := ws.GitCredentials.ListAll(context.Background(), workspace.ListCredentialsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range creds {
		c := creds[i]
		// The personal access token behind the credential is write-only in the
		// API and never returned, so nothing here is secret material.
		res, err := CreateResource(r.MqlRuntime, "databricks.gitCredential", map[string]*llx.RawData{
			"__id":                 llx.StringData("databricks.gitCredential/" + strconv.FormatInt(c.CredentialId, 10)),
			"id":                   llx.IntData(c.CredentialId),
			"name":                 llx.StringData(c.Name),
			"gitProvider":          llx.StringData(c.GitProvider),
			"gitUsername":          llx.StringData(c.GitUsername),
			"gitEmail":             llx.StringData(c.GitEmail),
			"isDefaultForProvider": llx.BoolData(c.IsDefaultForProvider),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// artifactAllowlistTypes are the artifact kinds a metastore keeps a separate
// allowlist for. The API exposes no listing, only a get per type, so the set is
// enumerated here.
var artifactAllowlistTypes = []catalog.ArtifactType{
	catalog.ArtifactTypeInitScript,
	catalog.ArtifactTypeLibraryJar,
	catalog.ArtifactTypeLibraryMaven,
}

func (r *mqlDatabricks) artifactAllowlists() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, artifactType := range artifactAllowlistTypes {
		allowlist, err := ws.ArtifactAllowlists.GetByArtifactType(context.Background(), artifactType)
		if err != nil {
			return nil, err
		}

		matchers := make(map[string]any, len(allowlist.ArtifactMatchers))
		for i := range allowlist.ArtifactMatchers {
			m := allowlist.ArtifactMatchers[i]
			matchers[m.Artifact] = string(m.MatchType)
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.artifactAllowlist", map[string]*llx.RawData{
			"__id":         llx.StringData("databricks.artifactAllowlist/" + allowlist.MetastoreId + "/" + string(artifactType)),
			"artifactType": llx.StringData(string(artifactType)),
			"matchers":     llx.MapData(matchers, types.String),
			"metastoreId":  llx.StringData(allowlist.MetastoreId),
			"createdAt":    llx.TimeDataPtr(epochMsTime(allowlist.CreatedAt)),
			"createdBy":    llx.StringData(allowlist.CreatedBy),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// cachedInstancePools lists the workspace instance pools at most once per scan,
// caching them on the root databricks resource so that the pool listing
// (databricks.instancePools) and the per-cluster resolutions
// (databricks.clusters { instancePool }) share a single List rather than one
// List each plus one Get per cluster.
//
// Both shapes are kept: the slice preserves the order the API returned, which
// the listing reports, and the map keyed by pool id serves the per-cluster
// lookups. Ranging over the map for the listing would reorder it on every scan.
func cachedInstancePools(runtime *plugin.Runtime) ([]compute.InstancePoolAndStats, map[string]compute.InstancePoolAndStats, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.instancePoolsOnce.Do(func() {
		ws, err := workspaceClient(runtime)
		if err != nil {
			root.instancePoolsErr = err
			return
		}
		pools, err := listInstancePools(ws.InstancePools)
		if err != nil {
			root.instancePoolsErr = err
			return
		}
		byID := make(map[string]compute.InstancePoolAndStats, len(pools))
		for i := range pools {
			byID[pools[i].InstancePoolId] = pools[i]
		}
		root.instancePoolList = pools
		root.instancePoolsByID = byID
	})
	return root.instancePoolList, root.instancePoolsByID, root.instancePoolsErr
}

// listInstancePools drains the pool listing iterator. The instance pools API
// returns every pool in one response and the SDK exposes no ListAll for it.
func listInstancePools(api compute.InstancePoolsInterface) ([]compute.InstancePoolAndStats, error) {
	ctx := context.Background()
	out := []compute.InstancePoolAndStats{}
	iter := api.List(ctx)
	for iter.HasNext(ctx) {
		pool, err := iter.Next(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, pool)
	}
	return out, nil
}

// poolDiskSpec flattens the managed-disk configuration of an instance pool.
// DiskType is a union in which the volume type is set for exactly one cloud, so
// the AWS field is preferred and the Azure field used otherwise. A pool that
// attaches no managed disks reports zeroes and an empty type.
func poolDiskSpec(spec *compute.DiskSpec) (count int, size int, diskType string) {
	if spec == nil {
		return 0, 0, ""
	}
	if spec.DiskType != nil {
		if spec.DiskType.EbsVolumeType != "" {
			diskType = string(spec.DiskType.EbsVolumeType)
		} else {
			diskType = string(spec.DiskType.AzureDiskVolumeType)
		}
	}
	return spec.DiskCount, spec.DiskSize, diskType
}

// newMqlDatabricksInstancePool maps an instance pool to its resource. The
// cloud-specific attribute blocks are flattened onto the pool with a cloud
// prefix, as only the block matching the workspace's cloud is ever populated.
func newMqlDatabricksInstancePool(runtime *plugin.Runtime, p compute.InstancePoolAndStats) (*mqlDatabricksInstancePool, error) {
	var awsAvailability, awsZoneId, instanceProfileArn string
	var awsSpotBidPricePercent int
	if p.AwsAttributes != nil {
		awsAvailability = string(p.AwsAttributes.Availability)
		awsZoneId = p.AwsAttributes.ZoneId
		awsSpotBidPricePercent = p.AwsAttributes.SpotBidPricePercent
		instanceProfileArn = p.AwsAttributes.InstanceProfileArn
	}

	var azureAvailability string
	var azureSpotBidMaxPrice float64
	if p.AzureAttributes != nil {
		azureAvailability = string(p.AzureAttributes.Availability)
		azureSpotBidMaxPrice = p.AzureAttributes.SpotBidMaxPrice
	}

	var gcpAvailability, gcpZoneId string
	var gcpLocalSsdCount int
	if p.GcpAttributes != nil {
		gcpAvailability = string(p.GcpAttributes.GcpAvailability)
		gcpZoneId = p.GcpAttributes.ZoneId
		gcpLocalSsdCount = p.GcpAttributes.LocalSsdCount
	}

	diskCount, diskSize, diskType := poolDiskSpec(p.DiskSpec)

	imageUrls := make([]string, 0, len(p.PreloadedDockerImages))
	for i := range p.PreloadedDockerImages {
		// Registry credentials on the image are deliberately not exposed.
		imageUrls = append(imageUrls, p.PreloadedDockerImages[i].Url)
	}

	res, err := CreateResource(runtime, "databricks.instancePool", map[string]*llx.RawData{
		"__id":                               llx.StringData("databricks.instancePool/" + p.InstancePoolId),
		"id":                                 llx.StringData(p.InstancePoolId),
		"name":                               llx.StringData(p.InstancePoolName),
		"state":                              llx.StringData(string(p.State)),
		"nodeTypeId":                         llx.StringData(p.NodeTypeId),
		"minIdleInstances":                   llx.IntData(p.MinIdleInstances),
		"maxCapacity":                        llx.IntData(p.MaxCapacity),
		"idleInstanceAutoterminationMinutes": llx.IntData(p.IdleInstanceAutoterminationMinutes),
		"enableElasticDisk":                  llx.BoolData(p.EnableElasticDisk),
		"customTags":                         llx.MapData(strMap(p.CustomTags), types.String),
		"defaultTags":                        llx.MapData(strMap(p.DefaultTags), types.String),
		"preloadedSparkVersions":             llx.ArrayData(strSlice(p.PreloadedSparkVersions), types.String),
		"preloadedDockerImageUrls":           llx.ArrayData(strSlice(imageUrls), types.String),
		"awsAvailability":                    llx.StringData(awsAvailability),
		"awsZoneId":                          llx.StringData(awsZoneId),
		"awsSpotBidPricePercent":             llx.IntData(awsSpotBidPricePercent),
		"azureAvailability":                  llx.StringData(azureAvailability),
		"azureSpotBidMaxPrice":               llx.FloatData(azureSpotBidMaxPrice),
		"gcpAvailability":                    llx.StringData(gcpAvailability),
		"gcpZoneId":                          llx.StringData(gcpZoneId),
		"gcpLocalSsdCount":                   llx.IntData(gcpLocalSsdCount),
		"diskCount":                          llx.IntData(diskCount),
		"diskSize":                           llx.IntData(diskSize),
		"diskType":                           llx.StringData(diskType),
	})
	if err != nil {
		return nil, err
	}
	pool := res.(*mqlDatabricksInstancePool)
	pool.cacheInstanceProfileArn = instanceProfileArn
	return pool, nil
}

type mqlDatabricksInstancePoolInternal struct {
	cacheInstanceProfileArn string
}

func (r *mqlDatabricks) instancePools() ([]any, error) {
	pools, _, err := cachedInstancePools(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range pools {
		res, err := newMqlDatabricksInstancePool(r.MqlRuntime, pools[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksInstancePool) instanceProfile() (*mqlDatabricksInstanceProfile, error) {
	// Only AWS pools carry an instance profile, so a workspace on another cloud
	// never reaches the lookup below.
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

func (r *mqlDatabricksInstancePool) permissions() ([]any, error) {
	return mqlDatabricksPermissions(r.MqlRuntime, permissionObjectInstancePool, r.Id.Data)
}

func (r *mqlDatabricksCluster) instancePool() (*mqlDatabricksInstancePool, error) {
	if r.cacheInstancePoolId == "" {
		r.InstancePool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, byID, err := cachedInstancePools(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	p, ok := byID[r.cacheInstancePoolId]
	if !ok {
		r.InstancePool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksInstancePool(r.MqlRuntime, p)
}

// clusterCompliance is the policy comparison for one cluster, fetched once and
// shared by policyCompliant and policyViolations so reading both costs a single
// call.
type clusterCompliance struct {
	err        error
	compliant  bool
	violations map[string]any
}

func (r *mqlDatabricksCluster) compliance() (*clusterCompliance, error) {
	r.policyComplianceOnce.Do(func() {
		ws, err := workspaceClient(r.MqlRuntime)
		if err != nil {
			r.policyCompliance.err = err
			return
		}
		resp, err := ws.PolicyComplianceForClusters.GetComplianceByClusterId(context.Background(), r.Id.Data)
		if err != nil {
			r.policyCompliance.err = err
			return
		}
		r.policyCompliance.compliant = resp.IsCompliant
		r.policyCompliance.violations = make(map[string]any, len(resp.Violations))
		for k, v := range resp.Violations {
			r.policyCompliance.violations[k] = v
		}
	})
	return &r.policyCompliance, r.policyCompliance.err
}

func (r *mqlDatabricksCluster) policyCompliant() (bool, error) {
	// A cluster created against no policy has nothing to comply with, and the
	// compliance endpoint rejects it, so the answer is null rather than a pass.
	if r.cachePolicyId == "" {
		r.PolicyCompliant.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	c, err := r.compliance()
	if err != nil {
		return false, err
	}
	return c.compliant, nil
}

func (r *mqlDatabricksCluster) policyViolations() (map[string]any, error) {
	if r.cachePolicyId == "" {
		r.PolicyViolations.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	c, err := r.compliance()
	if err != nil {
		return nil, err
	}
	return c.violations, nil
}

// jobCompliance is the policy comparison for one job, fetched once and shared by
// policyCompliant and policyViolations.
type jobCompliance struct {
	err        error
	compliant  bool
	violations map[string]any
}

func (r *mqlDatabricksJob) compliance() (*jobCompliance, error) {
	r.policyComplianceOnce.Do(func() {
		ws, err := workspaceClient(r.MqlRuntime)
		if err != nil {
			r.policyCompliance.err = err
			return
		}
		resp, err := ws.PolicyComplianceForJobs.GetComplianceByJobId(context.Background(), r.Id.Data)
		if err != nil {
			r.policyCompliance.err = err
			return
		}
		r.policyCompliance.compliant = resp.IsCompliant
		r.policyCompliance.violations = make(map[string]any, len(resp.Violations))
		for k, v := range resp.Violations {
			r.policyCompliance.violations[k] = v
		}
	})
	return &r.policyCompliance, r.policyCompliance.err
}

func (r *mqlDatabricksJob) policyCompliant() (bool, error) {
	c, err := r.compliance()
	if err != nil {
		return false, err
	}
	return c.compliant, nil
}

func (r *mqlDatabricksJob) policyViolations() (map[string]any, error) {
	c, err := r.compliance()
	if err != nil {
		return nil, err
	}
	return c.violations, nil
}
