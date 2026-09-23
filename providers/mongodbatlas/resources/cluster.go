// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// newMqlMongodbatlasCluster maps a cluster to its resource, shared by the
// clusters list and the by-name init used by typed references.
func newMqlMongodbatlasCluster(runtime *plugin.Runtime, pid string, c admin.ClusterDescription20240805) (*mqlMongodbatlasCluster, error) {
	tlsMin := ""
	tlsMode := ""
	if adv, ok := c.GetAdvancedConfigurationOk(); ok {
		tlsMin = adv.GetMinimumEnabledTlsProtocol()
		tlsMode = adv.GetTlsCipherConfigMode()
	}

	regionConfigs := []any{}
	for _, spec := range c.GetReplicationSpecs() {
		for _, rc := range spec.GetRegionConfigs() {
			entry := map[string]any{
				"providerName": rc.GetProviderName(),
				"regionName":   rc.GetRegionName(),
				"priority":     int64(rc.GetPriority()),
			}
			// A shared tier deployment reports providerName as TENANT and names
			// the cloud actually hosting it here, so without this the hosting
			// cloud of every shared cluster is unreadable.
			if backing := rc.GetBackingProviderName(); backing != "" {
				entry["backingProviderName"] = backing
			}
			if es, ok := rc.GetElectableSpecsOk(); ok {
				entry["instanceSize"] = es.GetInstanceSize()
				entry["nodeCount"] = int64(es.GetNodeCount())
				entry["diskSizeGB"] = es.GetDiskSizeGB()
			}
			regionConfigs = append(regionConfigs, entry)
		}
	}

	// Connection strings report how clients reach the cluster. A cluster served
	// only through a private endpoint has no standard SRV string, so these stay
	// nil rather than empty to keep "not reachable that way" distinct from "".
	var standardSrv, privateSrv *string
	privateEndpoints := []any{}
	if cs, ok := c.GetConnectionStringsOk(); ok {
		standardSrv = cs.StandardSrv
		privateSrv = cs.PrivateSrv
		for _, pe := range cs.GetPrivateEndpoint() {
			endpoints := []any{}
			for _, ep := range pe.GetEndpoints() {
				endpoints = append(endpoints, map[string]any{
					"endpointId":   ep.GetEndpointId(),
					"providerName": ep.GetProviderName(),
					"region":       ep.GetRegion(),
				})
			}
			privateEndpoints = append(privateEndpoints, map[string]any{
				"type":                pe.GetType(),
				"connectionString":    pe.GetConnectionString(),
				"srvConnectionString": pe.GetSrvConnectionString(),
				"endpoints":           endpoints,
			})
		}
	}

	// An employee access grant is absent unless MongoDB support currently holds
	// access, so both fields render null in the common case.
	var employeeGrantType *string
	var employeeGrantExpiration *time.Time
	if grant, ok := c.GetMongoDBEmployeeAccessGrantOk(); ok {
		employeeGrantType = &grant.GrantType
		employeeGrantExpiration = &grant.ExpirationTime
	}

	biConnectorEnabled := false
	var biConnectorReadPreference *string
	if bi, ok := c.GetBiConnectorOk(); ok {
		biConnectorEnabled = bi.GetEnabled()
		biConnectorReadPreference = bi.ReadPreference
	}

	res, err := CreateResource(runtime, "mongodbatlas.cluster", map[string]*llx.RawData{
		"__id":                             llx.StringData("mongodbatlas.cluster/" + pid + "/" + c.GetName()),
		"id":                               llx.StringData(c.GetId()),
		"name":                             llx.StringData(c.GetName()),
		"mongoDBMajorVersion":              llx.StringData(c.GetMongoDBMajorVersion()),
		"mongoDBVersion":                   llx.StringData(c.GetMongoDBVersion()),
		"clusterType":                      llx.StringData(c.GetClusterType()),
		"stateName":                        llx.StringData(c.GetStateName()),
		"backupEnabled":                    llx.BoolData(c.GetBackupEnabled()),
		"retainBackups":                    llx.BoolData(c.GetRetainBackups()),
		"pitEnabled":                       llx.BoolData(c.GetPitEnabled()),
		"encryptionAtRestProvider":         llx.StringData(c.GetEncryptionAtRestProvider()),
		"minimumEnabledTlsProtocol":        llx.StringData(tlsMin),
		"tlsCipherConfigMode":              llx.StringData(tlsMode),
		"redactClientLogData":              llx.BoolData(c.GetRedactClientLogData()),
		"terminationProtectionEnabled":     llx.BoolData(c.GetTerminationProtectionEnabled()),
		"paused":                           llx.BoolData(c.GetPaused()),
		"versionReleaseSystem":             llx.StringData(c.GetVersionReleaseSystem()),
		"rootCertType":                     llx.StringData(c.GetRootCertType()),
		"createDate":                       llx.TimeDataPtr(timePtr(c.GetCreateDate())),
		"regionConfigs":                    llx.ArrayData(regionConfigs, types.Dict),
		"tags":                             llx.MapData(tagMap(c.GetTags()), types.String),
		"standardSrvConnectionString":      llx.StringDataPtr(standardSrv),
		"privateSrvConnectionString":       llx.StringDataPtr(privateSrv),
		"privateEndpointConnectionStrings": llx.ArrayData(privateEndpoints, types.Dict),
		"employeeAccessGrantType":          llx.StringDataPtr(employeeGrantType),
		"employeeAccessGrantExpiration":    llx.TimeDataPtr(employeeGrantExpiration),
		"featureCompatibilityVersion":      llx.StringDataPtr(c.FeatureCompatibilityVersion),
		"featureCompatibilityVersionExpirationDate": llx.TimeDataPtr(c.FeatureCompatibilityVersionExpirationDate),
		"biConnectorEnabled":                        llx.BoolData(biConnectorEnabled),
		"biConnectorReadPreference":                 llx.StringDataPtr(biConnectorReadPreference),
		"configServerManagementMode":                llx.StringDataPtr(c.ConfigServerManagementMode),
		"configServerType":                          llx.StringDataPtr(c.ConfigServerType),
		"replicaSetScalingStrategy":                 llx.StringDataPtr(c.ReplicaSetScalingStrategy),
		"diskWarmingMode":                           llx.StringDataPtr(c.DiskWarmingMode),
		"globalClusterSelfManagedSharding":          llx.BoolData(c.GetGlobalClusterSelfManagedSharding()),
	})
	if err != nil {
		return nil, err
	}
	cluster := res.(*mqlMongodbatlasCluster)
	cluster.cacheProjectID = pid
	return cluster, nil
}

// initMongodbatlasCluster resolves a single cluster by name within the connected
// project so typed references (such as a database user's scoped clusters) can
// hydrate a full cluster from its name.
func initMongodbatlasCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("mongodbatlas.cluster requires a non-empty name")
	}
	pid, err := projectID(runtime)
	if err != nil {
		return nil, nil, err
	}
	c, _, err := atlasClient(runtime).ClustersAPI.GetCluster(context.Background(), pid, name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlMongodbatlasCluster(runtime, pid, *c)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// projectClustersByName lists the project's clusters once and caches them by
// name on the root resource, so scoped-cluster resolution for database users is
// a map lookup rather than a GetCluster call per scope entry.
func (r *mqlMongodbatlas) projectClustersByName() (map[string]*mqlMongodbatlasCluster, error) {
	r.clustersOnce.Do(func() {
		clusters, err := r.clusters()
		if err != nil {
			r.clustersErr = err
			return
		}
		m := make(map[string]*mqlMongodbatlasCluster, len(clusters))
		for _, c := range clusters {
			cl := c.(*mqlMongodbatlasCluster)
			m[cl.Name.Data] = cl
		}
		r.clustersByName = m
	})
	return r.clustersByName, r.clustersErr
}

func (r *mqlMongodbatlas) clusters() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.ClustersAPI.ListClusters(ctx, pid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasCluster(r.MqlRuntime, pid, results[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}
