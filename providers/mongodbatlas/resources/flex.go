// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// flexClusters lists the project's Flex tier deployments. Flex has its own
// endpoint: the clusters listing covers dedicated and shared tier deployments
// only, so a project running Flex is empty there and would otherwise go
// unexamined.
func (r *mqlMongodbatlas) flexClusters() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, httpResp, err := client.FlexClustersAPI.ListFlexClusters(ctx, pid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// Flex deployments are invisible in the clusters listing, so this
			// call is the only thing that reports them. A credential that may
			// not read it has established nothing, and an empty list would put
			// the project back to looking Flex-free, which is the exact blind
			// spot this accessor exists to close. Render null instead.
			if isAccessDenied(httpResp) {
				r.FlexClusters.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			c := results[i]

			backupEnabled := false
			if backup, ok := c.GetBackupSettingsOk(); ok {
				backupEnabled = backup.GetEnabled()
			}

			provider := c.GetProviderSettings()

			var standardSrv *string
			if cs, ok := c.GetConnectionStringsOk(); ok {
				standardSrv = cs.StandardSrv
			}

			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.flexCluster", map[string]*llx.RawData{
				"__id":                         llx.StringData("mongodbatlas.flexCluster/" + pid + "/" + c.GetName()),
				"id":                           llx.StringData(c.GetId()),
				"name":                         llx.StringData(c.GetName()),
				"clusterType":                  llx.StringData(c.GetClusterType()),
				"stateName":                    llx.StringData(c.GetStateName()),
				"mongoDBVersion":               llx.StringData(c.GetMongoDBVersion()),
				"versionReleaseSystem":         llx.StringData(c.GetVersionReleaseSystem()),
				"providerName":                 llx.StringData(provider.GetProviderName()),
				"backingProviderName":          llx.StringData(provider.GetBackingProviderName()),
				"regionName":                   llx.StringData(provider.GetRegionName()),
				"diskSizeGB":                   llx.FloatData(provider.GetDiskSizeGB()),
				"backupEnabled":                llx.BoolData(backupEnabled),
				"terminationProtectionEnabled": llx.BoolData(c.GetTerminationProtectionEnabled()),
				"standardSrvConnectionString":  llx.StringDataPtr(standardSrv),
				"tags":                         llx.MapData(tagMap(c.GetTags()), types.String),
				"createDate":                   llx.TimeDataPtr(timePtr(c.GetCreateDate())),
			})
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
