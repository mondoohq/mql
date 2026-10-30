// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlMongodbatlasPushBasedLogConfigInternal struct {
	cacheProjectID string
	cacheRoleID    string
}

func (r *mqlMongodbatlas) pushBasedLogExport() (*mqlMongodbatlasPushBasedLogConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// GetLogExport is deprecated in favor of ListGroupLogIntegrations plus
	// GetGroupLogIntegration, which model a project as holding several named
	// integrations rather than one configuration. Adopting that would turn this
	// singleton resource into a list, a schema change this upgrade does not
	// carry; the deprecated call keeps reporting the same configuration.
	cfg, httpResp, err := atlasClient(r.MqlRuntime).PushBasedLogExportAPI.GetLogExport(context.Background(), pid).Execute()
	if err != nil {
		// Push-based log export is an optional feature that is not configured on
		// every project; degrade to null rather than failing the scan when it is
		// unavailable or the credential cannot read it.
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.PushBasedLogExport.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.pushBasedLogConfig", map[string]*llx.RawData{
		"__id":       llx.StringData("mongodbatlas.pushBasedLogConfig/" + pid),
		"bucketName": llx.StringData(cfg.GetBucketName()),
		"prefixPath": llx.StringData(cfg.GetPrefixPath()),
		"state":      llx.StringData(cfg.GetState()),
	})
	if err != nil {
		return nil, err
	}
	logCfg := res.(*mqlMongodbatlasPushBasedLogConfig)
	logCfg.cacheProjectID = pid
	logCfg.cacheRoleID = cfg.GetIamRoleId()
	return logCfg, nil
}

// cloudProviderAccessRole resolves the cloud provider access role Atlas assumes
// to write logs to the bucket. Null when no role is configured.
func (r *mqlMongodbatlasPushBasedLogConfig) cloudProviderAccessRole() (*mqlMongodbatlasCloudProviderAccessRole, error) {
	if r.cacheRoleID == "" {
		r.CloudProviderAccessRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := resolveCloudProviderAccessRole(r.MqlRuntime, r.cacheProjectID, r.cacheRoleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		r.CloudProviderAccessRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}
