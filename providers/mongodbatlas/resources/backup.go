// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

type mqlMongodbatlasBackupScheduleConfigInternal struct {
	cacheExportBucketID string
}

type mqlMongodbatlasSnapshotExportBucketInternal struct {
	cacheRoleID string
}

// backupSchedule loads the cluster's snapshot schedule and retention policy.
// The endpoint only exists for clusters with cloud backup, so a known-disabled
// cluster skips the call and renders null, as it does when the endpoint reports
// no schedule or the credential lacks the backup role. The gate checks IsSet
// first: a cluster hydrated from complete args has never read backupEnabled,
// and treating that unset false as "disabled" would report no schedule for a
// cluster that has one.
func (r *mqlMongodbatlasCluster) backupSchedule() (*mqlMongodbatlasBackupScheduleConfig, error) {
	if r.BackupEnabled.IsSet() && !r.BackupEnabled.Data {
		r.BackupSchedule.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	schedule, httpResp, err := atlasClient(r.MqlRuntime).CloudBackupsAPI.
		GetBackupSchedule(context.Background(), pid, r.Name.Data).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.BackupSchedule.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	policyItems := []any{}
	for _, policy := range schedule.GetPolicies() {
		for _, item := range policy.GetPolicyItems() {
			policyItems = append(policyItems, map[string]any{
				"frequencyType":     item.GetFrequencyType(),
				"frequencyInterval": int64(item.GetFrequencyInterval()),
				"retentionUnit":     item.GetRetentionUnit(),
				"retentionValue":    int64(item.GetRetentionValue()),
			})
		}
	}

	copySettings := []any{}
	for _, cs := range schedule.GetCopySettings() {
		copySettings = append(copySettings, map[string]any{
			"cloudProvider":    cs.GetCloudProvider(),
			"regionName":       cs.GetRegionName(),
			"zoneId":           cs.GetZoneId(),
			"shouldCopyOplogs": cs.GetShouldCopyOplogs(),
			"frequencies":      strSlice(cs.GetFrequencies()),
		})
	}

	extraRetention := []any{}
	for _, ers := range schedule.GetExtraRetentionSettings() {
		extraRetention = append(extraRetention, map[string]any{
			"frequencyType": ers.GetFrequencyType(),
			"retentionDays": int64(ers.GetRetentionDays()),
		})
	}

	// The export policy is absent unless automatic export is configured, so both
	// the frequency and the destination bucket render null in that case.
	var exportFrequency, exportBucketID *string
	if export, ok := schedule.GetExportOk(); ok {
		exportFrequency = export.FrequencyType
		exportBucketID = export.ExportBucketId
	}

	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.backupScheduleConfig", map[string]*llx.RawData{
		"__id":                              llx.StringData("mongodbatlas.backupScheduleConfig/" + pid + "/" + r.Name.Data),
		"referenceHourOfDay":                llx.IntData(int64(schedule.GetReferenceHourOfDay())),
		"referenceMinuteOfHour":             llx.IntData(int64(schedule.GetReferenceMinuteOfHour())),
		"restoreWindowDays":                 llx.IntData(int64(schedule.GetRestoreWindowDays())),
		"nextSnapshot":                      llx.TimeDataPtr(timePtr(schedule.GetNextSnapshot())),
		"policyItems":                       llx.ArrayData(policyItems, types.Dict),
		"copySettings":                      llx.ArrayData(copySettings, types.Dict),
		"extraRetentionSettings":            llx.ArrayData(extraRetention, types.Dict),
		"autoExportEnabled":                 llx.BoolData(schedule.GetAutoExportEnabled()),
		"exportFrequencyType":               llx.StringDataPtr(exportFrequency),
		"useOrgAndGroupNamesInExportPrefix": llx.BoolData(schedule.GetUseOrgAndGroupNamesInExportPrefix()),
	})
	if err != nil {
		return nil, err
	}
	scheduleRes := res.(*mqlMongodbatlasBackupScheduleConfig)
	if exportBucketID != nil {
		scheduleRes.cacheExportBucketID = *exportBucketID
	}
	return scheduleRes, nil
}

// exportBucket resolves the bucket snapshots are automatically exported to.
// Null when automatic export is off.
func (r *mqlMongodbatlasBackupScheduleConfig) exportBucket() (*mqlMongodbatlasSnapshotExportBucket, error) {
	if r.cacheExportBucketID == "" {
		r.ExportBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := rootMongodbatlas(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	bucketsByID, err := root.projectExportBucketsByID()
	if err != nil {
		return nil, err
	}
	bucket, ok := bucketsByID[r.cacheExportBucketID]
	if !ok {
		r.ExportBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return bucket, nil
}

// projectExportBucketsByID lists the project's export buckets once and caches
// them by id on the root resource, so resolving an export destination is a map
// lookup rather than a get call per backup schedule.
func (r *mqlMongodbatlas) projectExportBucketsByID() (map[string]*mqlMongodbatlasSnapshotExportBucket, error) {
	r.exportBucketsOnce.Do(func() {
		buckets, err := r.snapshotExportBuckets()
		if err != nil {
			r.exportBucketsErr = err
			return
		}
		m := make(map[string]*mqlMongodbatlasSnapshotExportBucket, len(buckets))
		for _, b := range buckets {
			bucket := b.(*mqlMongodbatlasSnapshotExportBucket)
			m[bucket.Id.Data] = bucket
		}
		r.exportBucketsByID = m
	})
	return r.exportBucketsByID, r.exportBucketsErr
}

func (r *mqlMongodbatlas) snapshotExportBuckets() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, httpResp, err := client.CloudBackupsAPI.ListExportBuckets(ctx, pid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// An export bucket is a path for backup data to leave Atlas, so an
			// empty list is read as "no such path exists". A credential without
			// the backup role has not established that, and must not assert it;
			// render null instead of failing the whole query.
			if isAccessDenied(httpResp) {
				r.SnapshotExportBuckets.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasSnapshotExportBucket(r.MqlRuntime, pid, results[i])
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

func newMqlMongodbatlasSnapshotExportBucket(runtime *plugin.Runtime, pid string, b admin.DiskBackupSnapshotExportBucketResponse) (*mqlMongodbatlasSnapshotExportBucket, error) {
	res, err := CreateResource(runtime, "mongodbatlas.snapshotExportBucket", map[string]*llx.RawData{
		"__id":                     llx.StringData("mongodbatlas.snapshotExportBucket/" + pid + "/" + b.GetId()),
		"id":                       llx.StringData(b.GetId()),
		"bucketName":               llx.StringData(b.GetBucketName()),
		"cloudProvider":            llx.StringData(b.GetCloudProvider()),
		"region":                   llx.StringDataPtr(b.Region),
		"serviceUrl":               llx.StringDataPtr(b.ServiceUrl),
		"tenantId":                 llx.StringDataPtr(b.TenantId),
		"requirePrivateNetworking": llx.BoolData(b.GetRequirePrivateNetworking()),
	})
	if err != nil {
		return nil, err
	}
	bucket := res.(*mqlMongodbatlasSnapshotExportBucket)
	// AWS buckets carry the access role as iamRoleId, Azure as roleId; both name
	// the same cloud provider access role in the project.
	bucket.cacheRoleID = b.GetIamRoleId()
	if bucket.cacheRoleID == "" {
		bucket.cacheRoleID = b.GetRoleId()
	}
	return bucket, nil
}

// cloudProviderAccessRole resolves the role Atlas assumes to write snapshots to
// the bucket.
func (r *mqlMongodbatlasSnapshotExportBucket) cloudProviderAccessRole() (*mqlMongodbatlasCloudProviderAccessRole, error) {
	if r.cacheRoleID == "" {
		r.CloudProviderAccessRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := rootMongodbatlas(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	rolesByID, err := root.projectAccessRolesByID()
	if err != nil {
		return nil, err
	}
	role, ok := rolesByID[r.cacheRoleID]
	if !ok {
		r.CloudProviderAccessRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

// projectAccessRolesByID lists the project's cloud provider access roles once
// and caches them by id on the root resource. The listing is a single call that
// returns every provider, so resolving a bucket's role stays in memory.
func (r *mqlMongodbatlas) projectAccessRolesByID() (map[string]*mqlMongodbatlasCloudProviderAccessRole, error) {
	r.accessRolesOnce.Do(func() {
		roles, err := r.cloudProviderAccessRoles()
		if err != nil {
			r.accessRolesErr = err
			return
		}
		m := make(map[string]*mqlMongodbatlasCloudProviderAccessRole, len(roles))
		for _, role := range roles {
			accessRole := role.(*mqlMongodbatlasCloudProviderAccessRole)
			m[accessRole.Id.Data] = accessRole
		}
		r.accessRolesByID = m
	})
	return r.accessRolesByID, r.accessRolesErr
}
