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

// mqlMongodbatlasClusterInternal carries the project the cluster was listed
// under, which the per-cluster endpoints (process arguments, online archives)
// need and the cluster record itself does not report.
type mqlMongodbatlasClusterInternal struct {
	cacheProjectID string
}

// advancedConfiguration reads the cluster's process arguments. The
// advancedConfiguration embedded in the cluster listing is a four-field TLS
// summary; this endpoint is the one that reports whether server-side JavaScript
// runs, whether collection scans are refused, and how long the oplog is kept.
func (r *mqlMongodbatlasCluster) advancedConfiguration() (*mqlMongodbatlasClusterAdvancedConfig, error) {
	pid := r.cacheProjectID
	name := r.Name.Data
	if pid == "" || name == "" {
		r.AdvancedConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	adv, httpResp, err := atlasClient(r.MqlRuntime).ClustersAPI.
		GetProcessArgs(context.Background(), pid, name).Execute()
	if err != nil {
		// A deployment without process arguments (a shared tier cluster, or one
		// still being created) answers 404, and a credential without project
		// read answers 401/403. Both leave the configuration unknown, which is
		// null rather than a set of fabricated defaults.
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.AdvancedConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.clusterAdvancedConfig", map[string]*llx.RawData{
		"__id":                            llx.StringData("mongodbatlas.clusterAdvancedConfig/" + pid + "/" + name),
		"javascriptEnabled":               llx.BoolDataPtr(adv.JavascriptEnabled),
		"noTableScan":                     llx.BoolDataPtr(adv.NoTableScan),
		"minimumEnabledTlsProtocol":       llx.StringDataPtr(adv.MinimumEnabledTlsProtocol),
		"tlsCipherConfigMode":             llx.StringDataPtr(adv.TlsCipherConfigMode),
		"customOpensslCipherConfigTls12":  llx.ArrayData(strSlice(adv.GetCustomOpensslCipherConfigTls12()), types.String),
		"customOpensslCipherConfigTls13":  llx.ArrayData(strSlice(adv.GetCustomOpensslCipherConfigTls13()), types.String),
		"defaultWriteConcern":             llx.StringDataPtr(adv.DefaultWriteConcern),
		"defaultMaxTimeMS":                llx.IntDataPtr(adv.DefaultMaxTimeMS),
		"oplogMinRetentionHours":          llx.FloatDataPtr(adv.OplogMinRetentionHours),
		"oplogSizeMB":                     llx.IntDataPtr(adv.OplogSizeMB),
		"queryStatsLogVerbosity":          llx.IntDataPtr(adv.QueryStatsLogVerbosity),
		"transactionLifetimeLimitSeconds": llx.IntDataPtr(adv.TransactionLifetimeLimitSeconds),
		"changeStreamOptionsPreAndPostImagesExpireAfterSeconds": llx.IntDataPtr(adv.ChangeStreamOptionsPreAndPostImagesExpireAfterSeconds),
		"chunkMigrationConcurrency":                             llx.IntDataPtr(adv.ChunkMigrationConcurrency),
		"sampleSizeBIConnector":                                 llx.IntDataPtr(adv.SampleSizeBIConnector),
		"sampleRefreshIntervalBIConnector":                      llx.IntDataPtr(adv.SampleRefreshIntervalBIConnector),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasClusterAdvancedConfig), nil
}

// onlineArchives lists the archiving rules on the cluster. Archived documents
// leave the cluster for a separately governed store, so an archive is data that
// the cluster's own backup and encryption settings stop describing.
func (r *mqlMongodbatlasCluster) onlineArchives() ([]any, error) {
	pid := r.cacheProjectID
	name := r.Name.Data
	if pid == "" || name == "" {
		r.OnlineArchives.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err := forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.OnlineArchiveAPI.
			ListOnlineArchives(ctx, pid, name).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// A cluster tier that cannot hold an online archive answers 404,
			// and a denied read answers 401/403. Neither establishes that the
			// cluster archives nothing, so the field is null.
			if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
				r.OnlineArchives.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasOnlineArchive(r.MqlRuntime, pid, name, results[i])
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func newMqlMongodbatlasOnlineArchive(runtime *plugin.Runtime, pid, clusterName string, a admin.BackupOnlineArchive) (*mqlMongodbatlasOnlineArchive, error) {
	var criteriaType, criteriaDateField, criteriaQuery *string
	var criteriaExpireAfterDays *int
	if c, ok := a.GetCriteriaOk(); ok {
		criteriaType = c.Type
		criteriaDateField = c.DateField
		criteriaQuery = c.Query
		criteriaExpireAfterDays = c.ExpireAfterDays
	}

	// The archive-level expiry is a separate rule from the DATE criteria's own
	// age threshold: the criteria decides what is archived, this decides when
	// the archived copy is destroyed.
	var expireAfterDays *int
	if rule, ok := a.GetDataExpirationRuleOk(); ok {
		expireAfterDays = rule.ExpireAfterDays
	}

	var processProvider, processRegion *string
	if dpr, ok := a.GetDataProcessRegionOk(); ok {
		processProvider = dpr.CloudProvider
		processRegion = dpr.Region
	}

	var scheduleType *string
	if s, ok := a.GetScheduleOk(); ok {
		scheduleType = &s.Type
	}

	partitionFields := []any{}
	for _, pf := range a.GetPartitionFields() {
		partitionFields = append(partitionFields, map[string]any{
			"fieldName": pf.GetFieldName(),
			"fieldType": pf.GetFieldType(),
			"order":     int64(pf.GetOrder()),
		})
	}

	res, err := CreateResource(runtime, "mongodbatlas.onlineArchive", map[string]*llx.RawData{
		// An archive id is unique within its project, and a cluster name is
		// unique within one too, so both dimensions are carried: the same
		// archive id can otherwise be met again under another project when an
		// organization-wide scan walks several.
		"__id":                     llx.StringData("mongodbatlas.onlineArchive/" + pid + "/" + clusterName + "/" + a.GetId()),
		"id":                       llx.StringData(a.GetId()),
		"databaseName":             llx.StringDataPtr(a.DbName),
		"collectionName":           llx.StringDataPtr(a.CollName),
		"collectionType":           llx.StringDataPtr(a.CollectionType),
		"state":                    llx.StringDataPtr(a.State),
		"paused":                   llx.BoolDataPtr(a.Paused),
		"dataSetName":              llx.StringDataPtr(a.DataSetName),
		"criteriaType":             llx.StringDataPtr(criteriaType),
		"criteriaDateField":        llx.StringDataPtr(criteriaDateField),
		"criteriaExpireAfterDays":  llx.IntDataPtr(criteriaExpireAfterDays),
		"criteriaQuery":            llx.StringDataPtr(criteriaQuery),
		"expireAfterDays":          llx.IntDataPtr(expireAfterDays),
		"dataProcessCloudProvider": llx.StringDataPtr(processProvider),
		"dataProcessRegion":        llx.StringDataPtr(processRegion),
		"scheduleType":             llx.StringDataPtr(scheduleType),
		"partitionFields":          llx.ArrayData(partitionFields, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasOnlineArchive), nil
}
