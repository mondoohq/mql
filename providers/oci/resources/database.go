// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciDatabase) id() (string, error) {
	return "oci.database", nil
}

// DB Systems

func (o *mqlOciDatabase) dbSystems() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci DB systems with region %s", region)

			svc, err := conn.DatabaseClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]database.DbSystemSummary, *string, error) {
				response, err := svc.ListDbSystems(ctx, database.ListDbSystemsRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range items {
				s := items[i]

				var created *time.Time
				if s.TimeCreated != nil {
					created = &s.TimeCreated.Time
				}

				var storageManagement string
				if s.DbSystemOptions != nil {
					storageManagement = string(s.DbSystemOptions.StorageManagement)
				}

				// A DB system that has never had data collection configured
				// carries no DataCollectionOptions at all. Reporting false in
				// that case is correct: nothing is being collected.
				var isDiagnosticsEventsEnabled, isHealthMonitoringEnabled, isIncidentLogsEnabled bool
				if d := s.DataCollectionOptions; d != nil {
					isDiagnosticsEventsEnabled = boolValue(d.IsDiagnosticsEventsEnabled)
					isHealthMonitoringEnabled = boolValue(d.IsHealthMonitoringEnabled)
					isIncidentLogsEnabled = boolValue(d.IsIncidentLogsEnabled)
				}

				maintenanceWindow, err := convert.JsonToDict(s.MaintenanceWindow)
				if err != nil {
					return nil, err
				}
				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.database.dbSystem", stringValue(s.CompartmentId), map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(s.Id),
					"name":                 llx.StringDataPtr(s.DisplayName),
					"availabilityDomain":   llx.StringDataPtr(s.AvailabilityDomain),
					"shape":                llx.StringDataPtr(s.Shape),
					"databaseEdition":      llx.StringData(string(s.DatabaseEdition)),
					"diskRedundancy":       llx.StringData(string(s.DiskRedundancy)),
					"hostname":             llx.StringDataPtr(s.Hostname),
					"domain":               llx.StringDataPtr(s.Domain),
					"listenerPort":         llx.IntData(intValue(s.ListenerPort)),
					"scanDnsName":          llx.StringDataPtr(s.ScanDnsName),
					"version":              llx.StringDataPtr(s.Version),
					"cpuCoreCount":         llx.IntData(intValue(s.CpuCoreCount)),
					"nodeCount":            llx.IntData(intValue(s.NodeCount)),
					"dataStorageSizeInGBs": llx.IntData(intValue(s.DataStorageSizeInGBs)),
					"licenseModel":         llx.StringData(string(s.LicenseModel)),
					"state":                llx.StringData(string(s.LifecycleState)),
					"created":              llx.TimeDataPtr(created),
					"freeformTags":         llx.MapData(strMapToAny(s.FreeformTags), types.String),
					"definedTags":          llx.MapData(definedTagsToAny(s.DefinedTags), types.Any),
					"systemTags":           llx.MapData(definedTagsToAny(s.SystemTags), types.Dict),

					"sshPublicKeys":              llx.ArrayData(convert.SliceAnyToInterface(s.SshPublicKeys), types.String),
					"faultDomains":               llx.ArrayData(convert.SliceAnyToInterface(s.FaultDomains), types.String),
					"osVersion":                  llx.StringDataPtr(s.OsVersion),
					"timeZone":                   llx.StringDataPtr(s.TimeZone),
					"clusterName":                llx.StringDataPtr(s.ClusterName),
					"storageManagement":          llx.StringData(storageManagement),
					"isDiagnosticsEventsEnabled": llx.BoolData(isDiagnosticsEventsEnabled),
					"isHealthMonitoringEnabled":  llx.BoolData(isHealthMonitoringEnabled),
					"isIncidentLogsEnabled":      llx.BoolData(isIncidentLogsEnabled),
					"securityAttributes":         llx.MapData(definedTagsToAny(s.SecurityAttributes), types.Dict),
					"maintenanceWindow":          llx.DictData(maintenanceWindow),
					"lifecycleDetails":           llx.StringDataPtr(s.LifecycleDetails),
				})
				if err != nil {
					return nil, err
				}
				mqlDb := mqlInstance.(*mqlOciDatabaseDbSystem)
				mqlDb.cacheNsgIDs = convert.SliceAnyToInterface(s.NsgIds)
				mqlDb.cacheBackupNetworkNsgIDs = convert.SliceAnyToInterface(s.BackupNetworkNsgIds)
				mqlDb.cacheKmsKeyID = stringValue(s.KmsKeyId)
				mqlDb.cacheSubnetID = stringValue(s.SubnetId)
				mqlDb.cacheSourceDbSystemID = stringValue(s.SourceDbSystemId)
				mqlDb.cacheBackupSubnetID = stringValue(s.BackupSubnetId)
				mqlDb.cacheMaintenanceWindow = s.MaintenanceWindow
				res = append(res, mqlDb)
			}

			return res, nil
		})
}

// ociMaintenanceWindowArgs maps a DB system's maintenance window onto the
// fields of oci.database.maintenanceWindow, and reports nil for a system that
// has never had one configured. Nil rather than a row of zeroes: a window
// scheduled for no months on no days would read as a real schedule, and
// "patched on a rolling basis with no lead time" is a claim about a system
// nobody has configured.
func ociMaintenanceWindowArgs(w *database.MaintenanceWindow) map[string]*llx.RawData {
	if w == nil {
		return nil
	}

	months := make([]any, 0, len(w.Months))
	for _, m := range w.Months {
		months = append(months, string(m.Name))
	}
	daysOfWeek := make([]any, 0, len(w.DaysOfWeek))
	for _, d := range w.DaysOfWeek {
		daysOfWeek = append(daysOfWeek, string(d.Name))
	}
	weeksOfMonth := make([]any, 0, len(w.WeeksOfMonth))
	for _, v := range w.WeeksOfMonth {
		weeksOfMonth = append(weeksOfMonth, int64(v))
	}
	hoursOfDay := make([]any, 0, len(w.HoursOfDay))
	for _, v := range w.HoursOfDay {
		hoursOfDay = append(hoursOfDay, int64(v))
	}
	skipRu := make([]any, 0, len(w.SkipRu))
	for _, v := range w.SkipRu {
		skipRu = append(skipRu, v)
	}

	return map[string]*llx.RawData{
		"preference":                   llx.StringData(string(w.Preference)),
		"patchingMode":                 llx.StringData(string(w.PatchingMode)),
		"isCustomActionTimeoutEnabled": llx.BoolDataPtr(w.IsCustomActionTimeoutEnabled),
		"customActionTimeoutInMins":    llx.IntDataPtr(intPtrToInt64(w.CustomActionTimeoutInMins)),
		"isMonthlyPatchingEnabled":     llx.BoolDataPtr(w.IsMonthlyPatchingEnabled),
		"months":                       llx.ArrayData(months, types.String),
		"weeksOfMonth":                 llx.ArrayData(weeksOfMonth, types.Int),
		"daysOfWeek":                   llx.ArrayData(daysOfWeek, types.String),
		"hoursOfDay":                   llx.ArrayData(hoursOfDay, types.Int),
		"leadTimeInWeeks":              llx.IntDataPtr(intPtrToInt64(w.LeadTimeInWeeks)),
		"skipRu":                       llx.ArrayData(skipRu, types.Bool),
	}
}

type mqlOciDatabaseDbSystemInternal struct {
	ociCompartmentRef
	cacheNsgIDs              []any
	cacheBackupNetworkNsgIDs []any
	cacheKmsKeyID            string
	cacheSubnetID            string
	cacheSourceDbSystemID    string
	cacheBackupSubnetID      string
	cacheMaintenanceWindow   *database.MaintenanceWindow
}

// maintenanceSchedule builds the window Oracle may patch the system in.
//
// Null when the system has no window configured at all, which is a different
// fact from a window that schedules no months and no days.
func (o *mqlOciDatabaseDbSystem) maintenanceSchedule() (*mqlOciDatabaseMaintenanceWindow, error) {
	args := ociMaintenanceWindowArgs(o.cacheMaintenanceWindow)
	if args == nil {
		o.MaintenanceSchedule.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	args["__id"] = llx.StringData(o.Id.Data + "/maintenanceWindow")

	res, err := CreateResource(o.MqlRuntime, "oci.database.maintenanceWindow", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciDatabaseMaintenanceWindow), nil
}

func (o *mqlOciDatabaseDbSystem) backupSubnet() (*mqlOciNetworkSubnet, error) {
	return resolveOciSubnet(o.MqlRuntime, o.cacheBackupSubnetID, &o.BackupSubnet)
}

func (o *mqlOciDatabaseDbSystem) id() (string, error) {
	return "oci.database.dbSystem/" + o.Id.Data, nil
}

func (o *mqlOciDatabaseDbSystem) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" || !isOcid(o.cacheKmsKeyID) {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsKey), nil
}

func (o *mqlOciDatabaseDbSystem) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" || !isOcid(o.cacheSubnetID) {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciNetworkSubnet), nil
}

// Autonomous Databases

func (o *mqlOciDatabase) autonomousDatabases() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci autonomous databases with region %s", region)

			svc, err := conn.DatabaseClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]database.AutonomousDatabaseSummary, *string, error) {
				response, err := svc.ListAutonomousDatabases(ctx, database.ListAutonomousDatabasesRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range items {
				a := items[i]

				var created *time.Time
				if a.TimeCreated != nil {
					created = &a.TimeCreated.Time
				}

				var connectionUrls map[string]any
				if a.ConnectionUrls != nil {
					connectionUrls, err = convert.JsonToDict(a.ConnectionUrls)
					if err != nil {
						return nil, err
					}
				}

				var publicConnectionUrls map[string]any
				if a.PublicConnectionUrls != nil {
					publicConnectionUrls, err = convert.JsonToDict(a.PublicConnectionUrls)
					if err != nil {
						return nil, err
					}
				}

				ltb := longTermBackupArgs(a.LongTermBackupSchedule, a.NextLongTermBackupTimeStamp)
				smw := scheduledMaintenanceWindowArgs(a.ScheduledMaintenanceWindow, a.TimeScheduledMaintenanceWindowUpdate)

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.database.autonomousDatabase", stringValue(a.CompartmentId), map[string]*llx.RawData{
					"id":                                   llx.StringDataPtr(a.Id),
					"name":                                 llx.StringDataPtr(a.DisplayName),
					"dbName":                               llx.StringDataPtr(a.DbName),
					"isRefreshableClone":                   llx.BoolDataPtr(a.IsRefreshableClone),
					"dbVersion":                            llx.StringDataPtr(a.DbVersion),
					"dbWorkload":                           llx.StringData(string(a.DbWorkload)),
					"isDedicated":                          llx.BoolDataPtr(a.IsDedicated),
					"isFreeTier":                           llx.BoolDataPtr(a.IsFreeTier),
					"cpuCoreCount":                         llx.IntData(intValue(a.CpuCoreCount)),
					"dataStorageSizeInTBs":                 llx.IntData(intValue(a.DataStorageSizeInTBs)),
					"isMtlsConnectionRequired":             llx.BoolDataPtr(a.IsMtlsConnectionRequired),
					"isAccessControlEnabled":               llx.BoolDataPtr(a.IsAccessControlEnabled),
					"whitelistedIps":                       llx.ArrayData(convert.SliceAnyToInterface(a.WhitelistedIps), types.String),
					"standbyWhitelistedIps":                llx.ArrayData(convert.SliceAnyToInterface(a.StandbyWhitelistedIps), types.String),
					"isAutoScalingEnabled":                 llx.BoolDataPtr(a.IsAutoScalingEnabled),
					"isLocalDataGuardEnabled":              llx.BoolDataPtr(a.IsLocalDataGuardEnabled),
					"isRemoteDataGuardEnabled":             llx.BoolDataPtr(a.IsRemoteDataGuardEnabled),
					"isDataGuardEnabled":                   llx.BoolDataPtr(a.IsDataGuardEnabled),
					"backupRetentionPeriodInDays":          llx.IntData(intValue(a.BackupRetentionPeriodInDays)),
					"isBackupRetentionLocked":              llx.BoolDataPtr(a.IsBackupRetentionLocked),
					"longTermBackupRepeatCadence":          ltb["longTermBackupRepeatCadence"],
					"longTermBackupTimeOfBackup":           ltb["longTermBackupTimeOfBackup"],
					"longTermBackupRetentionPeriodInDays":  ltb["longTermBackupRetentionPeriodInDays"],
					"longTermBackupScheduleDisabled":       ltb["longTermBackupScheduleDisabled"],
					"nextLongTermBackupTimestamp":          ltb["nextLongTermBackupTimestamp"],
					"maintenanceDayOfWeek":                 smw["maintenanceDayOfWeek"],
					"maintenanceStartTime":                 smw["maintenanceStartTime"],
					"maintenanceEndTime":                   smw["maintenanceEndTime"],
					"maintenanceAvailabilityDomain":        smw["maintenanceAvailabilityDomain"],
					"maintenanceWindowChangeScheduled":     smw["maintenanceWindowChangeScheduled"],
					"timeScheduledMaintenanceWindowUpdate": smw["timeScheduledMaintenanceWindowUpdate"],
					"dataSafeStatus":                       llx.StringData(string(a.DataSafeStatus)),
					"openMode":                             llx.StringData(string(a.OpenMode)),
					"permissionLevel":                      llx.StringData(string(a.PermissionLevel)),
					"licenseModel":                         llx.StringData(string(a.LicenseModel)),
					"privateEndpointIp":                    llx.StringDataPtr(a.PrivateEndpointIp),
					"privateEndpointLabel":                 llx.StringDataPtr(a.PrivateEndpointLabel),
					"connectionUrls":                       llx.DictData(connectionUrls),
					"publicConnectionUrls":                 llx.DictData(publicConnectionUrls),
					"state":                                llx.StringData(string(a.LifecycleState)),
					"created":                              llx.TimeDataPtr(created),
					"freeformTags":                         llx.MapData(strMapToAny(a.FreeformTags), types.String),
					"definedTags":                          llx.MapData(definedTagsToAny(a.DefinedTags), types.Any),
					"systemTags":                           llx.MapData(definedTagsToAny(a.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlAdb := mqlInstance.(*mqlOciDatabaseAutonomousDatabase)
				mqlAdb.cacheNsgIDs = convert.SliceAnyToInterface(a.NsgIds)
				mqlAdb.cacheKmsKeyID = stringValue(a.KmsKeyId)
				mqlAdb.cacheVaultID = stringValue(a.VaultId)
				mqlAdb.cacheSubnetID = stringValue(a.SubnetId)
				mqlAdb.cacheSourceID = stringValue(a.SourceId)
				mqlAdb.cacheConnectionUrls = a.ConnectionUrls
				mqlAdb.cachePublicConnectionUrls = a.PublicConnectionUrls
				res = append(res, mqlAdb)
			}

			return res, nil
		})
}

type mqlOciDatabaseAutonomousDatabaseInternal struct {
	ociCompartmentRef
	cacheNsgIDs               []any
	cacheKmsKeyID             string
	cacheVaultID              string
	cacheSubnetID             string
	cacheSourceID             string
	cacheConnectionUrls       *database.AutonomousDatabaseConnectionUrls
	cachePublicConnectionUrls *database.AutonomousDatabaseConnectionUrls
}

// newOciAutonomousDatabaseConsoleUrls builds one console-URL resource. The
// endpoint name is part of the cache key because a database publishes the same
// consoles twice, once privately and once on its public endpoint, and the two
// sets are different answers to the same audit.
func newOciAutonomousDatabaseConsoleUrls(runtime *plugin.Runtime, dbID, endpoint string, urls *database.AutonomousDatabaseConnectionUrls) (*mqlOciDatabaseAutonomousDatabaseConsoleUrls, error) {
	res, err := CreateResource(runtime, "oci.database.autonomousDatabase.consoleUrls", map[string]*llx.RawData{
		"__id":                             llx.StringData(dbID + "/" + endpoint),
		"sqlDevWebUrl":                     llx.StringDataPtr(urls.SqlDevWebUrl),
		"apexUrl":                          llx.StringDataPtr(urls.ApexUrl),
		"machineLearningUserManagementUrl": llx.StringDataPtr(urls.MachineLearningUserManagementUrl),
		"graphStudioUrl":                   llx.StringDataPtr(urls.GraphStudioUrl),
		"mongoDbUrl":                       llx.StringDataPtr(urls.MongoDbUrl),
		"machineLearningNotebookUrl":       llx.StringDataPtr(urls.MachineLearningNotebookUrl),
		"ordsUrl":                          llx.StringDataPtr(urls.OrdsUrl),
		"databaseTransformsUrl":            llx.StringDataPtr(urls.DatabaseTransformsUrl),
		"spatialStudioUrl":                 llx.StringDataPtr(urls.SpatialStudioUrl),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciDatabaseAutonomousDatabaseConsoleUrls), nil
}

func (o *mqlOciDatabaseAutonomousDatabase) managementUrls() (*mqlOciDatabaseAutonomousDatabaseConsoleUrls, error) {
	if o.cacheConnectionUrls == nil {
		o.ManagementUrls.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newOciAutonomousDatabaseConsoleUrls(o.MqlRuntime, o.Id.Data, "consoleUrls", o.cacheConnectionUrls)
}

func (o *mqlOciDatabaseAutonomousDatabase) publicManagementUrls() (*mqlOciDatabaseAutonomousDatabaseConsoleUrls, error) {
	if o.cachePublicConnectionUrls == nil {
		o.PublicManagementUrls.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newOciAutonomousDatabaseConsoleUrls(o.MqlRuntime, o.Id.Data, "publicConsoleUrls", o.cachePublicConnectionUrls)
}

func (o *mqlOciDatabaseAutonomousDatabase) id() (string, error) {
	return "oci.database.autonomousDatabase/" + o.Id.Data, nil
}

func (o *mqlOciDatabaseAutonomousDatabase) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" || !isOcid(o.cacheKmsKeyID) {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsKey), nil
}

func (o *mqlOciDatabaseAutonomousDatabase) kmsVault() (*mqlOciKmsVault, error) {
	if o.cacheVaultID == "" || !isOcid(o.cacheVaultID) {
		o.KmsVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.vault", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVaultID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsVault), nil
}

func (o *mqlOciDatabaseAutonomousDatabase) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" || !isOcid(o.cacheSubnetID) {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciNetworkSubnet), nil
}

// Database backups (VM/BM)

func (o *mqlOciDatabase) backups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci database backups with region %s", region)

			svc, err := conn.DatabaseClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]database.BackupSummary, *string, error) {
				response, err := svc.ListBackups(ctx, database.ListBackupsRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range items {
				mqlBackup, err := newOciDatabaseBackup(o.MqlRuntime, items[i])
				if err != nil {
					return nil, err
				}
				res = append(res, mqlBackup)
			}

			return res, nil
		})
}

// newOciDatabaseBackup creates the resource for a backup summary. Both the
// service-wide backup list and a database's own backups build it, so the two
// paths share one cache entry per backup.
func newOciDatabaseBackup(runtime *plugin.Runtime, b database.BackupSummary) (*mqlOciDatabaseBackup, error) {
	var started, ended, expiry *time.Time
	if b.TimeStarted != nil {
		started = &b.TimeStarted.Time
	}
	if b.TimeEnded != nil {
		ended = &b.TimeEnded.Time
	}
	if b.TimeExpiryScheduled != nil {
		expiry = &b.TimeExpiryScheduled.Time
	}

	var sizeGBs float64
	if b.DatabaseSizeInGBs != nil {
		sizeGBs = *b.DatabaseSizeInGBs
	}

	mqlInstance, err := createOciResourceInCompartment(runtime, "oci.database.backup", stringValue(b.CompartmentId), map[string]*llx.RawData{
		"id":                       llx.StringDataPtr(b.Id),
		"name":                     llx.StringDataPtr(b.DisplayName),
		"databaseId":               llx.StringDataPtr(b.DatabaseId),
		"availabilityDomain":       llx.StringDataPtr(b.AvailabilityDomain),
		"type":                     llx.StringData(string(b.Type)),
		"backupDestinationType":    llx.StringData(string(b.BackupDestinationType)),
		"databaseSizeInGBs":        llx.FloatData(sizeGBs),
		"databaseEdition":          llx.StringData(string(b.DatabaseEdition)),
		"version":                  llx.StringDataPtr(b.Version),
		"shape":                    llx.StringDataPtr(b.Shape),
		"isUsingOracleManagedKeys": llx.BoolDataPtr(b.IsUsingOracleManagedKeys),
		"retentionPeriodInDays":    llx.IntData(intValue(b.RetentionPeriodInDays)),
		"retentionPeriodInYears":   llx.IntData(intValue(b.RetentionPeriodInYears)),
		"timeExpiryScheduled":      llx.TimeDataPtr(expiry),
		"state":                    llx.StringData(string(b.LifecycleState)),
		"timeStarted":              llx.TimeDataPtr(started),
		"timeEnded":                llx.TimeDataPtr(ended),
	})
	if err != nil {
		return nil, err
	}
	mqlBackup := mqlInstance.(*mqlOciDatabaseBackup)
	mqlBackup.cacheKmsKeyID = stringValue(b.KmsKeyId)
	mqlBackup.cacheVaultID = stringValue(b.VaultId)
	return mqlBackup, nil
}

type mqlOciDatabaseBackupInternal struct {
	ociCompartmentRef
	cacheKmsKeyID string
	cacheVaultID  string
}

func (o *mqlOciDatabaseBackup) id() (string, error) {
	return "oci.database.backup/" + o.Id.Data, nil
}

func (o *mqlOciDatabaseBackup) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" || !isOcid(o.cacheKmsKeyID) {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsKey), nil
}

func (o *mqlOciDatabaseBackup) kmsVault() (*mqlOciKmsVault, error) {
	if o.cacheVaultID == "" || !isOcid(o.cacheVaultID) {
		o.KmsVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.vault", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVaultID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsVault), nil
}

// Autonomous Database Backups

func (o *mqlOciDatabase) autonomousDatabaseBackups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci autonomous database backups with region %s", region)

			svc, err := conn.DatabaseClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]database.AutonomousDatabaseBackupSummary, *string, error) {
				response, err := svc.ListAutonomousDatabaseBackups(ctx, database.ListAutonomousDatabaseBackupsRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				b := items[i]

				var started, ended, timeTill *time.Time
				if b.TimeStarted != nil {
					started = &b.TimeStarted.Time
				}
				if b.TimeEnded != nil {
					ended = &b.TimeEnded.Time
				}
				if b.TimeAvailableTill != nil {
					timeTill = &b.TimeAvailableTill.Time
				}

				var dbSizeTBs, sizeTBs float64
				if b.DatabaseSizeInTBs != nil {
					dbSizeTBs = float64(*b.DatabaseSizeInTBs)
				}
				if b.SizeInTBs != nil {
					sizeTBs = *b.SizeInTBs
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.database.autonomousDatabaseBackup", stringValue(b.CompartmentId), map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(b.Id),
					"name":                  llx.StringDataPtr(b.DisplayName),
					"type":                  llx.StringData(string(b.Type)),
					"isAutomatic":           llx.BoolDataPtr(b.IsAutomatic),
					"isRestorable":          llx.BoolDataPtr(b.IsRestorable),
					"retentionPeriodInDays": llx.IntData(intValue(b.RetentionPeriodInDays)),
					"timeAvailableTill":     llx.TimeDataPtr(timeTill),
					"databaseSizeInTBs":     llx.FloatData(dbSizeTBs),
					"sizeInTBs":             llx.FloatData(sizeTBs),
					"dbVersion":             llx.StringDataPtr(b.DbVersion),
					"infrastructureType":    llx.StringData(string(b.InfrastructureType)),
					"state":                 llx.StringData(string(b.LifecycleState)),
					"timeStarted":           llx.TimeDataPtr(started),
					"timeEnded":             llx.TimeDataPtr(ended),
				})
				if err != nil {
					return nil, err
				}
				mqlBackup := mqlInstance.(*mqlOciDatabaseAutonomousDatabaseBackup)
				mqlBackup.cacheAutonomousDatabaseID = stringValue(b.AutonomousDatabaseId)
				mqlBackup.cacheKmsKeyID = stringValue(b.KmsKeyId)
				mqlBackup.cacheVaultID = stringValue(b.VaultId)
				res = append(res, mqlBackup)
			}

			return res, nil
		})
}

// backups on an individual autonomous database returns its backups by
// filtering the service-wide listing. We rely on the tenancy-wide listing
// being cached and filter client-side, which avoids fanning out region calls
// per-database when the parent list is already fetched.
func (o *mqlOciDatabaseAutonomousDatabase) backups() ([]any, error) {
	dbObj, err := CreateResource(o.MqlRuntime, "oci.database", nil)
	if err != nil {
		return nil, err
	}
	db := dbObj.(*mqlOciDatabase)
	raw := db.GetAutonomousDatabaseBackups()
	if raw.Error != nil {
		return nil, raw.Error
	}
	dbID := o.Id.Data
	res := []any{}
	for _, r := range raw.Data {
		b := r.(*mqlOciDatabaseAutonomousDatabaseBackup)
		if b.cacheAutonomousDatabaseID == dbID {
			res = append(res, b)
		}
	}
	return res, nil
}

type mqlOciDatabaseAutonomousDatabaseBackupInternal struct {
	ociCompartmentRef
	cacheAutonomousDatabaseID string
	cacheKmsKeyID             string
	cacheVaultID              string
}

func (o *mqlOciDatabaseAutonomousDatabaseBackup) id() (string, error) {
	return "oci.database.autonomousDatabaseBackup/" + o.Id.Data, nil
}

func (o *mqlOciDatabaseAutonomousDatabaseBackup) autonomousDatabase() (*mqlOciDatabaseAutonomousDatabase, error) {
	if o.cacheAutonomousDatabaseID == "" || !isOcid(o.cacheAutonomousDatabaseID) {
		o.AutonomousDatabase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.database.autonomousDatabase", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheAutonomousDatabaseID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciDatabaseAutonomousDatabase), nil
}

func (o *mqlOciDatabaseAutonomousDatabaseBackup) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" || !isOcid(o.cacheKmsKeyID) {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsKey), nil
}

func (o *mqlOciDatabaseAutonomousDatabaseBackup) kmsVault() (*mqlOciKmsVault, error) {
	if o.cacheVaultID == "" || !isOcid(o.cacheVaultID) {
		o.KmsVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.vault", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVaultID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsVault), nil
}

// longTermBackupArgs maps an Autonomous Database's long-term backup schedule
// onto resource arguments.
//
// A database with no long-term backup schedule leaves every one of these null.
// Defaulting them would report a cadence and a retention the database does not
// have, and "no schedule configured" is a different finding from "a schedule
// exists but is switched off" -- the latter reports
// longTermBackupScheduleDisabled true rather than null.
func longTermBackupArgs(sched *database.LongTermBackUpScheduleDetails, next *common.SDKTime) map[string]*llx.RawData {
	var (
		cadence   *string
		timeOf    *time.Time
		retention *int
		disabled  *bool
	)
	if sched != nil {
		// The SDK leaves an unset enum as "", which would otherwise reach MQL
		// as an empty cadence rather than as null.
		if sched.RepeatCadence != "" {
			c := string(sched.RepeatCadence)
			cadence = &c
		}
		if sched.TimeOfBackup != nil {
			timeOf = &sched.TimeOfBackup.Time
		}
		retention = sched.RetentionPeriodInDays
		disabled = sched.IsDisabled
	}

	var nextRun *time.Time
	if next != nil {
		nextRun = &next.Time
	}

	return map[string]*llx.RawData{
		"longTermBackupRepeatCadence":         llx.StringDataPtr(cadence),
		"longTermBackupTimeOfBackup":          llx.TimeDataPtr(timeOf),
		"longTermBackupRetentionPeriodInDays": llx.IntDataPtr(retention),
		"longTermBackupScheduleDisabled":      llx.BoolDataPtr(disabled),
		"nextLongTermBackupTimestamp":         llx.TimeDataPtr(nextRun),
	}
}

// scheduledMaintenanceWindowArgs flattens an Autonomous Database's scheduled
// maintenance window onto the parent resource. Every value stays null when the
// window is absent, so a database Oracle patches at a time of its own choosing
// reads as "not scheduled" rather than as a window with blank values.
func scheduledMaintenanceWindowArgs(win *database.AutonomousDatabaseMaintenanceWindowSummary, update *common.SDKTime) map[string]*llx.RawData {
	var (
		day           *string
		startTime     *string
		endTime       *string
		availability  *string
		changePending *bool
	)
	if win != nil {
		// The SDK leaves an unset enum as "", which would otherwise reach MQL
		// as an empty day rather than as null.
		if win.DayOfWeek != nil && win.DayOfWeek.Name != "" {
			d := string(win.DayOfWeek.Name)
			day = &d
		}
		startTime = win.MaintenanceStartTime
		endTime = win.MaintenanceEndTime
		availability = win.AvailabilityDomain
		changePending = win.IsMaintenanceWindowChangeScheduled
	}

	var updateAt *time.Time
	if update != nil {
		updateAt = &update.Time
	}

	return map[string]*llx.RawData{
		"maintenanceDayOfWeek":                 llx.StringDataPtr(day),
		"maintenanceStartTime":                 llx.StringDataPtr(startTime),
		"maintenanceEndTime":                   llx.StringDataPtr(endTime),
		"maintenanceAvailabilityDomain":        llx.StringDataPtr(availability),
		"maintenanceWindowChangeScheduled":     llx.BoolDataPtr(changePending),
		"timeScheduledMaintenanceWindowUpdate": llx.TimeDataPtr(updateAt),
	}
}
