// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ----- database homes -----

func (o *mqlOciDatabase) dbHomes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci database homes with region %s", region)

			svc, err := conn.DatabaseClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]database.DbHomeSummary, *string, error) {
				response, err := svc.ListDbHomes(ctx, database.ListDbHomesRequest{
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
				h := items[i]
				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.database.dbHome", stringValue(h.CompartmentId), map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(h.Id),
					"name":                     llx.StringDataPtr(h.DisplayName),
					"dbVersion":                llx.StringDataPtr(h.DbVersion),
					"oneOffPatches":            llx.ArrayData(stringsToAny(h.OneOffPatches), types.String),
					"isUnifiedAuditingEnabled": llx.BoolData(boolValue(h.IsUnifiedAuditingEnabled)),
					"state":                    llx.StringData(string(h.LifecycleState)),
					"lifecycleDetails":         llx.StringDataPtr(h.LifecycleDetails),
					"created":                  sdkTimeData(h.TimeCreated),
					"freeformTags":             llx.MapData(strMapToAny(h.FreeformTags), types.String),
					"definedTags":              llx.MapData(definedTagsToAny(h.DefinedTags), types.Any),
					"systemTags":               llx.MapData(definedTagsToAny(h.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				home := mqlInstance.(*mqlOciDatabaseDbHome)
				home.cacheRegion = region
				home.cacheDbSystemID = stringValue(h.DbSystemId)
				home.cacheKmsKeyID = stringValue(h.KmsKeyId)
				res = append(res, home)
			}
			return res, nil
		})
}

type mqlOciDatabaseDbHomeInternal struct {
	ociCompartmentRef
	cacheRegion     string
	cacheDbSystemID string
	cacheKmsKeyID   string
}

func (o *mqlOciDatabaseDbHome) id() (string, error) {
	return "oci.database.dbHome/" + o.Id.Data, nil
}

func (o *mqlOciDatabaseDbHome) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDatabaseDbHome) dbSystem() (*mqlOciDatabaseDbSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.database.dbSystem", ocidOrEmpty(o.cacheDbSystemID), &o.DbSystem)
}

func (o *mqlOciDatabaseDbHome) kmsKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

func (o *mqlOciDatabaseDbHome) databases() ([]any, error) {
	return ociFilterDatabases(o.MqlRuntime, func(d *mqlOciDatabaseDatabase) bool {
		return d.cacheDbHomeID == o.Id.Data
	})
}

func initOciDatabaseDbHome(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetDbHomes()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.database.dbHome", id, items)
}

func (o *mqlOciDatabaseDbSystem) dbHomes() ([]any, error) {
	items, err := ociServiceCollection(o.MqlRuntime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetDbHomes()
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, raw := range items {
		if h, ok := raw.(*mqlOciDatabaseDbHome); ok && h.cacheDbSystemID == o.Id.Data {
			res = append(res, h)
		}
	}
	return res, nil
}

func (o *mqlOciDatabaseDbSystem) databases() ([]any, error) {
	return ociFilterDatabases(o.MqlRuntime, func(d *mqlOciDatabaseDatabase) bool {
		return d.cacheDbSystemID == o.Id.Data
	})
}

// ----- databases -----

// databases lists the databases in every database home.
//
// ListDatabases answers for one home at a time, so the homes are listed first
// (reusing the dbHomes collection when it has already been read) and each is
// then asked for its databases, in the region the home was found in.
func (o *mqlOciDatabase) databases() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	homes := o.GetDbHomes()
	if homes.Error != nil {
		return nil, homes.Error
	}

	jobs := make([]*jobpool.Job, 0, len(homes.Data))
	for _, raw := range homes.Data {
		home, ok := raw.(*mqlOciDatabaseDbHome)
		if !ok {
			continue
		}
		jobs = append(jobs, jobpool.NewJob(func() (jobpool.JobResult, error) {
			ctx := context.Background()
			svc, err := conn.DatabaseClient(home.cacheRegion)
			if err != nil {
				return nil, err
			}
			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]database.DatabaseSummary, *string, error) {
				response, err := svc.ListDatabases(ctx, database.ListDatabasesRequest{
					CompartmentId: common.String(home.cacheCompartmentID),
					DbHomeId:      common.String(home.Id.Data),
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
				d := items[i]
				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.database.database", stringValue(d.CompartmentId), ociDatabaseArgs(&d))
				if err != nil {
					return nil, err
				}
				db := mqlInstance.(*mqlOciDatabaseDatabase)
				db.cacheDbHomeID = stringValue(d.DbHomeId)
				db.cacheDbSystemID = stringValue(d.DbSystemId)
				db.cacheKmsKeyID = stringValue(d.KmsKeyId)
				db.cacheVaultID = stringValue(d.VaultId)
				res = append(res, db)
			}
			return jobpool.JobResult(res), nil
		}))
	}

	// The same policy the region fan-out uses: a region where the service has
	// no endpoint is skipped, anything else is reported. A home is only listed
	// here because it was readable, so a database listing that fails is a real
	// gap rather than a compartment the scan was never meant to see.
	return ociJoinRegionJobs(jobs, ociScopeTenancyRoot.concurrency())
}

// ociDatabaseArgs maps a database summary onto its resource fields.
//
// A database with no backup configuration reports autoBackupEnabled false, not
// null: nothing is backing it up, and a null would satisfy an assertion that
// automatic backups are on. The recovery window has no such safe reading and
// stays null.
func ociDatabaseArgs(d *database.DatabaseSummary) map[string]*llx.RawData {
	var (
		autoBackupEnabled                             bool
		recoveryWindow                                *int
		backupWindow, fullBackupWindow, fullBackupDay string
		deletionPolicy                                string
		destinations                                  = []any{}
	)
	if cfg := d.DbBackupConfig; cfg != nil {
		autoBackupEnabled = boolValue(cfg.AutoBackupEnabled)
		recoveryWindow = cfg.RecoveryWindowInDays
		backupWindow = string(cfg.AutoBackupWindow)
		fullBackupWindow = string(cfg.AutoFullBackupWindow)
		fullBackupDay = string(cfg.AutoFullBackupDay)
		deletionPolicy = string(cfg.BackupDeletionPolicy)
		destinations = ociBackupDestinations(cfg.BackupDestinationDetails)
	}

	return map[string]*llx.RawData{
		"id":                          llx.StringDataPtr(d.Id),
		"name":                        llx.StringDataPtr(d.DbName),
		"dbUniqueName":                llx.StringDataPtr(d.DbUniqueName),
		"pdbName":                     llx.StringDataPtr(d.PdbName),
		"isCdb":                       llx.BoolData(boolValue(d.IsCdb)),
		"dbWorkload":                  llx.StringDataPtr(d.DbWorkload),
		"characterSet":                llx.StringDataPtr(d.CharacterSet),
		"ncharacterSet":               llx.StringDataPtr(d.NcharacterSet),
		"autoBackupEnabled":           llx.BoolData(autoBackupEnabled),
		"backupRecoveryWindowInDays":  llx.IntDataPtr(intPtrToInt64(recoveryWindow)),
		"autoBackupWindow":            llx.StringData(backupWindow),
		"autoFullBackupWindow":        llx.StringData(fullBackupWindow),
		"autoFullBackupDay":           llx.StringData(fullBackupDay),
		"backupDeletionPolicy":        llx.StringData(deletionPolicy),
		"backupDestinations":          llx.ArrayData(destinations, types.Dict),
		"lastBackup":                  sdkTimeData(d.LastBackupTimestamp),
		"lastBackupDurationInSeconds": llx.IntDataPtr(intPtrToInt64(d.LastBackupDurationInSeconds)),
		"lastFailedBackup":            sdkTimeData(d.LastFailedBackupTimestamp),
		"patchVersion":                llx.StringDataPtr(d.PatchVersion),
		"state":                       llx.StringData(string(d.LifecycleState)),
		"lifecycleDetails":            llx.StringDataPtr(d.LifecycleDetails),
		"created":                     sdkTimeData(d.TimeCreated),
		"freeformTags":                llx.MapData(strMapToAny(d.FreeformTags), types.String),
		"definedTags":                 llx.MapData(definedTagsToAny(d.DefinedTags), types.Any),
		"systemTags":                  llx.MapData(definedTagsToAny(d.SystemTags), types.Dict),
	}
}

// ociBackupDestinations builds the backupDestinations dicts field by field.
//
// Built by hand rather than by converting the SDK struct, because the struct
// carries the password of the NFS or Recovery Appliance user the backups are
// written as (VpcPassword). Converting the struct would copy that password
// into every scan result; the user name and internet proxy are left out with
// it, since neither answers a question about where backups go.
func ociBackupDestinations(details []database.BackupDestinationDetails) []any {
	res := make([]any, 0, len(details))
	for _, d := range details {
		entry := map[string]any{
			"type":                             string(d.Type),
			"id":                               stringValue(d.Id),
			"isRemote":                         nil,
			"remoteRegion":                     stringValue(d.RemoteRegion),
			"isRetentionLockEnabled":           nil,
			"isZeroDataLossEnabled":            nil,
			"backupRetentionPolicyOnTerminate": string(d.BackupRetentionPolicyOnTerminate),
		}
		if d.IsRemote != nil {
			entry["isRemote"] = *d.IsRemote
		}
		if d.IsRetentionLockEnabled != nil {
			entry["isRetentionLockEnabled"] = *d.IsRetentionLockEnabled
		}
		if d.IsZeroDataLossEnabled != nil {
			entry["isZeroDataLossEnabled"] = *d.IsZeroDataLossEnabled
		}
		res = append(res, entry)
	}
	return res
}

type mqlOciDatabaseDatabaseInternal struct {
	ociCompartmentRef
	cacheDbHomeID   string
	cacheDbSystemID string
	cacheKmsKeyID   string
	cacheVaultID    string
}

func (o *mqlOciDatabaseDatabase) id() (string, error) {
	return "oci.database.database/" + o.Id.Data, nil
}

func (o *mqlOciDatabaseDatabase) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDatabaseDatabase) dbHome() (*mqlOciDatabaseDbHome, error) {
	return resolveRef(o.MqlRuntime, "oci.database.dbHome", ocidOrEmpty(o.cacheDbHomeID), &o.DbHome)
}

func (o *mqlOciDatabaseDatabase) dbSystem() (*mqlOciDatabaseDbSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.database.dbSystem", ocidOrEmpty(o.cacheDbSystemID), &o.DbSystem)
}

func (o *mqlOciDatabaseDatabase) kmsKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

func (o *mqlOciDatabaseDatabase) kmsVault() (*mqlOciKmsVault, error) {
	return resolveOciVault(o.MqlRuntime, ocidOrEmpty(o.cacheVaultID), &o.KmsVault)
}

func (o *mqlOciDatabaseDatabase) backups() ([]any, error) {
	items, err := ociServiceCollection(o.MqlRuntime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetBackups()
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, raw := range items {
		if b, ok := raw.(*mqlOciDatabaseBackup); ok && b.DatabaseId.Data == o.Id.Data {
			res = append(res, b)
		}
	}
	return res, nil
}

func initOciDatabaseDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetDatabases()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.database.database", id, items)
}

// ociFilterDatabases returns the databases from the service-wide listing that
// match keep, so a DB system or home asking for its own databases shares the
// one listing instead of issuing its own calls.
func ociFilterDatabases(runtime *plugin.Runtime, keep func(*mqlOciDatabaseDatabase) bool) ([]any, error) {
	items, err := ociServiceCollection(runtime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetDatabases()
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, raw := range items {
		if d, ok := raw.(*mqlOciDatabaseDatabase); ok && keep(d) {
			res = append(res, d)
		}
	}
	return res, nil
}

// database resolves the database a backup was taken from, through the
// service-wide database listing.
//
// A backup outlives its database, so a database id the listing does not carry
// is a terminated database rather than a lookup failure, and reads null.
func (o *mqlOciDatabaseBackup) database() (*mqlOciDatabaseDatabase, error) {
	id := o.DatabaseId.Data
	if id == "" {
		o.Database.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	found, err := ociFilterDatabases(o.MqlRuntime, func(d *mqlOciDatabaseDatabase) bool {
		return d.Id.Data == id
	})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		o.Database.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return found[0].(*mqlOciDatabaseDatabase), nil
}
