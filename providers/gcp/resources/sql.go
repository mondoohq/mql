// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"

	"strconv"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
)

func initGcpProjectSqlService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func initGcpProjectSqlServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["region"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Create the parent SQL service and find the specific instance
	obj, err := CreateResource(runtime, "gcp.project.sqlService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	sqlSvc := obj.(*mqlGcpProjectSqlService)
	instances := sqlSvc.GetInstances()
	if instances.Error != nil {
		return nil, nil, instances.Error
	}

	// Find the matching instance
	for _, inst := range instances.Data {
		instance := inst.(*mqlGcpProjectSqlServiceInstance)
		name := instance.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := instance.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}
		instanceRegion := instance.GetRegion()
		if instanceRegion.Error != nil {
			return nil, nil, instanceRegion.Error
		}

		if instanceRegion.Data == args["region"].Value && name.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, instance, nil
		}
	}

	return nil, nil, errors.New("SQL instance not found")
}

func (g *mqlGcpProjectSqlService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.sqlService", projectId), nil
}

func (g *mqlGcpProject) sql() (*mqlGcpProjectSqlService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectSqlService), nil
}

func (g *mqlGcpProjectSqlService) instances() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, sqladmin.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	sqladminSvc, err := sqladmin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := sqladminSvc.Instances.List(projectId)
	if err := req.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for i := range page.Items {
			instance := page.Items[i]
			instanceId := fmt.Sprintf("%s/%s", projectId, instance.Name)

			type mqlDiskEncryptionCfg struct {
				KmsKeyName string `json:"kmsKeyName"`
			}
			var mqlEncCfg map[string]any
			if instance.DiskEncryptionConfiguration != nil {
				mqlEncCfg, err = convert.JsonToDict(mqlDiskEncryptionCfg{
					KmsKeyName: instance.DiskEncryptionConfiguration.KmsKeyName,
				})
				if err != nil {
					return err
				}
			}

			type mqlDiskEncryptionStatus struct {
				KmsKeyVersionName string `json:"kmsKeyVersionName"`
			}
			var mqlEncStatus map[string]any
			if instance.DiskEncryptionStatus != nil {
				mqlEncStatus, err = convert.JsonToDict(mqlDiskEncryptionStatus{
					KmsKeyVersionName: instance.DiskEncryptionStatus.KmsKeyVersionName,
				})
				if err != nil {
					return err
				}
			}

			type mqlFailoverReplicaCfg struct {
				Available bool   `json:"available"`
				Name      string `json:"name"`
			}
			var mqlFailoverReplica map[string]any
			if instance.FailoverReplica != nil {
				mqlFailoverReplica, err = convert.JsonToDict(mqlFailoverReplicaCfg{
					Available: instance.FailoverReplica.Available,
					Name:      instance.FailoverReplica.Name,
				})
				if err != nil {
					return err
				}
			}

			mqlIpAddresses := make([]any, 0, len(instance.IpAddresses))
			for i, a := range instance.IpAddresses {
				mqlIpAddress, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.ipMapping", map[string]*llx.RawData{
					"id":           llx.StringData(fmt.Sprintf("%s/ipAddresses%d", instanceId, i)),
					"ipAddress":    llx.StringData(a.IpAddress),
					"timeToRetire": llx.TimeDataPtr(parseTime(a.TimeToRetire)),
					"type":         llx.StringData(a.Type),
				})
				if err != nil {
					return err
				}
				mqlIpAddresses = append(mqlIpAddresses, mqlIpAddress)
			}

			s := instance.Settings
			dbFlags := make(map[string]string)
			for _, f := range s.DatabaseFlags {
				dbFlags[f.Name] = f.Value
			}

			type mqlActiveDirectoryCfg struct {
				Domain string `json:"domain,omitempty"`
			}
			var mqlADCfg map[string]any
			if s.ActiveDirectoryConfig != nil {
				mqlADCfg, err = convert.JsonToDict(mqlActiveDirectoryCfg{
					Domain: s.ActiveDirectoryConfig.Domain,
				})
				if err != nil {
					return err
				}
			}

			var mqlBackupCfg plugin.Resource
			if s.BackupConfiguration != nil {
				type mqlRetentionSettings struct {
					RetainedBackups int64  `json:"retainedBackups"`
					RetentionUnit   string `json:"retentionUnit"`
				}
				mqlRetention, err := convert.JsonToDict(mqlRetentionSettings{
					RetainedBackups: s.BackupConfiguration.BackupRetentionSettings.RetainedBackups,
					RetentionUnit:   s.BackupConfiguration.BackupRetentionSettings.RetentionUnit,
				})
				if err != nil {
					return err
				}

				mqlBackupCfg, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.backupconfiguration", map[string]*llx.RawData{
					"id":                          llx.StringData(fmt.Sprintf("%s/settings/backupConfiguration", instanceId)),
					"backupRetentionSettings":     llx.DictData(mqlRetention),
					"binaryLogEnabled":            llx.BoolData(s.BackupConfiguration.BinaryLogEnabled),
					"enabled":                     llx.BoolData(s.BackupConfiguration.Enabled),
					"location":                    llx.StringData(s.BackupConfiguration.Location),
					"pointInTimeRecoveryEnabled":  llx.BoolData(s.BackupConfiguration.PointInTimeRecoveryEnabled),
					"startTime":                   llx.StringData(s.BackupConfiguration.StartTime),
					"transactionLogRetentionDays": llx.IntData(s.BackupConfiguration.TransactionLogRetentionDays),
				})
				if err != nil {
					return err
				}
			}

			mqlDenyMaintenancePeriods := make([]any, 0, len(s.DenyMaintenancePeriods))
			for i, p := range s.DenyMaintenancePeriods {
				mqlPeriod, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.denyMaintenancePeriod", map[string]*llx.RawData{
					"id":        llx.StringData(fmt.Sprintf("%s/settings/denyMaintenancePeriod%d", instanceId, i)),
					"endDate":   llx.StringData(p.EndDate),
					"startDate": llx.StringData(p.StartDate),
					"time":      llx.StringData(p.Time),
				})
				if err != nil {
					return err
				}
				mqlDenyMaintenancePeriods = append(mqlDenyMaintenancePeriods, mqlPeriod)
			}

			type mqlInsightsCfg struct {
				QueryInsightsEnabled  bool  `json:"queryInsightsEnabled"`
				QueryPlansPerMinute   int64 `json:"queryPlansPerMinute"`
				QueryStringLength     int64 `json:"queryStringLength"`
				RecordApplicationTags bool  `json:"recordApplicationTags"`
				RecordClientAddress   bool  `json:"recordClientAddress"`
			}
			var mqlInsightsConfig map[string]any
			if s.InsightsConfig != nil {
				mqlInsightsConfig, err = convert.JsonToDict(mqlInsightsCfg{
					QueryInsightsEnabled:  s.InsightsConfig.QueryInsightsEnabled,
					QueryPlansPerMinute:   s.InsightsConfig.QueryPlansPerMinute,
					QueryStringLength:     s.InsightsConfig.QueryStringLength,
					RecordApplicationTags: s.InsightsConfig.RecordApplicationTags,
					RecordClientAddress:   s.InsightsConfig.RecordClientAddress,
				})
				if err != nil {
					return err
				}
			}

			type mqlAclEntry struct {
				ExpirationTime string `json:"expirationTime"`
				Kind           string `json:"kind"`
				Name           string `json:"name"`
				Value          string `json:"value"`
			}
			var mqlIpCfg plugin.Resource
			if s.IpConfiguration != nil {
				mqlAclEntries := make([]any, 0, len(s.IpConfiguration.AuthorizedNetworks))
				for _, e := range s.IpConfiguration.AuthorizedNetworks {
					mqlAclEntry, err := convert.JsonToDict(mqlAclEntry{
						ExpirationTime: e.ExpirationTime,
						Kind:           e.Kind,
						Name:           e.Name,
						Value:          e.Value,
					})
					if err != nil {
						return err
					}
					mqlAclEntries = append(mqlAclEntries, mqlAclEntry)
				}

				mqlIpCfg, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.ipConfiguration", map[string]*llx.RawData{
					"allocatedIpRange":                        llx.StringData(s.IpConfiguration.AllocatedIpRange),
					"authorizedNetworks":                      llx.ArrayData(mqlAclEntries, types.Dict),
					"enablePrivatePathForGoogleCloudServices": llx.BoolData(s.IpConfiguration.EnablePrivatePathForGoogleCloudServices),
					"id":             llx.StringData(fmt.Sprintf("%s/settings/ipConfiguration", instanceId)),
					"ipv4Enabled":    llx.BoolData(s.IpConfiguration.Ipv4Enabled),
					"privateNetwork": llx.StringData(s.IpConfiguration.PrivateNetwork),
					"requireSsl":     llx.BoolData(s.IpConfiguration.RequireSsl),
					"sslMode":        llx.StringData(s.IpConfiguration.SslMode),
				})
				if err != nil {
					return err
				}
			}

			type mqlLocationPref struct {
				FollowGaeApplication string `json:"followGaeApplication"`
				SecondaryZone        string `json:"secondaryZone"`
				Zone                 string `json:"zone"`
			}
			var mqlLocationP map[string]any
			if s.LocationPreference != nil {
				mqlLocationP, err = convert.JsonToDict(mqlLocationPref{
					FollowGaeApplication: s.LocationPreference.FollowGaeApplication,
					SecondaryZone:        s.LocationPreference.SecondaryZone,
					Zone:                 s.LocationPreference.Zone,
				})
				if err != nil {
					return err
				}
			}

			var mqlMaintenanceWindow plugin.Resource
			if s.MaintenanceWindow != nil {
				mqlMaintenanceWindow, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.maintenanceWindow", map[string]*llx.RawData{
					"id":          llx.StringData(fmt.Sprintf("%s/settings/maintenanceWindow", instanceId)),
					"day":         llx.IntData(s.MaintenanceWindow.Day),
					"hour":        llx.IntData(s.MaintenanceWindow.Hour),
					"updateTrack": llx.StringData(s.MaintenanceWindow.UpdateTrack),
				})
				if err != nil {
					return err
				}
			}

			var mqlPwdValidationPolicy plugin.Resource
			if s.PasswordValidationPolicy != nil {
				mqlPwdValidationPolicy, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.passwordValidationPolicy", map[string]*llx.RawData{
					"id":                        llx.StringData(fmt.Sprintf("%s/settings/passwordValidationPolicy", instanceId)),
					"complexity":                llx.StringData(s.PasswordValidationPolicy.Complexity),
					"disallowUsernameSubstring": llx.BoolData(s.PasswordValidationPolicy.DisallowUsernameSubstring),
					"enabledPasswordPolicy":     llx.BoolData(s.PasswordValidationPolicy.EnablePasswordPolicy),
					"minLength":                 llx.IntData(s.PasswordValidationPolicy.MinLength),
					"passwordChangeInterval":    llx.StringData(s.PasswordValidationPolicy.PasswordChangeInterval),
					"reuseInterval":             llx.IntData(s.PasswordValidationPolicy.ReuseInterval),
				})
				if err != nil {
					return err
				}
			}

			type mqlSqlServerAuditConfig struct {
				Bucket            string `json:"bucket"`
				RetentionInterval string `json:"retentionInterval"`
				UploadInterval    string `json:"uploadInterval"`
			}
			var mqlSqlServerAuditCfg map[string]any
			if s.SqlServerAuditConfig != nil {
				mqlSqlServerAuditCfg, err = convert.JsonToDict(mqlSqlServerAuditConfig{
					Bucket:            s.SqlServerAuditConfig.Bucket,
					RetentionInterval: s.SqlServerAuditConfig.RetentionInterval,
					UploadInterval:    s.SqlServerAuditConfig.UploadInterval,
				})
				if err != nil {
					return err
				}
			}

			mqlSettings, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings", map[string]*llx.RawData{
				"activationPolicy":            llx.StringData(s.ActivationPolicy),
				"activeDirectoryConfig":       llx.DictData(mqlADCfg),
				"availabilityType":            llx.StringData(s.AvailabilityType),
				"backupConfiguration":         llx.DictData(mqlBackupCfg),
				"collation":                   llx.StringData(s.Collation),
				"connectorEnforcement":        llx.StringData(s.ConnectorEnforcement),
				"crashSafeReplicationEnabled": llx.BoolData(s.CrashSafeReplicationEnabled),
				"databaseFlags":               llx.MapData(convert.MapToInterfaceMap(dbFlags), types.String),
				"databaseReplicationEnabled":  llx.BoolData(s.DatabaseReplicationEnabled),
				"dataDiskSizeGb":              llx.IntData(s.DataDiskSizeGb),
				"dataDiskType":                llx.StringData(s.DataDiskType),
				"deletionProtectionEnabled":   llx.BoolData(s.DeletionProtectionEnabled),
				"denyMaintenancePeriods":      llx.ArrayData(mqlDenyMaintenancePeriods, types.Resource("gcp.project.sqlService.instance.settings.denyMaintenancePeriod")),
				"insightsConfig":              llx.DictData(mqlInsightsConfig),
				"instanceName":                llx.StringData(instance.Name),
				"ipConfiguration":             llx.DictData(mqlIpCfg),
				"locationPreference":          llx.DictData(mqlLocationP),
				"maintenanceWindow":           llx.ResourceData(mqlMaintenanceWindow, "gcp.project.sqlService.instance.settings.maintenanceWindow"),
				"passwordValidationPolicy":    llx.ResourceData(mqlPwdValidationPolicy, "gcp.project.sqlService.instance.settings.passwordValidationPolicy"),
				"pricingPlan":                 llx.StringData(s.PricingPlan),
				"projectId":                   llx.StringData(projectId),
				"replicationType":             llx.StringData(s.ReplicationType),
				"settingsVersion":             llx.IntData(s.SettingsVersion),
				"sqlServerAuditConfig":        llx.DictData(mqlSqlServerAuditCfg),
				"storageAutoResize":           llx.BoolDataPtr(s.StorageAutoResize),
				"storageAutoResizeLimit":      llx.IntData(s.StorageAutoResizeLimit),
				"tier":                        llx.StringData(s.Tier),
				"timeZone":                    llx.StringData(s.TimeZone),
				"userLabels":                  llx.MapData(convert.MapToInterfaceMap(s.UserLabels), types.String),
			})
			if err != nil {
				return err
			}

			mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance", map[string]*llx.RawData{
				"availableMaintenanceVersions": llx.ArrayData(convert.SliceAnyToInterface(instance.AvailableMaintenanceVersions), types.String),
				"backendType":                  llx.StringData(instance.BackendType),
				"connectionName":               llx.StringData(instance.ConnectionName),
				"created":                      llx.TimeDataPtr(parseTime(instance.CreateTime)),
				"databaseInstalledVersion":     llx.StringData(instance.DatabaseInstalledVersion),
				"databaseVersion":              llx.StringData(instance.DatabaseVersion),
				"diskEncryptionConfiguration":  llx.DictData(mqlEncCfg),
				"diskEncryptionStatus":         llx.DictData(mqlEncStatus),
				"failoverReplica":              llx.DictData(mqlFailoverReplica),
				"gceZone":                      llx.StringData(instance.GceZone),
				"instanceType":                 llx.StringData(instance.InstanceType),
				"ipAddresses":                  llx.ArrayData(mqlIpAddresses, types.String),
				"maintenanceVersion":           llx.StringData(instance.MaintenanceVersion),
				"masterInstanceName":           llx.StringData(instance.MasterInstanceName),
				"maxDiskSize":                  llx.IntData(instance.MaxDiskSize),
				"name":                         llx.StringData(instance.Name),
				"projectId":                    llx.StringData(projectId),
				"region":                       llx.StringData(instance.Region),
				"replicaNames":                 llx.ArrayData(convert.SliceAnyToInterface(instance.ReplicaNames), types.String),
				"serviceAccountEmailAddress":   llx.StringData(instance.ServiceAccountEmailAddress),
				"settings":                     llx.ResourceData(mqlSettings, "gcp.project.sqlService.instance.settings"),
				"state":                        llx.StringData(instance.State),
				"satisfiesPzi":                 llx.BoolData(instance.SatisfiesPzi),
				"satisfiesPzs":                 llx.BoolData(instance.SatisfiesPzs),
				"dnsName":                      llx.StringData(instance.DnsName),
				"sqlNetworkArchitecture":       llx.StringData(instance.SqlNetworkArchitecture),
				"suspensionReason":             llx.ArrayData(convert.SliceAnyToInterface(instance.SuspensionReason), types.String),
				"switchTransactionLogsToCloudStorageEnabled": llx.BoolData(instance.SwitchTransactionLogsToCloudStorageEnabled),
				"primaryDnsName":           llx.StringData(instance.PrimaryDnsName),
				"writeEndpoint":            llx.StringData(instance.WriteEndpoint),
				"pscServiceAttachmentLink": llx.StringData(instance.PscServiceAttachmentLink),
				"currentDiskSize":          llx.IntData(instance.CurrentDiskSize),
				"etag":                     llx.StringData(instance.Etag),
			})
			if err != nil {
				return err
			}
			mqlInstance.(*mqlGcpProjectSqlServiceInstance).cacheSecondaryGceZone = instance.SecondaryGceZone
			res = append(res, mqlInstance)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectSqlServiceInstance) databases() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	instanceName := g.Name.Data

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, sqladmin.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	sqladminSvc, err := sqladmin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	dbs, err := sqladminSvc.Databases.List(projectId, instanceName).Do()
	if err != nil {
		return nil, err
	}

	mqlDbs := make([]any, 0, len(dbs.Items))
	for _, db := range dbs.Items {
		type mqlSqlServerDbDetails struct {
			CompatibilityLevel int64  `json:"compatibilityLevel"`
			RecoveryModel      string `json:"recoveryModel"`
		}
		var sqlServerDbDetails map[string]any
		if db.SqlserverDatabaseDetails != nil {
			sqlServerDbDetails, err = convert.JsonToDict(mqlSqlServerDbDetails{
				CompatibilityLevel: db.SqlserverDatabaseDetails.CompatibilityLevel,
				RecoveryModel:      db.SqlserverDatabaseDetails.RecoveryModel,
			})
			if err != nil {
				return nil, err
			}
		}

		mqlDb, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.database", map[string]*llx.RawData{
			"projectId":                llx.StringData(projectId),
			"charset":                  llx.StringData(db.Charset),
			"collation":                llx.StringData(db.Collation),
			"instance":                 llx.StringData(instanceName),
			"name":                     llx.StringData(db.Name),
			"sqlserverDatabaseDetails": llx.DictData(sqlServerDbDetails),
		})
		if err != nil {
			return nil, err
		}
		mqlDbs = append(mqlDbs, mqlDb)
	}
	return mqlDbs, nil
}

type mqlGcpProjectSqlServiceInstanceInternal struct {
	cacheSecondaryGceZone string
}

func (g *mqlGcpProjectSqlServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("%s/%s", projectId, name), nil
}

func (g *mqlGcpProjectSqlServiceInstance) zone() (*mqlGcpProjectComputeServiceZone, error) {
	if g.GceZone.Error != nil {
		return nil, g.GceZone.Error
	}
	zoneName := g.GceZone.Data
	if zoneName == "" {
		g.Zone.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return g.fetchZone(zoneName)
}

func (g *mqlGcpProjectSqlServiceInstance) secondaryZone() (*mqlGcpProjectComputeServiceZone, error) {
	zoneName := g.cacheSecondaryGceZone
	if zoneName == "" {
		g.SecondaryZone.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return g.fetchZone(zoneName)
}

func (g *mqlGcpProjectSqlServiceInstance) fetchZone(zoneName string) (*mqlGcpProjectComputeServiceZone, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.ComputeReadonlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	z, err := computeSvc.Zones.Get(projectId, zoneName).Do()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.zone", map[string]*llx.RawData{
		"id":          llx.StringData(strconv.FormatInt(int64(z.Id), 10)),
		"name":        llx.StringData(z.Name),
		"description": llx.StringData(z.Description),
		"status":      llx.StringData(z.Status),
		"created":     llx.TimeDataPtr(parseTime(z.CreationTimestamp)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceZone), nil
}

func (g *mqlGcpProjectSqlServiceInstanceDatabase) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Instance.Error != nil {
		return "", g.Instance.Error
	}
	instance := g.Instance.Data

	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("%s/%s/%s", projectId, instance, name), nil
}

func (g *mqlGcpProjectSqlServiceInstanceIpMapping) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettings) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	name := g.InstanceName.Data
	return fmt.Sprintf("%s/%s/settings", projectId, name), nil
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsBackupconfiguration) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsDenyMaintenancePeriod) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsIpConfiguration) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsMaintenanceWindow) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsPasswordValidationPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}
