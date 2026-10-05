// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"strconv"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
)

type mqlGcpProjectSqlServiceInstanceSettingsIpConfigurationInternal struct {
	cachePrivateNetwork string
}

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
	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.sqlService.instance requires a \"projectId\" argument")
	}

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

	// args["name"] on an absent key is a nil *llx.RawData; dereferencing it
	// panics the provider and kills the whole scan. `region` narrows the match
	// when supplied but is optional, so a two-arg lookup still resolves.
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.sqlService.instance requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	regionVal := ""
	if args["region"] != nil {
		regionVal, _ = args["region"].Value.(string)
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

		if name.Data == nameVal && projectId.Data == args["projectId"].Value &&
			(regionVal == "" || instanceRegion.Data == regionVal) {
			return args, instance, nil
		}
	}

	return nil, nil, errors.New("SQL instance not found")
}

// getSqlInstanceByName resolves a sibling Cloud SQL instance by its name within
// the same project. MasterInstanceName / ReplicaNames carry bare instance names
// (sometimes prefixed with "project:"), so the lookup lists the project's
// instances and matches by name rather than going through the region-keyed init.
// Returns nil when no instance with that name exists in the project (for example
// a cross-project replication pair).
func getSqlInstanceByName(runtime *plugin.Runtime, projectId, name string) (*mqlGcpProjectSqlServiceInstance, error) {
	if name == "" {
		return nil, nil
	}
	if i := strings.LastIndex(name, ":"); i >= 0 {
		name = name[i+1:]
	}

	obj, err := CreateResource(runtime, "gcp.project.sqlService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	sqlSvc := obj.(*mqlGcpProjectSqlService)
	instances := sqlSvc.GetInstances()
	if instances.Error != nil {
		return nil, instances.Error
	}

	for _, inst := range instances.Data {
		instance := inst.(*mqlGcpProjectSqlServiceInstance)
		n := instance.GetName()
		if n.Error != nil {
			return nil, n.Error
		}
		if n.Data == name {
			return instance, nil
		}
	}
	return nil, nil
}

func (g *mqlGcpProjectSqlServiceInstance) master() (*mqlGcpProjectSqlServiceInstance, error) {
	if g.MasterInstanceName.Error != nil {
		return nil, g.MasterInstanceName.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	master, err := getSqlInstanceByName(g.MqlRuntime, g.ProjectId.Data, g.MasterInstanceName.Data)
	if err != nil {
		return nil, err
	}
	if master == nil {
		g.Master.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return master, nil
}

func (g *mqlGcpProjectSqlServiceInstance) replicas() ([]any, error) {
	if g.ReplicaNames.Error != nil {
		return nil, g.ReplicaNames.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	res := []any{}
	for _, raw := range g.ReplicaNames.Data {
		name, ok := raw.(string)
		if !ok {
			continue
		}
		replica, err := getSqlInstanceByName(g.MqlRuntime, g.ProjectId.Data, name)
		if err != nil {
			return nil, err
		}
		if replica != nil {
			res = append(res, replica)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectSqlServiceInstance) failoverReplicaRef() (*mqlGcpProjectSqlServiceInstance, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	replica, err := getSqlInstanceByName(g.MqlRuntime, g.ProjectId.Data, g.cacheFailoverReplicaName)
	if err != nil {
		return nil, err
	}
	if replica == nil {
		g.FailoverReplicaRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return replica, nil
}

func (g *mqlGcpProjectSqlServiceInstance) drReplica() (*mqlGcpProjectSqlServiceInstance, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	replica, err := getSqlInstanceByName(g.MqlRuntime, g.ProjectId.Data, g.cacheDrReplicaName)
	if err != nil {
		return nil, err
	}
	if replica == nil {
		g.DrReplica.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return replica, nil
}

func (g *mqlGcpProjectSqlServiceInstance) managedBy() (string, error) {
	settings := g.GetSettings()
	if settings.Error != nil {
		return "", settings.Error
	}
	if settings.Data == nil {
		return "", nil
	}
	return managedByFromLabels(settings.Data.GetUserLabels())
}

// sqlIPMappingID returns a cache-stable identifier for a Cloud SQL instance
// IP address. A single instance can expose more than one IP of the same
// Type (e.g., two PRIVATE IPs across distinct VPCs), so the address itself
// must participate in the id to avoid runtime-cache collisions.
func sqlIPMappingID(instanceId, ipType, ipAddress string) string {
	return fmt.Sprintf("%s/ipAddresses/%s/%s", instanceId, ipType, ipAddress)
}

// sqlDenyMaintenancePeriodID returns a cache-stable identifier for a
// Cloud SQL deny-maintenance period. Two periods can start on the same
// date (e.g., recurring annual windows) but cover different end dates, so
// both dates must participate in the id.
func sqlDenyMaintenancePeriodID(instanceId, startDate, endDate string) string {
	return fmt.Sprintf("%s/settings/denyMaintenancePeriod/%s/%s", instanceId, startDate, endDate)
}

func (g *mqlGcpProjectSqlService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.sqlService", projectId), nil
}

type mqlGcpProjectSqlServiceInternal struct {
	serviceGate
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

	serviceEnabled, err := g.isServiceEnabled(service_sqladmin)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectSqlService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_sqladmin).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

// sqlDiskEncryptionConfigDict maps an instance's customer-managed encryption
// configuration to the diskEncryptionConfiguration dict. Absent
// configurations yield nil.
func sqlDiskEncryptionConfigDict(cfg *sqladmin.DiskEncryptionConfiguration) map[string]any {
	if cfg == nil {
		return nil
	}
	return map[string]any{
		"kmsKeyName":                      cfg.KmsKeyName,
		"cmekSourceLogEncryptionEnforced": cfg.CmekSourceLogEncryptionEnforced,
	}
}

// sqlCmekSourceLogEncryptionEnforced reports whether transaction logs are
// encrypted with the customer-managed key at source. It is nil when the
// instance has no customer-managed key, where the setting does not apply.
func sqlCmekSourceLogEncryptionEnforced(cfg *sqladmin.DiskEncryptionConfiguration) *bool {
	if cfg == nil || cfg.KmsKeyName == "" {
		return nil
	}
	v := cfg.CmekSourceLogEncryptionEnforced
	return &v
}

// sqlDiskConfidentialMode reports whether Confidential Mode is enabled for an
// instance's or a backup's disks.
//
// The whole DiskEncryptionConfiguration message is absent on an instance using
// Google-managed encryption with no confidential disks, which is the common
// case, so the nil guard is the normal path rather than an edge case. Absent
// means not enabled: Cloud SQL only supports Confidential Mode on zonal C4A
// instances, so false is the truthful reading everywhere else, and reporting it
// as such keeps an "is confidential mode on" check failing rather than erroring.
func sqlDiskConfidentialMode(cfg *sqladmin.DiskEncryptionConfiguration) bool {
	if cfg == nil {
		return false
	}
	return cfg.ConfidentialMode
}

func (g *mqlGcpProjectSqlService) instances() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

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

			mqlEncCfg := sqlDiskEncryptionConfigDict(instance.DiskEncryptionConfiguration)

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
			for _, a := range instance.IpAddresses {
				mqlIpAddress, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.ipMapping", map[string]*llx.RawData{
					"id":           llx.StringData(sqlIPMappingID(instanceId, a.Type, a.IpAddress)),
					"ipAddress":    llx.StringData(a.IpAddress),
					"timeToRetire": llx.TimeDataPtr(parseTime(a.TimeToRetire)),
					"type":         llx.StringData(a.Type),
				})
				if err != nil {
					return err
				}
				mqlIpAddresses = append(mqlIpAddresses, mqlIpAddress)
			}

			// Settings is nil for instances that are mid-provisioning or in a
			// failed state; fall back to an empty struct so a single such
			// instance doesn't panic (and take down) the whole instances() list.
			s := instance.Settings
			if s == nil {
				s = &sqladmin.Settings{}
			}
			dbFlags := make(map[string]string)
			for _, f := range s.DatabaseFlags {
				dbFlags[f.Name] = f.Value
			}

			var mqlActiveDirectory plugin.Resource
			if s.ActiveDirectoryConfig != nil {
				mqlActiveDirectory, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.activeDirectory", map[string]*llx.RawData{
					"__id":                      llx.StringData(fmt.Sprintf("%s/settings/activeDirectory", instanceId)),
					"domain":                    llx.StringData(s.ActiveDirectoryConfig.Domain),
					"mode":                      llx.StringData(s.ActiveDirectoryConfig.Mode),
					"dnsServers":                llx.ArrayData(convert.SliceAnyToInterface(s.ActiveDirectoryConfig.DnsServers), types.String),
					"adminCredentialSecretName": llx.StringData(s.ActiveDirectoryConfig.AdminCredentialSecretName),
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
				var mqlRetention map[string]any
				if brs := s.BackupConfiguration.BackupRetentionSettings; brs != nil {
					mqlRetention, err = convert.JsonToDict(mqlRetentionSettings{
						RetainedBackups: brs.RetainedBackups,
						RetentionUnit:   brs.RetentionUnit,
					})
					if err != nil {
						return err
					}
				}

				mqlBackupCfg, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.backupconfiguration", map[string]*llx.RawData{
					"id":                           llx.StringData(fmt.Sprintf("%s/settings/backupConfiguration", instanceId)),
					"backupRetentionSettings":      llx.DictData(mqlRetention),
					"backupTier":                   llx.StringData(s.BackupConfiguration.BackupTier),
					"binaryLogEnabled":             llx.BoolData(s.BackupConfiguration.BinaryLogEnabled),
					"enabled":                      llx.BoolData(s.BackupConfiguration.Enabled),
					"location":                     llx.StringData(s.BackupConfiguration.Location),
					"pointInTimeRecoveryEnabled":   llx.BoolData(s.BackupConfiguration.PointInTimeRecoveryEnabled),
					"startTime":                    llx.StringData(s.BackupConfiguration.StartTime),
					"transactionLogRetentionDays":  llx.IntData(s.BackupConfiguration.TransactionLogRetentionDays),
					"transactionalLogStorageState": llx.StringData(s.BackupConfiguration.TransactionalLogStorageState),
				})
				if err != nil {
					return err
				}
			}

			mqlDenyMaintenancePeriods := make([]any, 0, len(s.DenyMaintenancePeriods))
			for _, p := range s.DenyMaintenancePeriods {
				mqlPeriod, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.denyMaintenancePeriod", map[string]*llx.RawData{
					"id":        llx.StringData(sqlDenyMaintenancePeriodID(instanceId, p.StartDate, p.EndDate)),
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

				var mqlPscCfg plugin.Resource
				if s.IpConfiguration.PscConfig != nil {
					pscAutoConnections := make([]any, 0, len(s.IpConfiguration.PscConfig.PscAutoConnections))
					for _, c := range s.IpConfiguration.PscConfig.PscAutoConnections {
						if d, err := convert.JsonToDict(c); err == nil {
							pscAutoConnections = append(pscAutoConnections, d)
						}
					}
					mqlPscCfg, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.ipConfiguration.pscConfig", map[string]*llx.RawData{
						"id":                      llx.StringData(fmt.Sprintf("%s/settings/ipConfiguration/pscConfig", instanceId)),
						"pscEnabled":              llx.BoolData(s.IpConfiguration.PscConfig.PscEnabled),
						"allowedConsumerProjects": llx.ArrayData(convert.SliceAnyToInterface(s.IpConfiguration.PscConfig.AllowedConsumerProjects), types.String),
						"pscAutoConnections":      llx.ArrayData(pscAutoConnections, types.Dict),
					})
					if err != nil {
						return err
					}
				}

				mqlIpCfg, err = CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings.ipConfiguration", map[string]*llx.RawData{
					"allocatedIpRange":                        llx.StringData(s.IpConfiguration.AllocatedIpRange),
					"authorizedNetworks":                      llx.ArrayData(mqlAclEntries, types.Dict),
					"customSubjectAlternativeNames":           llx.ArrayData(convert.SliceAnyToInterface(s.IpConfiguration.CustomSubjectAlternativeNames), types.String),
					"enablePrivatePathForGoogleCloudServices": llx.BoolData(s.IpConfiguration.EnablePrivatePathForGoogleCloudServices),
					"id":                            llx.StringData(fmt.Sprintf("%s/settings/ipConfiguration", instanceId)),
					"ipv4Enabled":                   llx.BoolData(s.IpConfiguration.Ipv4Enabled),
					"requireSsl":                    llx.BoolData(s.IpConfiguration.RequireSsl),
					"sslMode":                       llx.StringData(s.IpConfiguration.SslMode),
					"serverCaMode":                  llx.StringData(s.IpConfiguration.ServerCaMode),
					"serverCaPool":                  llx.StringData(s.IpConfiguration.ServerCaPool),
					"serverCertificateRotationMode": llx.StringData(s.IpConfiguration.ServerCertificateRotationMode),
					"pscConfig":                     llx.ResourceData(mqlPscCfg, "gcp.project.sqlService.instance.settings.ipConfiguration.pscConfig"),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlIpCfg.(*mqlGcpProjectSqlServiceInstanceSettingsIpConfiguration)
				mqlRef.cachePrivateNetwork = s.IpConfiguration.PrivateNetwork
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

			type mqlDataCacheCfg struct {
				DataCacheEnabled bool `json:"dataCacheEnabled"`
			}
			var mqlDataCacheConfig map[string]any
			if s.DataCacheConfig != nil {
				mqlDataCacheConfig, err = convert.JsonToDict(mqlDataCacheCfg{
					DataCacheEnabled: s.DataCacheConfig.DataCacheEnabled,
				})
				if err != nil {
					return err
				}
			}

			type mqlEntraIdCfg struct {
				ApplicationId string `json:"applicationId"`
				TenantId      string `json:"tenantId"`
			}
			var mqlEntraIdConfig map[string]any
			if s.EntraidConfig != nil {
				mqlEntraIdConfig, err = convert.JsonToDict(mqlEntraIdCfg{
					ApplicationId: s.EntraidConfig.ApplicationId,
					TenantId:      s.EntraidConfig.TenantId,
				})
				if err != nil {
					return err
				}
			}

			var mqlPerformanceCaptureConfig map[string]any
			if s.PerformanceCaptureConfig != nil {
				mqlPerformanceCaptureConfig, err = convert.JsonToDict(s.PerformanceCaptureConfig)
				if err != nil {
					return err
				}
			}

			// Each of the three configs below is optional. A nil config leaves
			// its fields at the zero value rather than reporting a default the
			// API never returned; the booleans read false, which is the safe
			// direction for "not enabled".
			var finalBackupEnabled bool
			var finalBackupRetentionDays int64
			if s.FinalBackupConfig != nil {
				finalBackupEnabled = s.FinalBackupConfig.Enabled
				finalBackupRetentionDays = s.FinalBackupConfig.RetentionDays
			}

			var connectionPoolingEnabled bool
			var connectionPoolerCount int64
			connectionPoolFlags := map[string]any{}
			if s.ConnectionPoolConfig != nil {
				connectionPoolingEnabled = s.ConnectionPoolConfig.ConnectionPoolingEnabled
				connectionPoolerCount = s.ConnectionPoolConfig.PoolerCount
				for _, f := range s.ConnectionPoolConfig.Flags {
					if f == nil {
						continue
					}
					connectionPoolFlags[f.Name] = f.Value
				}
			}

			var threadsPerCore int64
			if s.AdvancedMachineFeatures != nil {
				threadsPerCore = s.AdvancedMachineFeatures.ThreadsPerCore
			}

			mqlSettings, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.settings", map[string]*llx.RawData{
				"retainBackupsOnDelete":       llx.BoolData(s.RetainBackupsOnDelete),
				"finalBackupEnabled":          llx.BoolData(finalBackupEnabled),
				"finalBackupRetentionDays":    llx.IntData(finalBackupRetentionDays),
				"autoUpgradeEnabled":          llx.BoolData(s.AutoUpgradeEnabled),
				"connectionPoolingEnabled":    llx.BoolData(connectionPoolingEnabled),
				"connectionPoolerCount":       llx.IntData(connectionPoolerCount),
				"connectionPoolFlags":         llx.MapData(connectionPoolFlags, types.String),
				"threadsPerCore":              llx.IntData(threadsPerCore),
				"performanceCaptureConfig":    llx.DictData(mqlPerformanceCaptureConfig),
				"activationPolicy":            llx.StringData(s.ActivationPolicy),
				"activeDirectory":             llx.ResourceData(mqlActiveDirectory, "gcp.project.sqlService.instance.settings.activeDirectory"),
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
				"edition":                     llx.StringData(s.Edition),
				"dataCacheConfig":             llx.DictData(mqlDataCacheConfig),
				"entraidConfig":               llx.DictData(mqlEntraIdConfig),
				"dataApiAccess":               llx.StringData(s.DataApiAccess),
				"enableGoogleMlIntegration":   llx.BoolData(s.EnableGoogleMlIntegration),
				"enableDataplexIntegration":   llx.BoolData(s.EnableDataplexIntegration),
			})
			if err != nil {
				return err
			}

			replicaConfigDict, err := convert.JsonToDict(instance.ReplicaConfiguration)
			if err != nil {
				return err
			}

			type mqlDnsNameMapping struct {
				Name           string `json:"name"`
				ConnectionType string `json:"connectionType"`
				DnsScope       string `json:"dnsScope"`
				RecordManager  string `json:"recordManager"`
			}
			mqlDnsNames := make([]any, 0, len(instance.DnsNames))
			for _, d := range instance.DnsNames {
				if d == nil {
					continue
				}
				entry, err := convert.JsonToDict(mqlDnsNameMapping{
					Name:           d.Name,
					ConnectionType: d.ConnectionType,
					DnsScope:       d.DnsScope,
					RecordManager:  d.RecordManager,
				})
				if err != nil {
					return err
				}
				mqlDnsNames = append(mqlDnsNames, entry)
			}

			type mqlScheduledMaintenance struct {
				StartTime            string `json:"startTime,omitempty"`
				CanDefer             bool   `json:"canDefer"`
				CanReschedule        bool   `json:"canReschedule"`
				ScheduleDeadlineTime string `json:"scheduleDeadlineTime,omitempty"`
			}
			var mqlScheduledMaint map[string]any
			if instance.ScheduledMaintenance != nil {
				mqlScheduledMaint, err = convert.JsonToDict(mqlScheduledMaintenance{
					StartTime:            instance.ScheduledMaintenance.StartTime,
					CanDefer:             instance.ScheduledMaintenance.CanDefer,
					CanReschedule:        instance.ScheduledMaintenance.CanReschedule,
					ScheduleDeadlineTime: instance.ScheduledMaintenance.ScheduleDeadlineTime,
				})
				if err != nil {
					return err
				}
			}

			type mqlAvailableDbVersion struct {
				Name         string `json:"name"`
				MajorVersion string `json:"majorVersion"`
				DisplayName  string `json:"displayName"`
			}
			mqlUpgradableVersions := make([]any, 0, len(instance.UpgradableDatabaseVersions))
			for _, v := range instance.UpgradableDatabaseVersions {
				if v == nil {
					continue
				}
				entry, err := convert.JsonToDict(mqlAvailableDbVersion{
					Name:         v.Name,
					MajorVersion: v.MajorVersion,
					DisplayName:  v.DisplayName,
				})
				if err != nil {
					return err
				}
				mqlUpgradableVersions = append(mqlUpgradableVersions, entry)
			}

			type mqlReplicationCluster struct {
				DrReplica             bool   `json:"drReplica"`
				FailoverDrReplicaName string `json:"failoverDrReplicaName,omitempty"`
				PsaWriteEndpoint      string `json:"psaWriteEndpoint,omitempty"`
			}
			var mqlReplicationClusterDict map[string]any
			if instance.ReplicationCluster != nil {
				mqlReplicationClusterDict, err = convert.JsonToDict(mqlReplicationCluster{
					DrReplica:             instance.ReplicationCluster.DrReplica,
					FailoverDrReplicaName: instance.ReplicationCluster.FailoverDrReplicaName,
					PsaWriteEndpoint:      instance.ReplicationCluster.PsaWriteEndpoint,
				})
				if err != nil {
					return err
				}
			}

			var serverCaCertExpiration *time.Time
			if instance.ServerCaCert != nil {
				serverCaCertExpiration = parseTime(instance.ServerCaCert.ExpirationTime)
			}

			mqlPoolNodes := make([]any, 0, len(instance.Nodes))
			for _, node := range instance.Nodes {
				if node == nil {
					continue
				}
				nodeDict, err := convert.JsonToDict(node)
				if err != nil {
					return err
				}
				mqlPoolNodes = append(mqlPoolNodes, nodeDict)
			}

			// An instance that is not an external-primary replica reports no
			// on-premises configuration at all. Leave the field null rather
			// than creating an empty sub-resource, so a check for an insecure
			// SSL mode cannot match an instance that has no external link.
			onPremisesConfigData := llx.NilData
			if opc := instance.OnPremisesConfiguration; opc != nil {
				mqlOnPrem, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.onPremisesConfiguration", map[string]*llx.RawData{
					"__id":              llx.StringData(fmt.Sprintf("%s/%s/onPremisesConfiguration", projectId, instance.Name)),
					"hostPort":          llx.StringData(opc.HostPort),
					"username":          llx.StringData(opc.Username),
					"caCertificate":     llx.StringData(opc.CaCertificate),
					"clientCertificate": llx.StringData(opc.ClientCertificate),
					"sslOption":         llx.StringData(opc.SslOption),
					"dmsManaged":        llx.BoolData(opc.DmsManaged),
					"dumpFilePath":      llx.StringData(opc.DumpFilePath),
				})
				if err != nil {
					return err
				}
				mqlOnPremRes := mqlOnPrem.(*mqlGcpProjectSqlServiceInstanceOnPremisesConfiguration)
				mqlOnPremRes.cacheProjectId = projectId
				if src := opc.SourceInstance; src != nil {
					mqlOnPremRes.cacheSourceInstanceName = src.Name
					mqlOnPremRes.cacheSourceInstanceRegion = src.Region
					// A cross-project source names its own project.
					if src.Project != "" {
						mqlOnPremRes.cacheProjectId = src.Project
					}
				}
				onPremisesConfigData = llx.ResourceData(mqlOnPrem, "gcp.project.sqlService.instance.onPremisesConfiguration")
			}

			mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance", map[string]*llx.RawData{
				"availableMaintenanceVersions":    llx.ArrayData(convert.SliceAnyToInterface(instance.AvailableMaintenanceVersions), types.String),
				"backendType":                     llx.StringData(instance.BackendType),
				"connectionName":                  llx.StringData(instance.ConnectionName),
				"created":                         llx.TimeDataPtr(parseTime(instance.CreateTime)),
				"databaseInstalledVersion":        llx.StringData(instance.DatabaseInstalledVersion),
				"databaseVersion":                 llx.StringData(instance.DatabaseVersion),
				"diskEncryptionConfiguration":     llx.DictData(mqlEncCfg),
				"cmekSourceLogEncryptionEnforced": llx.BoolDataPtr(sqlCmekSourceLogEncryptionEnforced(instance.DiskEncryptionConfiguration)),
				"diskConfidentialMode":            llx.BoolData(sqlDiskConfidentialMode(instance.DiskEncryptionConfiguration)),
				"diskEncryptionStatus":            llx.DictData(mqlEncStatus),
				"failoverReplica":                 llx.DictData(mqlFailoverReplica),
				"instanceType":                    llx.StringData(instance.InstanceType),
				"ipAddresses":                     llx.ArrayData(mqlIpAddresses, types.Resource("gcp.project.sqlService.instance.ipMapping")),
				"maintenanceVersion":              llx.StringData(instance.MaintenanceVersion),
				"masterInstanceName":              llx.StringData(instance.MasterInstanceName),
				"maxDiskSize":                     llx.IntData(instance.MaxDiskSize),
				"name":                            llx.StringData(instance.Name),
				"projectId":                       llx.StringData(projectId),
				"region":                          llx.StringData(instance.Region),
				"replicaNames":                    llx.ArrayData(convert.SliceAnyToInterface(instance.ReplicaNames), types.String),
				"settings":                        llx.ResourceData(mqlSettings, "gcp.project.sqlService.instance.settings"),
				"state":                           llx.StringData(instance.State),
				"satisfiesPzi":                    llx.BoolData(instance.SatisfiesPzi),
				"satisfiesPzs":                    llx.BoolData(instance.SatisfiesPzs),
				"dnsName":                         llx.StringData(instance.DnsName),
				"sqlNetworkArchitecture":          llx.StringData(instance.SqlNetworkArchitecture),
				"suspensionReason":                llx.ArrayData(convert.SliceAnyToInterface(instance.SuspensionReason), types.String),
				"switchTransactionLogsToCloudStorageEnabled": llx.BoolData(instance.SwitchTransactionLogsToCloudStorageEnabled),
				"primaryDnsName":             llx.StringData(instance.PrimaryDnsName),
				"writeEndpoint":              llx.StringData(instance.WriteEndpoint),
				"pscServiceAttachmentLink":   llx.StringData(instance.PscServiceAttachmentLink),
				"currentDiskSize":            llx.IntData(instance.CurrentDiskSize),
				"etag":                       llx.StringData(instance.Etag),
				"replicaConfiguration":       llx.DictData(replicaConfigDict),
				"dnsNames":                   llx.ArrayData(mqlDnsNames, types.Dict),
				"scheduledMaintenance":       llx.DictData(mqlScheduledMaint),
				"upgradableDatabaseVersions": llx.ArrayData(mqlUpgradableVersions, types.Dict),
				"replicationCluster":         llx.DictData(mqlReplicationClusterDict),
				"serverCaCertExpiration":     llx.TimeDataPtr(serverCaCertExpiration),
				"ipv6Address":                llx.StringData(instance.Ipv6Address),
				"nodeCount":                  llx.IntData(instance.NodeCount),
				"nodes":                      llx.ArrayData(mqlPoolNodes, types.Dict),
				"onPremisesConfig":           onPremisesConfigData,
			})
			if err != nil {
				return err
			}
			mqlRef := mqlInstance.(*mqlGcpProjectSqlServiceInstance)
			mqlRef.cacheGceZone = instance.GceZone
			mqlRef.cacheServiceAccountEmailAddress = instance.ServiceAccountEmailAddress
			mqlSqlInstance := mqlInstance.(*mqlGcpProjectSqlServiceInstance)
			mqlSqlInstance.cacheSecondaryGceZone = instance.SecondaryGceZone
			if instance.DiskEncryptionConfiguration != nil {
				mqlSqlInstance.cacheKmsKeyName = instance.DiskEncryptionConfiguration.KmsKeyName
			}
			if instance.FailoverReplica != nil {
				mqlSqlInstance.cacheFailoverReplicaName = instance.FailoverReplica.Name
			}
			if instance.ReplicationCluster != nil {
				mqlSqlInstance.cacheDrReplicaName = instance.ReplicationCluster.FailoverDrReplicaName
			}
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
		// A principal often holds cloudsql.instances.list without the
		// per-instance sub-collection permissions. Degrade to null so the
		// instance still reports, rather than failing the whole query.
		if isSkippable(err) {
			log.Warn().Err(err).Str("instance", instanceName).Msg("could not list Cloud SQL databases")
			return nil, nil
		}
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
	cacheSecondaryGceZone           string
	cacheKmsKeyName                 string
	cacheFailoverReplicaName        string
	cacheDrReplicaName              string
	cacheGceZone                    string
	cacheServiceAccountEmailAddress string
}

type mqlGcpProjectSqlServiceInstanceOnPremisesConfigurationInternal struct {
	cacheProjectId            string
	cacheSourceInstanceName   string
	cacheSourceInstanceRegion string
}

// sourceInstance resolves the Cloud SQL instance this replica reads from.
//
// Most external-primary replicas point at a self-managed server that Cloud SQL
// does not model, in which case the API returns no sourceInstance and the field
// is null. It is only populated when the source is itself a Cloud SQL instance.
func (g *mqlGcpProjectSqlServiceInstanceOnPremisesConfiguration) sourceInstance() (*mqlGcpProjectSqlServiceInstance, error) {
	if g.cacheSourceInstanceName == "" {
		g.SourceInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	src, err := getSqlInstanceByName(g.MqlRuntime, g.cacheProjectId, g.cacheSourceInstanceName)
	if err != nil {
		return nil, err
	}
	if src == nil {
		g.SourceInstance.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return src, nil
}

func (g *mqlGcpProjectSqlServiceInstance) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectSqlServiceInstance) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheServiceAccountEmailAddress, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsIpConfiguration) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cachePrivateNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

// dumpFileBucket resolves the Cloud Storage bucket holding the source database
// dump. A dump is a full copy of the external database's contents, so the
// bucket's own IAM policy decides who can read that copy.
func (g *mqlGcpProjectSqlServiceInstanceOnPremisesConfiguration) dumpFileBucket() (*mqlGcpProjectStorageServiceBucket, error) {
	return resolveGcsBucketFromURI(g.MqlRuntime, g.DumpFilePath.Data, &g.DumpFileBucket)
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
	zoneName := g.cacheGceZone
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

func (g *mqlGcpProjectSqlServiceInstanceSettingsIpConfiguration) hasOpenAuthorizedNetworks() (bool, error) {
	if g.AuthorizedNetworks.Error != nil {
		return false, g.AuthorizedNetworks.Error
	}
	for _, n := range g.AuthorizedNetworks.Data {
		entry, ok := n.(map[string]any)
		if !ok {
			continue
		}
		value, _ := entry["value"].(string)
		if value == "0.0.0.0/0" || value == "::/0" {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsIpConfigurationPscConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsMaintenanceWindow) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstanceSettingsPasswordValidationPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectSqlServiceInstance) users() ([]any, error) {
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

	resp, err := sqladminSvc.Users.List(projectId, instanceName).Do()
	if err != nil {
		// hasBuiltInUsers() and localRootEnabled() both read this collection,
		// so propagating a 403 here failed the two headline Cloud SQL
		// hardening checks with an opaque error.
		if isSkippable(err) {
			log.Warn().Err(err).Str("instance", instanceName).Msg("could not list Cloud SQL users")
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for _, user := range resp.Items {
		databaseRoles := make([]any, len(user.DatabaseRoles))
		for i, r := range user.DatabaseRoles {
			databaseRoles[i] = r
		}

		var passwordPolicy map[string]any
		if user.PasswordPolicy != nil {
			passwordPolicy = map[string]any{
				"allowedFailedAttempts":      user.PasswordPolicy.AllowedFailedAttempts,
				"passwordExpirationDuration": user.PasswordPolicy.PasswordExpirationDuration,
				"enableFailedAttemptsCheck":  user.PasswordPolicy.EnableFailedAttemptsCheck,
				"enablePasswordVerification": user.PasswordPolicy.EnablePasswordVerification,
			}
		}

		mqlUser, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.user", map[string]*llx.RawData{
			"projectId":        llx.StringData(projectId),
			"instanceName":     llx.StringData(instanceName),
			"name":             llx.StringData(user.Name),
			"host":             llx.StringData(user.Host),
			"type":             llx.StringData(user.Type),
			"iamEmail":         llx.StringData(user.IamEmail),
			"databaseRoles":    llx.ArrayData(databaseRoles, types.String),
			"dualPasswordType": llx.StringData(user.DualPasswordType),
			"passwordPolicy":   llx.DictData(passwordPolicy),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}

	return res, nil
}

func (g *mqlGcpProjectSqlServiceInstanceUser) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	if g.Host.Error != nil {
		return "", g.Host.Error
	}
	return fmt.Sprintf("gcp.project/%s/sqlService.instance/%s/user/%s@%s", g.ProjectId.Data, g.InstanceName.Data, g.Name.Data, g.Host.Data), nil
}

func (g *mqlGcpProjectSqlServiceInstance) sslCerts() ([]any, error) {
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

	resp, err := sqladminSvc.SslCerts.List(projectId, instanceName).Do()
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("instance", instanceName).Msg("could not list Cloud SQL SSL certificates")
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for _, cert := range resp.Items {
		var createTime, expirationTime *time.Time
		if cert.CreateTime != "" {
			if t, err := time.Parse(time.RFC3339, cert.CreateTime); err == nil {
				createTime = &t
			} else {
				log.Warn().Err(err).Str("instance", instanceName).Msg("failed to parse SSL cert createTime")
			}
		}
		if cert.ExpirationTime != "" {
			if t, err := time.Parse(time.RFC3339, cert.ExpirationTime); err == nil {
				expirationTime = &t
			} else {
				log.Warn().Err(err).Str("instance", instanceName).Msg("failed to parse SSL cert expirationTime")
			}
		}

		mqlCert, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.instance.sslCert", map[string]*llx.RawData{
			"projectId":        llx.StringData(projectId),
			"instanceName":     llx.StringData(instanceName),
			"commonName":       llx.StringData(cert.CommonName),
			"sha1Fingerprint":  llx.StringData(cert.Sha1Fingerprint),
			"certSerialNumber": llx.StringData(cert.CertSerialNumber),
			"cert":             llx.StringData(cert.Cert),
			"createTime":       llx.TimeDataPtr(createTime),
			"expirationTime":   llx.TimeDataPtr(expirationTime),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCert)
	}

	return res, nil
}

func (g *mqlGcpProjectSqlServiceInstanceSslCert) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Sha1Fingerprint.Error != nil {
		return "", g.Sha1Fingerprint.Error
	}
	return fmt.Sprintf("gcp.project/%s/sqlService.instance/%s/sslCert/%s", g.ProjectId.Data, g.InstanceName.Data, g.Sha1Fingerprint.Data), nil
}

func (g *mqlGcpProjectSqlServiceInstance) backupRuns() ([]any, error) {
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

	var res []any
	req := sqladminSvc.BackupRuns.List(projectId, instanceName)
	if err := req.Pages(ctx, func(page *sqladmin.BackupRunsListResponse) error {
		for _, run := range page.Items {
			var encCfg map[string]any
			if run.DiskEncryptionConfiguration != nil {
				encCfg, err = convert.JsonToDict(run.DiskEncryptionConfiguration)
				if err != nil {
					return err
				}
			}
			var encStatus map[string]any
			if run.DiskEncryptionStatus != nil {
				encStatus, err = convert.JsonToDict(run.DiskEncryptionStatus)
				if err != nil {
					return err
				}
			}
			var runErr map[string]any
			if run.Error != nil {
				runErr, err = convert.JsonToDict(run.Error)
				if err != nil {
					return err
				}
			}

			mqlRun, err := CreateResource(g.MqlRuntime, "gcp.project.sqlService.backupRun", map[string]*llx.RawData{
				"projectId":                   llx.StringData(projectId),
				"instanceName":                llx.StringData(instanceName),
				"id":                          llx.StringData(strconv.FormatInt(run.Id, 10)),
				"backupKind":                  llx.StringData(run.BackupKind),
				"databaseVersion":             llx.StringData(run.DatabaseVersion),
				"description":                 llx.StringData(run.Description),
				"diskEncryptionConfiguration": llx.DictData(encCfg),
				"diskConfidentialMode":        llx.BoolData(sqlDiskConfidentialMode(run.DiskEncryptionConfiguration)),
				"diskEncryptionStatus":        llx.DictData(encStatus),
				"endTime":                     llx.TimeDataPtr(parseTime(run.EndTime)),
				"enqueuedTime":                llx.TimeDataPtr(parseTime(run.EnqueuedTime)),
				"error":                       llx.DictData(runErr),
				"location":                    llx.StringData(run.Location),
				"selfLink":                    llx.StringData(run.SelfLink),
				"startTime":                   llx.TimeDataPtr(parseTime(run.StartTime)),
				"status":                      llx.StringData(run.Status),
				"timeZone":                    llx.StringData(run.TimeZone),
				"type":                        llx.StringData(run.Type),
				"windowStartTime":             llx.TimeDataPtr(parseTime(run.WindowStartTime)),
				"maxChargeableBytes":          llx.IntData(run.MaxChargeableBytes),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlRun)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectSqlServiceBackupRun) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return fmt.Sprintf("gcp.project/%s/sqlService.instance/%s/backupRun/%s", g.ProjectId.Data, g.InstanceName.Data, g.Id.Data), nil
}

func (g *mqlGcpProjectSqlServiceInstance) publicIpEnabled() (bool, error) {
	settings := g.GetSettings()
	if settings.Error != nil {
		return false, settings.Error
	}
	if settings.Data == nil {
		return false, nil
	}
	ip := settings.Data.GetIpConfiguration()
	if ip.Error != nil {
		return false, ip.Error
	}
	if ip.Data == nil {
		return false, nil
	}
	enabled := ip.Data.GetIpv4Enabled()
	if enabled.Error != nil {
		return false, enabled.Error
	}
	return enabled.Data, nil
}

func (g *mqlGcpProjectSqlServiceInstance) iamAuthenticationEnabled() (bool, error) {
	settings := g.GetSettings()
	if settings.Error != nil {
		return false, settings.Error
	}
	if settings.Data == nil {
		return false, nil
	}
	flags := settings.Data.GetDatabaseFlags()
	if flags.Error != nil {
		return false, flags.Error
	}
	return sqlFlagOn(flags.Data, "cloudsql.iam_authentication"), nil
}

// normalizeSqlFlagName folds the separators Cloud SQL uses to spell the same
// database flag differently per engine. IAM database authentication, for
// example, is "cloudsql.iam_authentication" on PostgreSQL,
// "cloudsql_iam_authentication" on MySQL and "cloudsql iam authentication" on
// SQL Server. Matching one spelling literally reported IAM auth as disabled on
// every instance of the other two engines.
func normalizeSqlFlagName(name string) string {
	return strings.ToLower(strings.NewReplacer(".", "_", " ", "_", "-", "_").Replace(name))
}

// sqlFlagOn reports whether the named database flag is set to "on", comparing
// flag names by their normalized form so any engine's spelling matches. A flag
// that is absent reports false, which matches the Cloud SQL default.
func sqlFlagOn(flags map[string]any, name string) bool {
	want := normalizeSqlFlagName(name)
	for k, v := range flags {
		if normalizeSqlFlagName(k) != want {
			continue
		}
		if s, ok := v.(string); ok && strings.EqualFold(s, "on") {
			return true
		}
	}
	return false
}

func (g *mqlGcpProjectSqlServiceInstance) backupConfigurationEnabled() (bool, error) {
	settings := g.GetSettings()
	if settings.Error != nil {
		return false, settings.Error
	}
	if settings.Data == nil {
		return false, nil
	}
	backup := settings.Data.GetBackupConfiguration()
	if backup.Error != nil {
		return false, backup.Error
	}
	if backup.Data == nil {
		return false, nil
	}
	enabled := backup.Data.GetEnabled()
	if enabled.Error != nil {
		return false, enabled.Error
	}
	return enabled.Data, nil
}

func (g *mqlGcpProjectSqlServiceInstance) pointInTimeRecoveryEnabled() (bool, error) {
	settings := g.GetSettings()
	if settings.Error != nil {
		return false, settings.Error
	}
	if settings.Data == nil {
		return false, nil
	}
	backup := settings.Data.GetBackupConfiguration()
	if backup.Error != nil {
		return false, backup.Error
	}
	if backup.Data == nil {
		return false, nil
	}
	pitr := backup.Data.GetPointInTimeRecoveryEnabled()
	if pitr.Error != nil {
		return false, pitr.Error
	}
	return pitr.Data, nil
}

func (g *mqlGcpProjectSqlServiceInstance) hasBuiltInUsers() (bool, error) {
	users := g.GetUsers()
	if users.Error != nil {
		return false, users.Error
	}
	for _, raw := range users.Data {
		u, ok := raw.(*mqlGcpProjectSqlServiceInstanceUser)
		if !ok || u == nil {
			continue
		}
		t := u.GetType()
		if t.Error != nil {
			return false, t.Error
		}
		if t.Data == "BUILT_IN" || t.Data == "" {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectSqlServiceInstance) localRootEnabled() (bool, error) {
	users := g.GetUsers()
	if users.Error != nil {
		return false, users.Error
	}
	for _, raw := range users.Data {
		u, ok := raw.(*mqlGcpProjectSqlServiceInstanceUser)
		if !ok || u == nil {
			continue
		}
		name := u.GetName()
		if name.Error != nil {
			return false, name.Error
		}
		if name.Data != "root" {
			continue
		}
		t := u.GetType()
		if t.Error != nil {
			return false, t.Error
		}
		if t.Data == "BUILT_IN" || t.Data == "" {
			return true, nil
		}
	}
	return false, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectSqlService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_sqladmin)
}
