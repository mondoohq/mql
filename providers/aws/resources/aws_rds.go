// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rds_types "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// The cluster and instance API also return data for non-RDS engines like Neptune and DocumentDB. We have to filter
// these out since we have specific resources for them.
var nonRdsEngines = []string{"neptune", "docdb"}

func (a *mqlAwsRds) id() (string, error) {
	return ResourceAwsRds, nil
}

// instances returns all RDS instances
func (a *mqlAwsRds) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getDbInstances>calling aws with region %s", region)

		res := []any{}
		svc := conn.Rds(region)

		params := &rds.DescribeDBInstancesInput{}
		paginator := rds.NewDescribeDBInstancesPaginator(svc, params)
		for paginator.HasMorePages() {
			dbInstances, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, dbInstance := range dbInstances.DBInstances {
				// we cannot filter it in the api call since the api does not support it negative filters
				if dbInstance.Engine != nil && slices.Contains(nonRdsEngines, *dbInstance.Engine) {
					log.Debug().Str("engine", *dbInstance.Engine).Msg("skipping non-RDS engine")
					continue
				}

				if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(rdsTagsToMap(dbInstance.TagList))) {
					log.Debug().Interface("dbInstance", dbInstance.DBInstanceArn).Msg("skipping rds db instance due to filters")
					continue
				}

				mqlDBInstance, err := newMqlAwsRdsInstance(a.MqlRuntime, region, conn.AccountId(), dbInstance)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlDBInstance)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsRds) clusterParameterGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getClusterParameterGroup>calling aws with region %s", region)
		res := []any{}
		svc := conn.Rds(region)

		params := &rds.DescribeDBClusterParameterGroupsInput{}
		paginator := rds.NewDescribeDBClusterParameterGroupsPaginator(svc, params)
		for paginator.HasMorePages() {
			DBClusterParameterGroups, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, dbClusterParameterGroup := range DBClusterParameterGroups.DBClusterParameterGroups {
				mqlParameterGroup, err := newMqlAwsRdsClusterParameterGroup(a.MqlRuntime, region, dbClusterParameterGroup)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlParameterGroup)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsRds) eventSubscriptions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getEventSubscriptions>calling aws with region %s", region)
		res := []any{}
		svc := conn.Rds(region)

		paginator := rds.NewDescribeEventSubscriptionsPaginator(svc, &rds.DescribeEventSubscriptionsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, sub := range page.EventSubscriptionsList {
				sourceIds := make([]any, 0, len(sub.SourceIdsList))
				for _, id := range sub.SourceIdsList {
					sourceIds = append(sourceIds, id)
				}
				eventCategories := make([]any, 0, len(sub.EventCategoriesList))
				for _, cat := range sub.EventCategoriesList {
					eventCategories = append(eventCategories, cat)
				}

				mqlSub, err := CreateResource(a.MqlRuntime, "aws.rds.eventSubscription",
					map[string]*llx.RawData{
						"__id":                     llx.StringDataPtr(sub.EventSubscriptionArn),
						"arn":                      llx.StringDataPtr(sub.EventSubscriptionArn),
						"name":                     llx.StringDataPtr(sub.CustSubscriptionId),
						"region":                   llx.StringData(region),
						"status":                   llx.StringDataPtr(sub.Status),
						"sourceType":               llx.StringDataPtr(sub.SourceType),
						"sourceIds":                llx.ArrayData(sourceIds, types.String),
						"enabled":                  llx.BoolData(convert.ToValue(sub.Enabled)),
						"eventCategories":          llx.ArrayData(eventCategories, types.String),
						"customerAwsId":            llx.StringDataPtr(sub.CustomerAwsId),
						"subscriptionCreationTime": llx.StringDataPtr(sub.SubscriptionCreationTime),
					})
				if err != nil {
					return nil, err
				}
				mqlSub.(*mqlAwsRdsEventSubscription).cacheSnsTopicArn = convert.ToValue(sub.SnsTopicArn)
				res = append(res, mqlSub)
			}
		}
		return res, nil
	})
}

type mqlAwsRdsEventSubscriptionInternal struct {
	lazyTags
	cacheSnsTopicArn string
}

func (a *mqlAwsRdsEventSubscription) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRdsEventSubscription) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return rdsTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsRdsEventSubscription) snsTopic() (*mqlAwsSnsTopic, error) {
	arn := a.cacheSnsTopicArn
	if arn == "" {
		a.SnsTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlTopic, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlTopic.(*mqlAwsSnsTopic), nil
}

func (a *mqlAwsRds) parameterGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getParameterGroup>calling aws with region %s", region)
		res := []any{}
		svc := conn.Rds(region)

		params := &rds.DescribeDBParameterGroupsInput{}
		paginator := rds.NewDescribeDBParameterGroupsPaginator(svc, params)
		for paginator.HasMorePages() {
			dbParameterGroups, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, dbParameterGroup := range dbParameterGroups.DBParameterGroups {
				mqlParameterGroup, err := newMqlAwsParameterGroup(a.MqlRuntime, region, dbParameterGroup)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlParameterGroup)
			}
		}
		return res, nil
	})
}

func newMqlAwsRdsClusterParameterGroup(runtime *plugin.Runtime, region string, parameterGroup rds_types.DBClusterParameterGroup) (*mqlAwsRdsClusterParameterGroup, error) {
	resource, err := CreateResource(runtime, ResourceAwsRdsClusterParameterGroup,
		map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("%s/%s", *parameterGroup.DBClusterParameterGroupArn, *parameterGroup.DBClusterParameterGroupName)),
			"arn":         llx.StringDataPtr(parameterGroup.DBClusterParameterGroupArn),
			"family":      llx.StringDataPtr(parameterGroup.DBParameterGroupFamily),
			"name":        llx.StringDataPtr(parameterGroup.DBClusterParameterGroupName),
			"description": llx.StringDataPtr(parameterGroup.Description),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlParameterGroup := resource.(*mqlAwsRdsClusterParameterGroup)
	return mqlParameterGroup, nil
}

type mqlAwsRdsClusterParameterGroupInternal struct {
	lazyTags
}

func (a *mqlAwsRdsClusterParameterGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return rdsTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

type mqlAwsRdsParameterGroupInternal struct {
	lazyTags
}

func (a *mqlAwsRdsParameterGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return rdsTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

// pendingMaintenanceActions returns all pending maintenance actions for all RDS instances
func (a *mqlAwsRds) allPendingMaintenanceActions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getDbInstances>calling aws with region %s", region)

		res := []any{}
		svc := conn.Rds(region)

		params := &rds.DescribePendingMaintenanceActionsInput{}
		paginator := rds.NewDescribePendingMaintenanceActionsPaginator(svc, params)
		for paginator.HasMorePages() {
			pendingMaintenanceList, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, resp := range pendingMaintenanceList.PendingMaintenanceActions {
				if resp.ResourceIdentifier == nil {
					continue
				}
				for _, action := range resp.PendingMaintenanceActionDetails {
					resourceArn := *resp.ResourceIdentifier
					mqlPendingAction, err := newMqlAwsPendingMaintenanceAction(a.MqlRuntime, resourceArn, action)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPendingAction)
				}
			}
		}
		return res, nil
	})
}

func (a *mqlAwsRdsDbinstance) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsRdsDbinstanceInternal struct {
	securityGroupIdHandler
	cacheSubnets                     *rds_types.DBSubnetGroup
	cacheKmsKeyId                    *string
	cachePerformanceInsightsKmsKeyId *string
	cacheActivityStreamKmsKeyId      *string
	cacheAssociatedRoles             []rds_types.DBInstanceRole
	cacheOptionGroupNames            []string
	region                           string
}

func newMqlAwsParameterGroup(runtime *plugin.Runtime, region string, parameterGroup rds_types.DBParameterGroup) (*mqlAwsRdsParameterGroup, error) {
	resource, err := CreateResource(runtime, ResourceAwsRdsParameterGroup,
		map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("%s/%s", *parameterGroup.DBParameterGroupArn, *parameterGroup.DBParameterGroupName)),
			"arn":         llx.StringDataPtr(parameterGroup.DBParameterGroupArn),
			"family":      llx.StringDataPtr(parameterGroup.DBParameterGroupFamily),
			"name":        llx.StringDataPtr(parameterGroup.DBParameterGroupName),
			"description": llx.StringDataPtr(parameterGroup.Description),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlParameterGroup := resource.(*mqlAwsRdsParameterGroup)
	return mqlParameterGroup, nil
}

// rdsGetParent returns the aws.rds resource the parameter-group lists hang off.
func rdsGetParent(runtime *plugin.Runtime) (*mqlAwsRds, error) {
	obj, err := CreateResource(runtime, "aws.rds", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsRds), nil
}

// rdsParameterGroupMatches reports whether a parameter group reached by name or
// arn is the one the caller asked for. Callers pass whichever of the two the
// query supplied; an empty wanted value never matches, so a query carrying only
// a name cannot be satisfied by a group whose arn happens to be empty.
func rdsParameterGroupMatches(gotArn, gotName, wantArn, wantName string) bool {
	if wantArn != "" {
		return gotArn == wantArn
	}
	return wantName != "" && gotName == wantName
}

// initAwsRdsParameterGroup resolves a DB parameter group by name or arn.
//
// Without an init, NewResource fell straight through to the generated
// constructor, which builds the resource from the two args the query supplied
// and leaves arn, family, description and region unset -- surfacing as
// "primitive with no type information". Worse, the resource has no id()
// method, so every such husk keyed on the empty string and the second lookup
// in a session returned the first group's data: asking for
// default.postgres16 answered with default.mysql8.0, with no error.
func initAwsRdsParameterGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	wantArn, wantName := rdsParameterGroupArgs(args)
	if wantArn == "" && wantName == "" {
		return nil, nil, errors.New("name or arn required to fetch rds parameter group")
	}
	r, err := rdsGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	groups := r.GetParameterGroups()
	if groups.Error != nil {
		return nil, nil, groups.Error
	}
	for _, raw := range groups.Data {
		pg, ok := raw.(*mqlAwsRdsParameterGroup)
		if !ok {
			continue
		}
		if rdsParameterGroupMatches(pg.Arn.Data, pg.Name.Data, wantArn, wantName) {
			return args, pg, nil
		}
	}
	return nil, nil, fmt.Errorf("aws.rds.parameterGroup with %s not found", rdsParameterGroupWanted(wantArn, wantName))
}

// initAwsRdsClusterParameterGroup is initAwsRdsParameterGroup for cluster
// parameter groups; see that function for why the fall-through was wrong.
func initAwsRdsClusterParameterGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	wantArn, wantName := rdsParameterGroupArgs(args)
	if wantArn == "" && wantName == "" {
		return nil, nil, errors.New("name or arn required to fetch rds cluster parameter group")
	}
	r, err := rdsGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	groups := r.GetClusterParameterGroups()
	if groups.Error != nil {
		return nil, nil, groups.Error
	}
	for _, raw := range groups.Data {
		pg, ok := raw.(*mqlAwsRdsClusterParameterGroup)
		if !ok {
			continue
		}
		if rdsParameterGroupMatches(pg.Arn.Data, pg.Name.Data, wantArn, wantName) {
			return args, pg, nil
		}
	}
	return nil, nil, fmt.Errorf("aws.rds.clusterParameterGroup with %s not found", rdsParameterGroupWanted(wantArn, wantName))
}

// rdsParameterGroupArgs reads the arn and name a parameter-group lookup
// supplied, tolerating either being absent or of an unexpected type.
func rdsParameterGroupArgs(args map[string]*llx.RawData) (arn string, name string) {
	if raw, ok := args["arn"]; ok && raw != nil {
		arn, _ = raw.Value.(string)
	}
	if raw, ok := args["name"]; ok && raw != nil {
		name, _ = raw.Value.(string)
	}
	return arn, name
}

// rdsParameterGroupWanted renders the lookup key for a not-found error.
func rdsParameterGroupWanted(arn, name string) string {
	if arn != "" {
		return fmt.Sprintf("arn %q", arn)
	}
	return fmt.Sprintf("name %q", name)
}

func (a *mqlAwsRdsClusterParameterGroup) parameters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	svc := conn.Rds(a.Region.Data)
	ctx := context.Background()

	params := &rds.DescribeDBClusterParametersInput{
		DBClusterParameterGroupName: &a.Name.Data,
	}
	paginator := rds.NewDescribeDBClusterParametersPaginator(svc, params)
	for paginator.HasMorePages() {
		parameters, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, parameter := range parameters.Parameters {
			mqlParameter, err := newMqlAwsRdsParameterGroupParameter(a.MqlRuntime, a.Arn.Data, parameter)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlParameter)
		}
	}
	return res, nil
}

func (a *mqlAwsRdsParameterGroup) parameters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	svc := conn.Rds(a.Region.Data)
	ctx := context.Background()

	params := &rds.DescribeDBParametersInput{
		DBParameterGroupName: &a.Name.Data,
	}
	paginator := rds.NewDescribeDBParametersPaginator(svc, params)
	for paginator.HasMorePages() {
		parameters, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, parameter := range parameters.Parameters {
			mqlParameter, err := newMqlAwsRdsParameterGroupParameter(a.MqlRuntime, a.Arn.Data, parameter)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlParameter)
		}
	}
	return res, nil
}

// newMqlAwsRdsParameterGroupParameter builds a single parameter row. groupArn
// qualifies the cache key: parameter names are unique only within one parameter
// group, so keying on the bare name collapses every group in the account onto
// whichever group resolved first.
func newMqlAwsRdsParameterGroupParameter(runtime *plugin.Runtime, groupArn string, parameter rds_types.Parameter) (*mqlAwsRdsParameterGroupParameter, error) {
	engineModes := []any{}
	for _, engineMode := range parameter.SupportedEngineModes {
		engineModes = append(engineModes, engineMode)
	}

	resource, err := CreateResource(runtime, ResourceAwsRdsParameterGroupParameter,
		map[string]*llx.RawData{
			"__id":                 llx.StringData(groupArn + "/parameter/" + convert.ToValue(parameter.ParameterName)),
			"name":                 llx.StringDataPtr(parameter.ParameterName),
			"value":                llx.StringDataPtr(parameter.ParameterValue),
			"allowedValues":        llx.StringDataPtr(parameter.AllowedValues),
			"applyType":            llx.StringDataPtr(parameter.ApplyType),
			"applyMethod":          llx.StringData(string(parameter.ApplyMethod)),
			"dataType":             llx.StringDataPtr(parameter.DataType),
			"description":          llx.StringDataPtr(parameter.Description),
			"isModifiable":         llx.BoolDataPtr(parameter.IsModifiable),
			"source":               llx.StringDataPtr(parameter.Source),
			"minimumEngineVersion": llx.StringDataPtr(parameter.MinimumEngineVersion),
			"supportedEngineModes": llx.ArrayData(engineModes, types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlParameter := resource.(*mqlAwsRdsParameterGroupParameter)
	return mqlParameter, nil
}

func newMqlAwsRdsInstance(runtime *plugin.Runtime, region string, accountID string, dbInstance rds_types.DBInstance) (*mqlAwsRdsDbinstance, error) {
	stringSliceInterface := []any{}
	for _, logExport := range dbInstance.EnabledCloudwatchLogsExports {
		stringSliceInterface = append(stringSliceInterface, logExport)
	}
	sgsArn := []string{}
	for i := range dbInstance.VpcSecurityGroups {
		sgsArn = append(sgsArn, NewSecurityGroupArn(region, accountID, convert.ToValue(dbInstance.VpcSecurityGroups[i].VpcSecurityGroupId)))
	}
	var endpointAddress *string
	if dbInstance.Endpoint != nil {
		endpointAddress = dbInstance.Endpoint.Address
	}

	var certificateExpiration *time.Time
	if dbInstance.CertificateDetails != nil {
		certificateExpiration = dbInstance.CertificateDetails.ValidTill
	}

	dbSubnetGroupDict, err := convert.JsonToDict(dbInstance.DBSubnetGroup)
	if err != nil {
		return nil, err
	}
	domainMemberships, err := convert.JsonToDictSlice(dbInstance.DomainMemberships)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAwsRdsDbinstance,
		map[string]*llx.RawData{
			"arn":                                llx.StringDataPtr(dbInstance.DBInstanceArn),
			"autoMinorVersionUpgrade":            llx.BoolDataPtr(dbInstance.AutoMinorVersionUpgrade),
			"availabilityZone":                   llx.StringDataPtr(dbInstance.AvailabilityZone),
			"backupRetentionPeriod":              llx.IntDataDefault(dbInstance.BackupRetentionPeriod, 0),
			"createdAt":                          llx.TimeDataPtr(dbInstance.InstanceCreateTime),
			"dbInstanceClass":                    llx.StringDataPtr(dbInstance.DBInstanceClass),
			"dbInstanceIdentifier":               llx.StringDataPtr(dbInstance.DBInstanceIdentifier),
			"deletionProtection":                 llx.BoolDataPtr(dbInstance.DeletionProtection),
			"enabledCloudwatchLogsExports":       llx.ArrayData(stringSliceInterface, types.String),
			"endpoint":                           llx.StringDataPtr(endpointAddress),
			"engine":                             llx.StringDataPtr(dbInstance.Engine),
			"engineLifecycleSupport":             llx.StringDataPtr(dbInstance.EngineLifecycleSupport),
			"engineVersion":                      llx.StringDataPtr(dbInstance.EngineVersion),
			"monitoringInterval":                 llx.IntDataPtr(dbInstance.MonitoringInterval),
			"enhancedMonitoringResourceArn":      llx.StringDataPtr(dbInstance.EnhancedMonitoringResourceArn),
			"id":                                 llx.StringDataPtr(dbInstance.DBInstanceIdentifier),
			"latestRestorableTime":               llx.TimeDataPtr(dbInstance.LatestRestorableTime),
			"masterUsername":                     llx.StringDataPtr(dbInstance.MasterUsername),
			"multiAZ":                            llx.BoolDataPtr(dbInstance.MultiAZ),
			"name":                               llx.StringDataPtr(dbInstance.DBName),
			"port":                               llx.IntDataDefault(dbInstance.DbInstancePort, 0),
			"publiclyAccessible":                 llx.BoolDataPtr(dbInstance.PubliclyAccessible),
			"region":                             llx.StringData(region),
			"status":                             llx.StringDataPtr(dbInstance.DBInstanceStatus),
			"storageAllocated":                   llx.IntDataDefault(dbInstance.AllocatedStorage, 0),
			"storageEncrypted":                   llx.BoolDataPtr(dbInstance.StorageEncrypted),
			"storageEncryptionType":              llx.StringData(string(dbInstance.StorageEncryptionType)),
			"storageIops":                        llx.IntDataDefault(dbInstance.Iops, 0),
			"storageType":                        llx.StringDataPtr(dbInstance.StorageType),
			"tags":                               llx.MapData(rdsTagsToMap(dbInstance.TagList), types.String),
			"certificateExpiresAt":               llx.TimeDataPtr(certificateExpiration),
			"certificateAuthority":               llx.StringDataPtr(dbInstance.CACertificateIdentifier),
			"iamDatabaseAuthentication":          llx.BoolDataPtr(dbInstance.IAMDatabaseAuthenticationEnabled),
			"customIamInstanceProfile":           llx.StringDataPtr(dbInstance.CustomIamInstanceProfile),
			"activityStreamMode":                 llx.StringData(string(dbInstance.ActivityStreamMode)),
			"activityStreamStatus":               llx.StringData(string(dbInstance.ActivityStreamStatus)),
			"networkType":                        llx.StringDataPtr(dbInstance.NetworkType),
			"preferredMaintenanceWindow":         llx.StringDataPtr(dbInstance.PreferredMaintenanceWindow),
			"preferredBackupWindow":              llx.StringDataPtr(dbInstance.PreferredBackupWindow),
			"performanceInsightsEnabled":         llx.BoolDataPtr(dbInstance.PerformanceInsightsEnabled),
			"performanceInsightsRetentionPeriod": llx.IntDataDefault(dbInstance.PerformanceInsightsRetentionPeriod, 0),
			"copyTagsToSnapshot":                 llx.BoolDataPtr(dbInstance.CopyTagsToSnapshot),
			"licenseModel":                       llx.StringDataPtr(dbInstance.LicenseModel),
			"maxAllocatedStorage":                llx.IntDataDefault(dbInstance.MaxAllocatedStorage, 0),
			"dedicatedLogVolume":                 llx.BoolDataPtr(dbInstance.DedicatedLogVolume),
			"dbiResourceId":                      llx.StringDataPtr(dbInstance.DbiResourceId),
			"dbClusterIdentifier":                llx.StringDataPtr(dbInstance.DBClusterIdentifier),
			"readReplicaSourceInstanceId":        llx.StringDataPtr(dbInstance.ReadReplicaSourceDBInstanceIdentifier),
			"readReplicaSourceClusterId":         llx.StringDataPtr(dbInstance.ReadReplicaSourceDBClusterIdentifier),
			"readReplicaInstanceIds":             llx.ArrayData(stringSliceToAny(dbInstance.ReadReplicaDBInstanceIdentifiers), types.String),
			"readReplicaClusterIds":              llx.ArrayData(stringSliceToAny(dbInstance.ReadReplicaDBClusterIdentifiers), types.String),
			"automatedBackupReplicationArns":     llx.ArrayData(rdsAutomatedBackupReplicationArns(dbInstance.DBInstanceAutomatedBackupsReplications), types.String),
			"storageThroughput":                  llx.IntDataDefault(dbInstance.StorageThroughput, 0),
			"masterUserSecret":                   llx.DictData(masterUserSecretToDict(dbInstance.MasterUserSecret)),
			"customerOwnedIpEnabled":             llx.BoolDataPtr(dbInstance.CustomerOwnedIpEnabled),
			"dbSubnetGroup":                      llx.DictData(dbSubnetGroupDict),
			"domainMemberships":                  llx.ArrayData(domainMemberships, types.Dict),
			"replicaMode":                        llx.StringData(string(dbInstance.ReplicaMode)),
			"multiTenant":                        llx.BoolDataPtr(dbInstance.MultiTenant),
		})
	if err != nil {
		return nil, err
	}
	mqlDBInstance := resource.(*mqlAwsRdsDbinstance)
	mqlDBInstance.region = region
	mqlDBInstance.cacheSubnets = dbInstance.DBSubnetGroup
	mqlDBInstance.cacheKmsKeyId = dbInstance.KmsKeyId
	mqlDBInstance.cachePerformanceInsightsKmsKeyId = dbInstance.PerformanceInsightsKMSKeyId
	mqlDBInstance.cacheActivityStreamKmsKeyId = dbInstance.ActivityStreamKmsKeyId
	mqlDBInstance.cacheAssociatedRoles = dbInstance.AssociatedRoles
	optionGroupNames := make([]string, 0, len(dbInstance.OptionGroupMemberships))
	for _, og := range dbInstance.OptionGroupMemberships {
		if og.OptionGroupName != nil && *og.OptionGroupName != "" {
			optionGroupNames = append(optionGroupNames, *og.OptionGroupName)
		}
	}
	mqlDBInstance.cacheOptionGroupNames = optionGroupNames
	mqlDBInstance.setSecurityGroupArns(sgsArn)
	return mqlDBInstance, nil
}

func (a *mqlAwsRdsDbinstance) associatedRoles() ([]any, error) {
	res := make([]any, 0, len(a.cacheAssociatedRoles))
	instanceArn := a.Arn.Data
	for _, role := range a.cacheAssociatedRoles {
		roleArn := convert.ToValue(role.RoleArn)
		featureName := convert.ToValue(role.FeatureName)
		mqlRole, err := CreateResource(a.MqlRuntime, ResourceAwsRdsDbinstanceAssociatedRole,
			map[string]*llx.RawData{
				"__id":        llx.StringData(fmt.Sprintf("%s/role/%s/feature/%s", instanceArn, roleArn, featureName)),
				"featureName": llx.StringData(featureName),
				"status":      llx.StringDataPtr(role.Status),
			})
		if err != nil {
			return nil, err
		}
		mqlRole.(*mqlAwsRdsDbinstanceAssociatedRole).cacheRoleArn = roleArn
		res = append(res, mqlRole)
	}
	return res, nil
}

func (a *mqlAwsRdsDbinstanceAssociatedRole) iamRole() (*mqlAwsIamRole, error) {
	arn := a.cacheRoleArn
	if arn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func initAwsRdsDbcluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformRdsDbcluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch rds db cluster")
	}

	// load all rds db clusters
	obj, err := CreateResource(runtime, "aws.rds", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	rds := obj.(*mqlAwsRds)
	rawResources := rds.GetClusters()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		dbInstance := rawResource.(*mqlAwsRdsDbcluster)
		if dbInstance.Arn.Data == arnVal {
			return args, dbInstance, nil
		}
	}
	return nil, nil, errors.New("rds db cluster does not exist")
}

func initAwsRdsDbinstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformRdsDbinstance); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch rds db instance")
	}

	// load all rds db instances
	obj, err := CreateResource(runtime, "aws.rds", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	rds := obj.(*mqlAwsRds)
	rawResources := rds.GetInstances()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		dbInstance := rawResource.(*mqlAwsRdsDbinstance)
		if dbInstance.Arn.Data == arnVal {
			return args, dbInstance, nil
		}
	}
	return nil, nil, errors.New("rds db instance does not exist")
}

// rdsSourceArn returns the ARN for a read-replica source identifier. Same-region
// sources are reported as a bare identifier and are assembled into an ARN using
// this instance's region and account; cross-region sources are already ARNs and
// are returned as-is.
func (a *mqlAwsRdsDbinstance) rdsSourceArn(identifier, pattern string) string {
	if strings.HasPrefix(identifier, "arn:") {
		return identifier
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(pattern, a.Region.Data, conn.AccountId(), identifier)
}

// readReplicaSourceInstance resolves the primary DB instance this read replica
// replicates from, when it is present in this account. Cross-account or
// cross-region sources that are not in the inventory resolve to null; the
// readReplicaSourceInstanceId field always carries the lineage identifier.
func (a *mqlAwsRdsDbinstance) readReplicaSourceInstance() (*mqlAwsRdsDbinstance, error) {
	if !a.ReadReplicaSourceInstanceId.IsSet() || a.ReadReplicaSourceInstanceId.Data == "" {
		a.ReadReplicaSourceInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	arnVal := a.rdsSourceArn(a.ReadReplicaSourceInstanceId.Data, rdsInstanceArnPattern)
	res, err := NewResource(a.MqlRuntime, "aws.rds.dbinstance",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.ReadReplicaSourceInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsRdsDbinstance), nil
}

// readReplicaSourceCluster resolves the source DB cluster this read replica
// replicates from, when it is present in this account. See
// readReplicaSourceInstance for the null-resolution semantics.
func (a *mqlAwsRdsDbinstance) readReplicaSourceCluster() (*mqlAwsRdsDbcluster, error) {
	if !a.ReadReplicaSourceClusterId.IsSet() || a.ReadReplicaSourceClusterId.Data == "" {
		a.ReadReplicaSourceCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	arnVal := a.rdsSourceArn(a.ReadReplicaSourceClusterId.Data, "arn:aws:rds:%s:%s:cluster:%s")
	res, err := NewResource(a.MqlRuntime, "aws.rds.dbcluster",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.ReadReplicaSourceCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsRdsDbcluster), nil
}

// rdsAutomatedBackupReplicationArns extracts the ARNs of an instance's
// cross-region automated backup replications.
func rdsAutomatedBackupReplicationArns(reps []rds_types.DBInstanceAutomatedBackupsReplication) []any {
	res := make([]any, 0, len(reps))
	for _, r := range reps {
		if r.DBInstanceAutomatedBackupsArn != nil && *r.DBInstanceAutomatedBackupsArn != "" {
			res = append(res, *r.DBInstanceAutomatedBackupsArn)
		}
	}
	return res
}

// resolveRdsReplicaRefs resolves read-replica identifiers to typed RDS resources,
// skipping any that aren't present in this account's inventory (cross-account or
// cross-region replicas). The raw identifiers remain available on the companion
// *Ids field so no lineage is lost.
func (a *mqlAwsRdsDbinstance) resolveRdsReplicaRefs(ids plugin.TValue[[]any], pattern, resourceName string) []any {
	res := []any{}
	for _, raw := range ids.Data {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		r, err := NewResource(a.MqlRuntime, resourceName,
			map[string]*llx.RawData{"arn": llx.StringData(a.rdsSourceArn(id, pattern))})
		if err != nil {
			continue
		}
		res = append(res, r)
	}
	return res
}

// readReplicaInstances resolves the DB instances that replicate from this
// instance. See resolveRdsReplicaRefs for the cross-account/region semantics.
func (a *mqlAwsRdsDbinstance) readReplicaInstances() ([]any, error) {
	return a.resolveRdsReplicaRefs(a.ReadReplicaInstanceIds, rdsInstanceArnPattern, "aws.rds.dbinstance"), nil
}

// readReplicaClusters resolves the DB clusters that replicate from this instance.
func (a *mqlAwsRdsDbinstance) readReplicaClusters() ([]any, error) {
	return a.resolveRdsReplicaRefs(a.ReadReplicaClusterIds, "arn:aws:rds:%s:%s:cluster:%s", "aws.rds.dbcluster"), nil
}

// readReplicas resolves the DB clusters that replicate from this cluster,
// skipping any not present in this account's inventory. The raw identifiers
// remain available on readReplicaClusterIds.
func (a *mqlAwsRdsDbcluster) readReplicas() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, raw := range a.ReadReplicaClusterIds.Data {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		arnVal := id
		if !strings.HasPrefix(id, "arn:") {
			arnVal = fmt.Sprintf("arn:aws:rds:%s:%s:cluster:%s", a.Region.Data, conn.AccountId(), id)
		}
		r, err := NewResource(a.MqlRuntime, "aws.rds.dbcluster",
			map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
		if err != nil {
			continue
		}
		res = append(res, r)
	}
	return res, nil
}

// dbCluster resolves the DB cluster this instance belongs to, when it is
// present in this account. Standalone instances and cross-account members
// resolve to null; dbClusterIdentifier always carries the identifier.
func (a *mqlAwsRdsDbinstance) dbCluster() (*mqlAwsRdsDbcluster, error) {
	if !a.DbClusterIdentifier.IsSet() || a.DbClusterIdentifier.Data == "" {
		a.DbCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	arnVal := a.rdsSourceArn(a.DbClusterIdentifier.Data, "arn:aws:rds:%s:%s:cluster:%s")
	res, err := NewResource(a.MqlRuntime, "aws.rds.dbcluster",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.DbCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsRdsDbcluster), nil
}

// resolveSubnetRefs turns subnet ids into aws.vpc.subnet references, skipping any
// that cannot be resolved.
//
// A DB subnet group keeps listing a subnet after that subnet is deleted, so a
// dangling reference is ordinary account state rather than a failure. Returning
// an error on the first one threw away every reference that did resolve, and
// because a field error renders as the value of the enclosing collection, a query
// written as `aws.rds { instances { ... } }` lost every other field on every
// instance as well.
func resolveSubnetRefs(runtime *plugin.Runtime, region, accountID string, subnetIDs []string) []any {
	res := []any{}
	for _, id := range subnetIDs {
		if id == "" {
			continue
		}
		arn := fmt.Sprintf(subnetArnPattern, region, accountID, id)
		sub, err := NewResource(runtime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			log.Warn().Err(err).Str("subnet", id).Str("region", region).
				Msg("cannot resolve subnet reference, skipping it")
			continue
		}
		res = append(res, sub)
	}
	return res
}

func (a *mqlAwsRdsDbinstance) subnets() ([]any, error) {
	if a.cacheSubnets == nil {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ids := make([]string, 0, len(a.cacheSubnets.Subnets))
	for i := range a.cacheSubnets.Subnets {
		ids = append(ids, convert.ToValue(a.cacheSubnets.Subnets[i].SubnetIdentifier))
	}
	return resolveSubnetRefs(a.MqlRuntime, a.region, conn.AccountId(), ids), nil
}

func (a *mqlAwsRdsDbinstance) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// KmsKeyId is already an ARN from the AWS API
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRdsDbinstance) performanceInsightsKmsKey() (*mqlAwsKmsKey, error) {
	if a.cachePerformanceInsightsKmsKeyId == nil || *a.cachePerformanceInsightsKmsKeyId == "" {
		a.PerformanceInsightsKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cachePerformanceInsightsKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRdsDbinstance) activityStreamKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheActivityStreamKmsKeyId == nil || *a.cacheActivityStreamKmsKeyId == "" {
		a.ActivityStreamKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheActivityStreamKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRdsDbinstance) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsRdsDbinstance) snapshots() ([]any, error) {
	instanceId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Rds(region)
	ctx := context.Background()
	res := []any{}

	params := &rds.DescribeDBSnapshotsInput{DBInstanceIdentifier: &instanceId}
	paginator := rds.NewDescribeDBSnapshotsPaginator(svc, params)
	for paginator.HasMorePages() {
		snapshots, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range snapshots.DBSnapshots {
			// defensive: the parent instance list is already engine-filtered,
			// but keep the account-wide listing and this one consistent
			if snapshot.Engine != nil && slices.Contains(nonRdsEngines, *snapshot.Engine) {
				continue
			}
			mqlDbSnapshot, err := newMqlAwsRdsDbSnapshot(a.MqlRuntime, region, snapshot)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDbSnapshot)
		}
	}
	return res, nil
}

// snapshots lists every DB instance and DB cluster snapshot in the account,
// including snapshots whose source instance or cluster no longer exists --
// exactly the orphans a security review cares about most.
func (a *mqlAwsRds) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		res := []any{}
		svc := conn.Rds(region)

		paginator := rds.NewDescribeDBSnapshotsPaginator(svc, &rds.DescribeDBSnapshotsInput{})
		for paginator.HasMorePages() {
			snapshots, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, snapshot := range snapshots.DBSnapshots {
				// the shared RDS API also returns snapshots of non-RDS engines
				if snapshot.Engine != nil && slices.Contains(nonRdsEngines, *snapshot.Engine) {
					continue
				}
				if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(rdsTagsToMap(snapshot.TagList))) {
					continue
				}
				mqlSnapshot, err := newMqlAwsRdsDbSnapshot(a.MqlRuntime, region, snapshot)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlSnapshot)
			}
		}

		clusterPaginator := rds.NewDescribeDBClusterSnapshotsPaginator(svc, &rds.DescribeDBClusterSnapshotsInput{})
		for clusterPaginator.HasMorePages() {
			snapshots, err := clusterPaginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, snapshot := range snapshots.DBClusterSnapshots {
				// DocumentDB and Neptune cluster snapshots come through the same
				// API; they are not RDS assets
				if snapshot.Engine != nil && slices.Contains(nonRdsEngines, *snapshot.Engine) {
					continue
				}
				if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(rdsTagsToMap(snapshot.TagList))) {
					continue
				}
				mqlSnapshot, err := newMqlAwsRdsClusterSnapshot(a.MqlRuntime, region, snapshot)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlSnapshot)
			}
		}
		return res, nil
	})
}

// initAwsRdsSnapshot resolves a single snapshot from its ARN, so aws.rds.snapshot
// works in per-asset scans of aws-rds-snapshot assets.
func initAwsRdsSnapshot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformRdsSnapshot); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch rds snapshot")
	}
	arnVal := args["arn"].Value.(string)

	if cached := cachedByArn(runtime, ResourceAwsRdsSnapshot, arnVal); cached != nil {
		return args, cached, nil
	}

	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, errors.New("invalid arn for rds snapshot: " + arnVal)
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Rds(parsed.Region)
	ctx := context.Background()

	switch {
	case strings.HasPrefix(parsed.Resource, "cluster-snapshot:"):
		id := strings.TrimPrefix(parsed.Resource, "cluster-snapshot:")
		resp, err := svc.DescribeDBClusterSnapshots(ctx, &rds.DescribeDBClusterSnapshotsInput{DBClusterSnapshotIdentifier: &id})
		if err != nil {
			return nil, nil, err
		}
		if len(resp.DBClusterSnapshots) > 0 {
			snapshot, err := newMqlAwsRdsClusterSnapshot(runtime, parsed.Region, resp.DBClusterSnapshots[0])
			if err != nil {
				return nil, nil, err
			}
			return args, snapshot, nil
		}
	case strings.HasPrefix(parsed.Resource, "snapshot:"):
		id := strings.TrimPrefix(parsed.Resource, "snapshot:")
		resp, err := svc.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{DBSnapshotIdentifier: &id})
		if err != nil {
			return nil, nil, err
		}
		if len(resp.DBSnapshots) > 0 {
			snapshot, err := newMqlAwsRdsDbSnapshot(runtime, parsed.Region, resp.DBSnapshots[0])
			if err != nil {
				return nil, nil, err
			}
			return args, snapshot, nil
		}
	}
	return nil, nil, errors.New("rds snapshot does not exist")
}

// pendingMaintenanceActions returns all pending maintenance actions for the RDS instance
func (a *mqlAwsRdsDbinstance) pendingMaintenanceActions() ([]any, error) {
	return rdsPendingMaintenanceActions(a.MqlRuntime, a.Region.Data, a.Arn.Data)
}

// pendingMaintenanceActions returns all pending maintenance actions for the RDS cluster.
func (a *mqlAwsRdsDbcluster) pendingMaintenanceActions() ([]any, error) {
	return rdsPendingMaintenanceActions(a.MqlRuntime, a.Region.Data, a.Arn.Data)
}

func rdsPendingMaintenanceActions(runtime *plugin.Runtime, region string, resourceArn string) ([]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Rds(region)
	ctx := context.Background()
	res := []any{}

	params := &rds.DescribePendingMaintenanceActionsInput{ResourceIdentifier: &resourceArn}
	paginator := rds.NewDescribePendingMaintenanceActionsPaginator(svc, params)
	for paginator.HasMorePages() {
		pendingMaintenanceList, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Str("resource", resourceArn).Msg("error accessing RDS pending maintenance actions")
				return res, nil
			}
			return nil, err
		}
		for _, resp := range pendingMaintenanceList.PendingMaintenanceActions {
			if resp.ResourceIdentifier == nil {
				continue
			}
			for _, action := range resp.PendingMaintenanceActionDetails {
				mqlPendingAction, err := newMqlAwsPendingMaintenanceAction(runtime, *resp.ResourceIdentifier, action)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlPendingAction)
			}
		}
	}
	return res, nil
}

func (a *mqlAwsRdsDbinstance) recommendations() ([]any, error) {
	if a.DbiResourceId.Data == "" {
		return []any{}, nil
	}
	return rdsRecommendations(a.MqlRuntime, a.Region.Data, a.Arn.Data, "dbi-resource-id", a.DbiResourceId.Data)
}

func (a *mqlAwsRdsDbcluster) recommendations() ([]any, error) {
	if a.cacheDbClusterResourceId == "" {
		return []any{}, nil
	}
	return rdsRecommendations(a.MqlRuntime, a.Region.Data, a.Arn.Data, "cluster-resource-id", a.cacheDbClusterResourceId)
}

func rdsRecommendations(runtime *plugin.Runtime, region string, parentArn string, filterName string, filterValue string) ([]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Rds(region)
	ctx := context.Background()
	res := []any{}

	params := &rds.DescribeDBRecommendationsInput{
		Filters: []rds_types.Filter{{
			Name:   &filterName,
			Values: []string{filterValue},
		}},
	}
	paginator := rds.NewDescribeDBRecommendationsPaginator(svc, params)
	recommendationIndex := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Str("resource", parentArn).Msg("error accessing RDS recommendations")
				return res, nil
			}
			return nil, err
		}
		for _, recommendation := range page.DBRecommendations {
			mqlRecommendation, err := newMqlAwsRdsRecommendation(runtime, parentArn, recommendationIndex, recommendation)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRecommendation)
			recommendationIndex++
		}
	}
	return res, nil
}

// newMqlAwsPendingMaintenanceAction creates a new mqlAwsRdsPendingMaintenanceActions from a rds_types.PendingMaintenanceAction
func newMqlAwsPendingMaintenanceAction(runtime *plugin.Runtime, resourceArn string, maintenanceAction rds_types.PendingMaintenanceAction) (*mqlAwsRdsPendingMaintenanceAction, error) {
	action := ""
	if maintenanceAction.Action != nil {
		action = *maintenanceAction.Action
	}

	res, err := CreateResource(runtime, ResourceAwsRdsPendingMaintenanceAction,
		map[string]*llx.RawData{
			"__id":                 llx.StringData(fmt.Sprintf("%s/pendingMaintainance/%s", resourceArn, action)),
			"resourceArn":          llx.StringData(resourceArn),
			"action":               llx.StringDataPtr(maintenanceAction.Action),
			"description":          llx.StringDataPtr(maintenanceAction.Description),
			"autoAppliedAfterDate": llx.TimeDataPtr(maintenanceAction.AutoAppliedAfterDate),
			"currentApplyDate":     llx.TimeDataPtr(maintenanceAction.CurrentApplyDate),
			"forcedApplyDate":      llx.TimeDataPtr(maintenanceAction.ForcedApplyDate),
			"optInStatus":          llx.StringDataPtr(maintenanceAction.OptInStatus),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRdsPendingMaintenanceAction), nil
}

func newMqlAwsRdsRecommendation(runtime *plugin.Runtime, parentArn string, index int, recommendation rds_types.DBRecommendation) (*mqlAwsRdsRecommendation, error) {
	recommendationID := convert.ToValue(recommendation.RecommendationId)
	cacheID := recommendationID
	if cacheID == "" {
		cacheID = convert.ToValue(recommendation.TypeId)
	}
	if cacheID == "" {
		cacheID = fmt.Sprintf("%d", index)
	}

	links := make([]any, 0, len(recommendation.Links))
	for _, link := range recommendation.Links {
		links = append(links, map[string]any{
			"text": convert.ToValue(link.Text),
			"url":  convert.ToValue(link.Url),
		})
	}

	actions := make([]any, 0, len(recommendation.RecommendedActions))
	for i, action := range recommendation.RecommendedActions {
		mqlAction, err := newMqlAwsRdsRecommendedAction(runtime, parentArn, cacheID, i, action)
		if err != nil {
			return nil, err
		}
		actions = append(actions, mqlAction)
	}

	res, err := CreateResource(runtime, ResourceAwsRdsRecommendation,
		map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("%s/recommendation/%s", parentArn, cacheID)),
			"id":                 llx.StringDataPtr(recommendation.RecommendationId),
			"typeId":             llx.StringDataPtr(recommendation.TypeId),
			"severity":           llx.StringDataPtr(recommendation.Severity),
			"status":             llx.StringDataPtr(recommendation.Status),
			"createdAt":          llx.TimeDataPtr(recommendation.CreatedTime),
			"updatedAt":          llx.TimeDataPtr(recommendation.UpdatedTime),
			"detection":          llx.StringDataPtr(recommendation.Detection),
			"recommendation":     llx.StringDataPtr(recommendation.Recommendation),
			"description":        llx.StringDataPtr(recommendation.Description),
			"reason":             llx.StringDataPtr(recommendation.Reason),
			"impact":             llx.StringDataPtr(recommendation.Impact),
			"category":           llx.StringDataPtr(recommendation.Category),
			"source":             llx.StringDataPtr(recommendation.Source),
			"typeDetection":      llx.StringDataPtr(recommendation.TypeDetection),
			"typeRecommendation": llx.StringDataPtr(recommendation.TypeRecommendation),
			"additionalInfo":     llx.StringDataPtr(recommendation.AdditionalInfo),
			"links":              llx.ArrayData(links, types.Dict),
			"actions":            llx.ArrayData(actions, types.Resource(ResourceAwsRdsRecommendationAction)),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRdsRecommendation), nil
}

func newMqlAwsRdsRecommendedAction(runtime *plugin.Runtime, parentArn string, recommendationID string, index int, action rds_types.RecommendedAction) (*mqlAwsRdsRecommendationAction, error) {
	actionID := convert.ToValue(action.ActionId)
	cacheID := actionID
	if cacheID == "" {
		cacheID = fmt.Sprintf("%d", index)
	}

	parameters := map[string]any{}
	for _, parameter := range action.Parameters {
		key := convert.ToValue(parameter.Key)
		if key != "" {
			parameters[key] = convert.ToValue(parameter.Value)
		}
	}
	contextAttributes := map[string]any{}
	for _, attribute := range action.ContextAttributes {
		key := convert.ToValue(attribute.Key)
		if key != "" {
			contextAttributes[key] = convert.ToValue(attribute.Value)
		}
	}

	res, err := CreateResource(runtime, ResourceAwsRdsRecommendationAction,
		map[string]*llx.RawData{
			"__id":              llx.StringData(fmt.Sprintf("%s/recommendation/%s/action/%s", parentArn, recommendationID, cacheID)),
			"id":                llx.StringDataPtr(action.ActionId),
			"title":             llx.StringDataPtr(action.Title),
			"description":       llx.StringDataPtr(action.Description),
			"operation":         llx.StringDataPtr(action.Operation),
			"parameters":        llx.MapData(parameters, types.String),
			"applyModes":        llx.ArrayData(stringSliceToAny(action.ApplyModes), types.String),
			"status":            llx.StringDataPtr(action.Status),
			"contextAttributes": llx.MapData(contextAttributes, types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRdsRecommendationAction), nil
}

func masterUserSecretToDict(secret *rds_types.MasterUserSecret) any {
	if secret == nil {
		return nil
	}
	result := map[string]any{}
	if secret.SecretArn != nil {
		result["secretArn"] = *secret.SecretArn
	}
	if secret.KmsKeyId != nil {
		result["kmsKeyId"] = *secret.KmsKeyId
	}
	if secret.SecretStatus != nil {
		result["secretStatus"] = *secret.SecretStatus
	}
	return result
}

func rdsTagsToMap(tags []rds_types.Tag) map[string]any {
	return tagsToMap(tags, func(t rds_types.Tag) *string { return t.Key }, func(t rds_types.Tag) *string { return t.Value })
}

// clusters returns all RDS clusters
func (a *mqlAwsRds) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getDbClusters>calling aws with region %s", region)

		res := []any{}
		svc := conn.Rds(region)

		params := &rds.DescribeDBClustersInput{}
		paginator := rds.NewDescribeDBClustersPaginator(svc, params)
		for paginator.HasMorePages() {
			dbClusters, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, cluster := range dbClusters.DBClusters {
				// we cannot filter it in the api call since the api does not support it negative filters
				if cluster.Engine != nil && slices.Contains(nonRdsEngines, *cluster.Engine) {
					log.Debug().Str("engine", *cluster.Engine).Msg("skipping non-RDS engine")
					continue
				}

				if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(rdsTagsToMap(cluster.TagList))) {
					log.Debug().Interface("cluster", cluster.DBClusterArn).Msg("skipping rds cluster due to filters")
					continue
				}

				mqlDbCluster, err := newMqlAwsRdsCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlDbCluster)
			}
		}
		return res, nil
	})
}

type mqlAwsRdsDbclusterInternal struct {
	securityGroupIdHandler
	cacheKmsKeyId               *string
	cacheActivityStreamKmsKeyId *string
	cacheDbClusterResourceId    string
	cacheMonitoringRoleArn      string
	cacheParameterGroupName     string
	cacheAccountID              string
}

const rdsClusterParameterGroupArnPattern = "arn:aws:rds:%s:%s:cluster-pg:%s"

func (a *mqlAwsRdsDbcluster) id() (string, error) {
	return a.Arn.Data, nil
}

func newMqlAwsRdsCluster(runtime *plugin.Runtime, region string, accountID string, cluster rds_types.DBCluster) (*mqlAwsRdsDbcluster, error) {
	mqlRdsDbInstances := []any{}
	for _, instance := range cluster.DBClusterMembers {
		memberID := convert.ToValue(instance.DBInstanceIdentifier)
		mqlInstance, err := NewResource(runtime, ResourceAwsRdsDbinstance,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(rdsInstanceArnPattern, region, accountID, memberID)),
			})
		if err != nil {
			// DescribeDBClusters reports members that DescribeDBInstances may not
			// return - one still being created or deleted, or one filtered out
			// because instance tags differ from the cluster's. Losing the cluster
			// entirely over one member is far worse than losing the member.
			log.Warn().Err(err).Str("member", memberID).Str("region", region).
				Msg("cannot resolve rds cluster member, skipping it")
			continue
		}
		mqlRdsDbInstances = append(mqlRdsDbInstances, mqlInstance)
	}
	sgsArns := []string{}
	for i := range cluster.VpcSecurityGroups {
		sgsArns = append(sgsArns, NewSecurityGroupArn(region, accountID, convert.ToValue(cluster.VpcSecurityGroups[i].VpcSecurityGroupId)))
	}
	stringSliceAZs := []any{}
	for _, zone := range cluster.AvailabilityZones {
		stringSliceAZs = append(stringSliceAZs, zone)
	}

	var certificateExpiration *time.Time
	var caIdentifier *string
	if cluster.CertificateDetails != nil {
		certificateExpiration = cluster.CertificateDetails.ValidTill
		caIdentifier = cluster.CertificateDetails.CAIdentifier
	}

	resource, err := CreateResource(runtime, ResourceAwsRdsDbcluster,
		map[string]*llx.RawData{
			"activityStreamMode":                 llx.StringData(string(cluster.ActivityStreamMode)),
			"activityStreamStatus":               llx.StringData(string(cluster.ActivityStreamStatus)),
			"arn":                                llx.StringDataPtr(cluster.DBClusterArn),
			"autoMinorVersionUpgrade":            llx.BoolDataPtr(cluster.AutoMinorVersionUpgrade),
			"availabilityZones":                  llx.ArrayData(stringSliceAZs, types.String),
			"backupRetentionPeriod":              llx.IntDataDefault(cluster.BackupRetentionPeriod, 0),
			"certificateAuthority":               llx.StringDataPtr(caIdentifier),
			"certificateExpiresAt":               llx.TimeDataPtr(certificateExpiration),
			"clusterDbInstanceClass":             llx.StringDataPtr(cluster.DBClusterInstanceClass),
			"createdAt":                          llx.TimeDataPtr(cluster.ClusterCreateTime),
			"databaseInsightsMode":               llx.StringData(string(cluster.DatabaseInsightsMode)),
			"deletionProtection":                 llx.BoolDataPtr(cluster.DeletionProtection),
			"endpoint":                           llx.StringDataPtr(cluster.Endpoint),
			"engine":                             llx.StringDataPtr(cluster.Engine),
			"engineLifecycleSupport":             llx.StringDataPtr(cluster.EngineLifecycleSupport),
			"engineVersion":                      llx.StringDataPtr(cluster.EngineVersion),
			"globalClusterIdentifier":            llx.StringDataPtr(cluster.GlobalClusterIdentifier),
			"hostedZoneId":                       llx.StringDataPtr(cluster.HostedZoneId),
			"httpEndpointEnabled":                llx.BoolDataPtr(cluster.HttpEndpointEnabled),
			"iamDatabaseAuthentication":          llx.BoolDataPtr(cluster.IAMDatabaseAuthenticationEnabled),
			"id":                                 llx.StringDataPtr(cluster.DBClusterIdentifier),
			"latestRestorableTime":               llx.TimeDataPtr(cluster.LatestRestorableTime),
			"masterUsername":                     llx.StringDataPtr(cluster.MasterUsername),
			"members":                            llx.ArrayData(mqlRdsDbInstances, types.Resource(ResourceAwsRdsDbinstance)),
			"monitoringInterval":                 llx.IntDataPtr(cluster.MonitoringInterval),
			"multiAZ":                            llx.BoolDataPtr(cluster.MultiAZ),
			"networkType":                        llx.StringDataPtr(cluster.NetworkType),
			"parameterGroupName":                 llx.StringDataPtr(cluster.DBClusterParameterGroup),
			"port":                               llx.IntDataDefault(cluster.Port, -1),
			"preferredBackupWindow":              llx.StringDataPtr(cluster.PreferredBackupWindow),
			"preferredMaintenanceWindow":         llx.StringDataPtr(cluster.PreferredMaintenanceWindow),
			"publiclyAccessible":                 llx.BoolDataPtr(cluster.PubliclyAccessible),
			"region":                             llx.StringData(region),
			"status":                             llx.StringDataPtr(cluster.Status),
			"storageAllocated":                   llx.IntDataDefault(cluster.AllocatedStorage, 0),
			"storageEncrypted":                   llx.BoolDataPtr(cluster.StorageEncrypted),
			"storageEncryptionType":              llx.StringData(string(cluster.StorageEncryptionType)),
			"storageIops":                        llx.IntDataDefault(cluster.Iops, 0),
			"storageType":                        llx.StringDataPtr(cluster.StorageType),
			"tags":                               llx.MapData(rdsTagsToMap(cluster.TagList), types.String),
			"performanceInsightsEnabled":         llx.BoolDataPtr(cluster.PerformanceInsightsEnabled),
			"performanceInsightsRetentionPeriod": llx.IntDataDefault(cluster.PerformanceInsightsRetentionPeriod, 0),
			"engineMode":                         llx.StringDataPtr(cluster.EngineMode),
			"earliestRestorableTime":             llx.TimeDataPtr(cluster.EarliestRestorableTime),
			"masterUserSecret":                   llx.DictData(masterUserSecretToDict(cluster.MasterUserSecret)),
			"copyTagsToSnapshot":                 llx.BoolDataPtr(cluster.CopyTagsToSnapshot),
			"databaseName":                       llx.StringDataPtr(cluster.DatabaseName),
			"crossAccountClone":                  llx.BoolDataPtr(cluster.CrossAccountClone),
			"cloneGroupId":                       llx.StringDataPtr(cluster.CloneGroupId),
			"replicationSourceIdentifier":        llx.StringDataPtr(cluster.ReplicationSourceIdentifier),
			"globalWriteForwardingStatus":        llx.StringData(string(cluster.GlobalWriteForwardingStatus)),
			"upgradeRolloutOrder":                llx.StringData(string(cluster.UpgradeRolloutOrder)),
			"readReplicaClusterIds":              llx.ArrayData(stringSliceToAny(cluster.ReadReplicaIdentifiers), types.String),
			"backtrackWindow":                    llx.IntDataDefault(cluster.BacktrackWindow, 0),
			"earliestBacktrackTime":              llx.TimeDataPtr(cluster.EarliestBacktrackTime),
		})
	if err != nil {
		return nil, err
	}
	mqlDbCluster := resource.(*mqlAwsRdsDbcluster)
	mqlDbCluster.cacheKmsKeyId = cluster.KmsKeyId
	mqlDbCluster.cacheActivityStreamKmsKeyId = cluster.ActivityStreamKmsKeyId
	mqlDbCluster.cacheDbClusterResourceId = convert.ToValue(cluster.DbClusterResourceId)
	mqlDbCluster.cacheMonitoringRoleArn = convert.ToValue(cluster.MonitoringRoleArn)
	mqlDbCluster.cacheParameterGroupName = convert.ToValue(cluster.DBClusterParameterGroup)
	mqlDbCluster.cacheAccountID = accountID
	mqlDbCluster.setSecurityGroupArns(sgsArns)
	return mqlDbCluster, nil
}

func (a *mqlAwsRdsDbcluster) monitoringRole() (*mqlAwsIamRole, error) {
	if a.cacheMonitoringRoleArn == "" {
		a.MonitoringRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheMonitoringRoleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsRdsDbcluster) dbClusterParameterGroup() (*mqlAwsRdsClusterParameterGroup, error) {
	if a.cacheParameterGroupName == "" {
		a.DbClusterParameterGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	region := a.Region.Data
	arn := fmt.Sprintf(rdsClusterParameterGroupArnPattern, region, a.cacheAccountID, a.cacheParameterGroupName)
	pgID := arn + "/" + a.cacheParameterGroupName
	mqlPg, err := NewResource(a.MqlRuntime, ResourceAwsRdsClusterParameterGroup,
		map[string]*llx.RawData{
			"__id":   llx.StringData(pgID),
			"arn":    llx.StringData(arn),
			"name":   llx.StringData(a.cacheParameterGroupName),
			"region": llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return mqlPg.(*mqlAwsRdsClusterParameterGroup), nil
}

func (a *mqlAwsRdsDbcluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsRdsDbcluster) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// KmsKeyId is already an ARN from the AWS API
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRdsDbcluster) activityStreamKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheActivityStreamKmsKeyId == nil || *a.cacheActivityStreamKmsKeyId == "" {
		a.ActivityStreamKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheActivityStreamKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRdsDbcluster) snapshots() ([]any, error) {
	dbClusterId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Rds(region)
	ctx := context.Background()
	res := []any{}

	params := &rds.DescribeDBClusterSnapshotsInput{DBClusterIdentifier: &dbClusterId}
	paginator := rds.NewDescribeDBClusterSnapshotsPaginator(svc, params)
	for paginator.HasMorePages() {
		snapshots, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range snapshots.DBClusterSnapshots {
			// defensive: the parent cluster list is already engine-filtered,
			// but keep the account-wide listing and this one consistent
			if snapshot.Engine != nil && slices.Contains(nonRdsEngines, *snapshot.Engine) {
				continue
			}
			mqlDbSnapshot, err := newMqlAwsRdsClusterSnapshot(a.MqlRuntime, region, snapshot)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDbSnapshot)
		}
	}
	return res, nil
}

// newMqlAwsRdsClusterSnapshot creates a new mqlAwsRdsSnapshot from a rds_types.DBClusterSnapshot which is only
// used for Aurora clusters not for RDS instances
func newMqlAwsRdsClusterSnapshot(runtime *plugin.Runtime, region string, snapshot rds_types.DBClusterSnapshot) (*mqlAwsRdsSnapshot, error) {
	res, err := CreateResource(runtime, ResourceAwsRdsSnapshot,
		map[string]*llx.RawData{
			"allocatedStorage":      llx.IntDataDefault(snapshot.AllocatedStorage, 0),
			"arn":                   llx.StringDataPtr(snapshot.DBClusterSnapshotArn),
			"availabilityZone":      llx.StringData(""),
			"backupRetentionPeriod": llx.IntDataDefault(snapshot.BackupRetentionPeriod, 0),
			"createdAt":             llx.TimeDataPtr(snapshot.SnapshotCreateTime),
			"encrypted":             llx.BoolDataPtr(snapshot.StorageEncrypted),
			"storageEncryptionType": llx.StringData(string(snapshot.StorageEncryptionType)),
			"engine":                llx.StringDataPtr(snapshot.Engine),
			"engineVersion":         llx.StringDataPtr(snapshot.EngineVersion),
			"id":                    llx.StringDataPtr(snapshot.DBClusterSnapshotIdentifier),
			"port":                  llx.IntDataDefault(snapshot.Port, -1),
			"preferredBackupWindow": llx.StringDataPtr(snapshot.PreferredBackupWindow),
			"isClusterSnapshot":     llx.BoolData(true),
			"region":                llx.StringData(region),
			"status":                llx.StringDataPtr(snapshot.Status),
			"tags":                  llx.MapData(rdsTagsToMap(snapshot.TagList), types.String),
			"timezone":              llx.StringData(""),
			"type":                  llx.StringDataPtr(snapshot.SnapshotType),
			"sourceSnapshot":        llx.StringDataPtr(snapshot.SourceDBClusterSnapshotArn),
			"sourceRegion":          llx.StringData(""),
			"originalCreatedAt":     llx.NilData,
		})
	if err != nil {
		return nil, err
	}
	mqlSnapshot := res.(*mqlAwsRdsSnapshot)
	mqlSnapshot.cacheKmsKeyId = snapshot.KmsKeyId
	mqlSnapshot.cacheSourceDbClusterId = snapshot.DBClusterIdentifier
	return mqlSnapshot, nil
}

// newMqlAwsRdsDbSnapshot creates a new mqlAwsRdsSnapshot from a rds_types.DBSnapshot which is only
// used for Aurora clusters not for RDS instances
func newMqlAwsRdsDbSnapshot(runtime *plugin.Runtime, region string, snapshot rds_types.DBSnapshot) (*mqlAwsRdsSnapshot, error) {
	res, err := CreateResource(runtime, ResourceAwsRdsSnapshot,
		map[string]*llx.RawData{
			"allocatedStorage":      llx.IntDataDefault(snapshot.AllocatedStorage, 0),
			"arn":                   llx.StringDataPtr(snapshot.DBSnapshotArn),
			"availabilityZone":      llx.StringDataPtr(snapshot.AvailabilityZone),
			"backupRetentionPeriod": llx.IntDataDefault(snapshot.BackupRetentionPeriod, 0),
			"createdAt":             llx.TimeDataPtr(snapshot.SnapshotCreateTime),
			"encrypted":             llx.BoolDataPtr(snapshot.Encrypted),
			"storageEncryptionType": llx.StringData(string(snapshot.StorageEncryptionType)),
			"engine":                llx.StringDataPtr(snapshot.Engine),
			"engineVersion":         llx.StringDataPtr(snapshot.EngineVersion),
			"id":                    llx.StringDataPtr(snapshot.DBSnapshotIdentifier),
			"port":                  llx.IntDataDefault(snapshot.Port, -1),
			"preferredBackupWindow": llx.StringDataPtr(snapshot.PreferredBackupWindow),
			"isClusterSnapshot":     llx.BoolData(false),
			"region":                llx.StringData(region),
			"status":                llx.StringDataPtr(snapshot.Status),
			"tags":                  llx.MapData(rdsTagsToMap(snapshot.TagList), types.String),
			"timezone":              llx.StringDataPtr(snapshot.Timezone),
			"type":                  llx.StringDataPtr(snapshot.SnapshotType),
			"sourceSnapshot":        llx.StringDataPtr(snapshot.SourceDBSnapshotIdentifier),
			"sourceRegion":          llx.StringDataPtr(snapshot.SourceRegion),
			"originalCreatedAt":     llx.TimeDataPtr(snapshot.OriginalSnapshotCreateTime),
		})
	if err != nil {
		return nil, err
	}
	mqlSnapshot := res.(*mqlAwsRdsSnapshot)
	mqlSnapshot.cacheKmsKeyId = snapshot.KmsKeyId
	mqlSnapshot.cacheSourceDbInstanceId = snapshot.DBInstanceIdentifier
	return mqlSnapshot, nil
}

func (a *mqlAwsRdsSnapshot) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsRdsSnapshotInternal struct {
	cacheKmsKeyId           *string
	cacheSourceDbInstanceId *string
	cacheSourceDbClusterId  *string
}

// sourceDbInstance resolves the DB instance this snapshot was taken from, when
// it is present in this account. Cluster snapshots and instances no longer in
// the inventory resolve to null.
func (a *mqlAwsRdsSnapshot) sourceDbInstance() (*mqlAwsRdsDbinstance, error) {
	if a.cacheSourceDbInstanceId == nil || *a.cacheSourceDbInstanceId == "" {
		a.SourceDbInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := *a.cacheSourceDbInstanceId
	if !strings.HasPrefix(arnVal, "arn:") {
		arnVal = fmt.Sprintf(rdsInstanceArnPattern, a.Region.Data, conn.AccountId(), arnVal)
	}
	res, err := NewResource(a.MqlRuntime, "aws.rds.dbinstance",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.SourceDbInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsRdsDbinstance), nil
}

// sourceDbCluster resolves the DB cluster this snapshot was taken from, when it
// is present in this account.
func (a *mqlAwsRdsSnapshot) sourceDbCluster() (*mqlAwsRdsDbcluster, error) {
	if a.cacheSourceDbClusterId == nil || *a.cacheSourceDbClusterId == "" {
		a.SourceDbCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := *a.cacheSourceDbClusterId
	if !strings.HasPrefix(arnVal, "arn:") {
		arnVal = fmt.Sprintf("arn:aws:rds:%s:%s:cluster:%s", a.Region.Data, conn.AccountId(), arnVal)
	}
	res, err := NewResource(a.MqlRuntime, "aws.rds.dbcluster",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.SourceDbCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsRdsDbcluster), nil
}

func (a *mqlAwsRdsSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// KmsKeyId is already an ARN from the AWS API
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// id returns the parent-qualified cache key set at construction. It must not
// fall back to `target`, which is the backup *location* ("region" for almost
// every instance) and therefore identical across the whole account.
func (a *mqlAwsRdsBackupsetting) id() (string, error) {
	return a.__id, nil
}

type mqlAwsRdsBackupsettingInternal struct {
	kmsKeyId *string
}

func (a *mqlAwsRdsBackupsetting) kmsKey() (*mqlAwsKmsKey, error) {
	if a.kmsKeyId == nil {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.kmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsRdsDbinstance) backupSettings() ([]any, error) {
	instanceId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Rds(region)
	ctx := context.Background()
	res := []any{}
	params := &rds.DescribeDBInstanceAutomatedBackupsInput{DBInstanceIdentifier: &instanceId}
	paginator := rds.NewDescribeDBInstanceAutomatedBackupsPaginator(svc, params)
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		var respErr *http.ResponseError
		if err != nil {
			if errors.As(err, &respErr) {
				if respErr.HTTPStatusCode() == 404 {
					return nil, nil
				}
			}
			return nil, err
		}
		for _, backup := range resp.DBInstanceAutomatedBackups {
			var earliest *time.Time
			var latest *time.Time
			if backup.RestoreWindow != nil {
				earliest = backup.RestoreWindow.EarliestTime
				latest = backup.RestoreWindow.LatestTime
			}
			mqlRdsBackup, err := CreateResource(a.MqlRuntime, ResourceAwsRdsBackupsetting,
				map[string]*llx.RawData{
					"__id":                     llx.StringData(a.Arn.Data + "/backupsetting/" + convert.ToValue(backup.DbiResourceId)),
					"target":                   llx.StringDataPtr(backup.BackupTarget),
					"retentionPeriod":          llx.IntDataPtr(backup.BackupRetentionPeriod),
					"dedicatedLogVolume":       llx.BoolDataPtr(backup.DedicatedLogVolume),
					"encrypted":                llx.BoolDataPtr(backup.Encrypted),
					"region":                   llx.StringData(region),
					"status":                   llx.StringDataPtr(backup.Status),
					"timezone":                 llx.StringDataPtr(backup.Timezone),
					"earliestRestoreAvailable": llx.TimeDataPtr(earliest),
					"latestRestoreAvailable":   llx.TimeDataPtr(latest),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRdsBackup)
			mqlRdsBackup.(*mqlAwsRdsBackupsetting).kmsKeyId = backup.KmsKeyId
		}
	}
	return res, nil
}

func (a *mqlAwsRdsDbcluster) backupSettings() ([]any, error) {
	clusterId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Rds(region)
	ctx := context.Background()
	res := []any{}

	params := &rds.DescribeDBClusterAutomatedBackupsInput{DBClusterIdentifier: &clusterId}
	paginator := rds.NewDescribeDBClusterAutomatedBackupsPaginator(svc, params)
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		var respErr *http.ResponseError
		if err != nil {
			if errors.As(err, &respErr) {
				if respErr.HTTPStatusCode() == 404 {
					return nil, nil
				}
			}
			return nil, err
		}
		for _, backup := range resp.DBClusterAutomatedBackups {
			var earliest *time.Time
			var latest *time.Time
			if backup.RestoreWindow != nil {
				earliest = backup.RestoreWindow.EarliestTime
				latest = backup.RestoreWindow.LatestTime
			}
			mqlRdsBackup, err := CreateResource(a.MqlRuntime, ResourceAwsRdsBackupsetting,
				map[string]*llx.RawData{
					"__id":                     llx.StringData(a.Arn.Data + "/backupsetting/" + convert.ToValue(backup.DbClusterResourceId)),
					"target":                   llx.StringDataPtr(backup.DBClusterIdentifier),
					"retentionPeriod":          llx.IntDataPtr(backup.BackupRetentionPeriod),
					"dedicatedLogVolume":       llx.NilData,
					"encrypted":                llx.BoolDataPtr(backup.StorageEncrypted),
					"region":                   llx.StringData(region),
					"status":                   llx.StringDataPtr(backup.Status),
					"timezone":                 llx.NilData,
					"earliestRestoreAvailable": llx.TimeDataPtr(earliest),
					"latestRestoreAvailable":   llx.TimeDataPtr(latest),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRdsBackup)
			mqlRdsBackup.(*mqlAwsRdsBackupsetting).kmsKeyId = backup.KmsKeyId
		}
	}
	return res, nil
}

func (a *mqlAwsRdsSnapshot) attributes() ([]any, error) {
	snapshotId := a.Id.Data
	region := a.Region.Data
	isCluster := a.IsClusterSnapshot.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Rds(region)
	ctx := context.Background()
	if isCluster == true {
		snapshotAttributes, err := svc.DescribeDBClusterSnapshotAttributes(ctx, &rds.DescribeDBClusterSnapshotAttributesInput{DBClusterSnapshotIdentifier: &snapshotId})
		if err != nil {
			return nil, err
		}
		if snapshotAttributes == nil || snapshotAttributes.DBClusterSnapshotAttributesResult == nil {
			return []any{}, nil
		}
		return convert.JsonToDictSlice(snapshotAttributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes)
	}
	snapshotAttributes, err := svc.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: &snapshotId})
	if err != nil {
		return nil, err
	}
	if snapshotAttributes == nil || snapshotAttributes.DBSnapshotAttributesResult == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(snapshotAttributes.DBSnapshotAttributesResult.DBSnapshotAttributes)
}

// restoreAttributes re-keys the name/value pair list RDS returns into a map of
// attribute name to its values. Cluster and instance snapshots come back from
// two different API calls with two different result shapes, so both branches
// have to be walked to answer "who may restore this".
func (a *mqlAwsRdsSnapshot) restoreAttributes() (map[string]any, error) {
	snapshotId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Rds(region)
	ctx := context.Background()
	if a.IsClusterSnapshot.Data {
		out, err := svc.DescribeDBClusterSnapshotAttributes(ctx, &rds.DescribeDBClusterSnapshotAttributesInput{DBClusterSnapshotIdentifier: &snapshotId})
		if err != nil {
			return nil, err
		}
		if out == nil || out.DBClusterSnapshotAttributesResult == nil {
			return map[string]any{}, nil
		}
		return rdsSnapshotAttributeMap(out.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes,
			func(a rds_types.DBClusterSnapshotAttribute) (*string, []string) {
				return a.AttributeName, a.AttributeValues
			}), nil
	}
	out, err := svc.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: &snapshotId})
	if err != nil {
		return nil, err
	}
	if out == nil || out.DBSnapshotAttributesResult == nil {
		return map[string]any{}, nil
	}
	return rdsSnapshotAttributeMap(out.DBSnapshotAttributesResult.DBSnapshotAttributes,
		func(a rds_types.DBSnapshotAttribute) (*string, []string) { return a.AttributeName, a.AttributeValues }), nil
}

// rdsSnapshotAttributeMap re-keys a snapshot attribute pair list into a map of
// attribute name to its values. An attribute with no name is dropped: it can
// key nothing, and an empty-string key would read as a real attribute named "".
func rdsSnapshotAttributeMap[T any](attrs []T, split func(T) (*string, []string)) map[string]any {
	res := map[string]any{}
	for _, attr := range attrs {
		name, values := split(attr)
		if name == nil {
			continue
		}
		res[*name] = stringsToAnyArray(values)
	}
	return res
}

// isPublic reports whether the snapshot is shared with all AWS accounts, which
// makes it restorable by anyone. RDS exposes this through the "restore" attribute
// carrying the special value "all" in its list of authorized accounts.
func (a *mqlAwsRdsSnapshot) isPublic() (bool, error) {
	result := a.GetAttributes()
	if result.Error != nil {
		return false, result.Error
	}
	for _, attr := range result.Data {
		attrMap, ok := attr.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := attrMap["AttributeName"].(string); !ok || name != "restore" {
			continue
		}
		values, ok := attrMap["AttributeValues"].([]any)
		if !ok {
			continue
		}
		for _, v := range values {
			if account, ok := v.(string); ok && account == "all" {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *mqlAwsRds) proxies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("rds>getProxies>calling aws with region %s", region)

		res := []any{}
		svc := conn.Rds(region)

		paginator := rds.NewDescribeDBProxiesPaginator(svc, &rds.DescribeDBProxiesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if IsServiceNotAvailableInRegionError(err) {
					log.Debug().Str("region", region).Msg("rds proxy service not available in region")
					return res, nil
				}
				return nil, err
			}
			for _, proxy := range page.DBProxies {
				mqlProxy, err := newMqlAwsRdsProxy(a.MqlRuntime, region, conn.AccountId(), proxy)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProxy)
			}
		}
		return res, nil
	})
}

func newMqlAwsRdsProxy(runtime *plugin.Runtime, region string, accountID string, proxy rds_types.DBProxy) (*mqlAwsRdsProxy, error) {
	// Build security group ARNs
	sgs := []string{}
	for _, sgId := range proxy.VpcSecurityGroupIds {
		sgs = append(sgs, NewSecurityGroupArn(region, accountID, sgId))
	}

	resource, err := CreateResource(runtime, "aws.rds.proxy",
		map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(proxy.DBProxyArn),
			"arn":                 llx.StringDataPtr(proxy.DBProxyArn),
			"name":                llx.StringDataPtr(proxy.DBProxyName),
			"region":              llx.StringData(region),
			"debugLogging":        llx.BoolDataPtr(proxy.DebugLogging),
			"endpoint":            llx.StringDataPtr(proxy.Endpoint),
			"endpointNetworkType": llx.StringData(string(proxy.EndpointNetworkType)),
			"engineFamily":        llx.StringDataPtr(proxy.EngineFamily),
			"idleClientTimeout":   llx.IntDataDefault(proxy.IdleClientTimeout, 0),
			"requireTLS":          llx.BoolDataPtr(proxy.RequireTLS),
			"status":              llx.StringData(string(proxy.Status)),
			"createdAt":           llx.TimeDataPtr(proxy.CreatedDate),
			"updatedAt":           llx.TimeDataPtr(proxy.UpdatedDate),
		})
	if err != nil {
		return nil, err
	}
	mqlProxy := resource.(*mqlAwsRdsProxy)
	mqlProxy.cacheVpcId = proxy.VpcId
	mqlProxy.cacheRoleArn = proxy.RoleArn
	mqlProxy.setSecurityGroupArns(sgs)
	mqlProxy.cacheSubnetIds = proxy.VpcSubnetIds
	mqlProxy.region = region
	mqlProxy.accountID = accountID
	return mqlProxy, nil
}

type mqlAwsRdsProxyInternal struct {
	securityGroupIdHandler
	cacheVpcId     *string
	cacheRoleArn   *string
	cacheSubnetIds []string
	region         string
	accountID      string
}

func (a *mqlAwsRdsProxy) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsRdsProxy) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsRdsProxy) subnets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := resolveSubnetRefs(a.MqlRuntime, a.region, conn.AccountId(), a.cacheSubnetIds)
	return res, nil
}

func (a *mqlAwsRdsProxy) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheRoleArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsRdsProxy) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRdsProxy) tags() (map[string]any, error) {
	tags, err := rdsTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	if errors.Is(err, errTagsUnreadable) {
		a.Tags.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return tags, err
}

// rdsTagsForArn reads the tags of any RDS resource. RDS leaves tags out of most
// of its describe responses, so every resource that is not a DB instance,
// cluster, or snapshot (which carry TagList inline) resolves them here.
func rdsTagsForArn(runtime *plugin.Runtime, region, resourceArn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Rds(region)
	resp, err := svc.ListTagsForResource(context.Background(), &rds.ListTagsForResourceInput{
		ResourceName: &resourceArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, errTagsUnreadable
		}
		return nil, err
	}
	return rdsTagsToMap(resp.TagList), nil
}

// ---------- aws.rds.optionGroup ----------

func (a *mqlAwsRds) optionGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		res := []any{}
		svc := conn.Rds(region)
		paginator := rds.NewDescribeOptionGroupsPaginator(svc, &rds.DescribeOptionGroupsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, og := range page.OptionGroupsList {
				mqlOG, err := newMqlAwsRdsOptionGroup(a.MqlRuntime, region, og)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlOG)
			}
		}
		return res, nil
	})
}

type mqlAwsRdsOptionGroupInternal struct {
	lazyTags
	cacheVpcId string
}

func (a *mqlAwsRdsOptionGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return rdsTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func newMqlAwsRdsOptionGroup(runtime *plugin.Runtime, region string, og rds_types.OptionGroup) (*mqlAwsRdsOptionGroup, error) {
	options, err := convert.JsonToDictSlice(og.Options)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "aws.rds.optionGroup", map[string]*llx.RawData{
		"__id":                                  llx.StringDataPtr(og.OptionGroupArn),
		"arn":                                   llx.StringDataPtr(og.OptionGroupArn),
		"optionGroupName":                       llx.StringDataPtr(og.OptionGroupName),
		"description":                           llx.StringDataPtr(og.OptionGroupDescription),
		"engineName":                            llx.StringDataPtr(og.EngineName),
		"majorEngineVersion":                    llx.StringDataPtr(og.MajorEngineVersion),
		"region":                                llx.StringData(region),
		"allowsVpcAndNonVpcInstanceMemberships": llx.BoolDataPtr(og.AllowsVpcAndNonVpcInstanceMemberships),
		"sourceAccountId":                       llx.StringDataPtr(og.SourceAccountId),
		"sourceOptionGroup":                     llx.StringDataPtr(og.SourceOptionGroup),
		"copyTimestamp":                         llx.TimeDataPtr(og.CopyTimestamp),
		"options":                               llx.ArrayData(options, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	mqlOG := res.(*mqlAwsRdsOptionGroup)
	if og.VpcId != nil {
		mqlOG.cacheVpcId = *og.VpcId
	}
	return mqlOG, nil
}

func (a *mqlAwsRdsOptionGroup) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

// optionGroups resolves the option groups attached to this DB instance by
// looking them up in the parent aws.rds.optionGroups listing (cached after
// the first call). This avoids issuing a fresh DescribeOptionGroups per
// membership when both the top-level list and per-instance accessors are
// queried in the same session, and keeps every returned resource
// fully populated (ARN, region, options) rather than carrying just a name.
func (a *mqlAwsRdsDbinstance) optionGroups() ([]any, error) {
	if len(a.cacheOptionGroupNames) == 0 {
		return []any{}, nil
	}

	obj, err := CreateResource(a.MqlRuntime, "aws.rds", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	rdsRes := obj.(*mqlAwsRds)
	rawResources := rdsRes.GetOptionGroups()
	if rawResources.Error != nil {
		return nil, rawResources.Error
	}

	wanted := make(map[string]bool, len(a.cacheOptionGroupNames))
	instanceRegion := a.Region.Data
	for _, n := range a.cacheOptionGroupNames {
		wanted[n] = true
	}

	res := []any{}
	for _, raw := range rawResources.Data {
		og := raw.(*mqlAwsRdsOptionGroup)
		// Filter by region too — option groups with the same name exist in
		// every region (default:mysql-8-0 etc.), so matching on name alone
		// produces one entry per region the name appears in.
		if og.Region.Data != instanceRegion {
			continue
		}
		if wanted[og.OptionGroupName.Data] {
			res = append(res, og)
		}
	}
	return res, nil
}

// ---------- aws.rds.globalCluster ----------

func (a *mqlAwsRds) globalClusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	all, err := perRegion(conn, "rds", func(ctx context.Context, region string) ([]any, error) {
		res := []any{}
		svc := conn.Rds(region)
		paginator := rds.NewDescribeGlobalClustersPaginator(svc, &rds.DescribeGlobalClustersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, gc := range page.GlobalClusters {
				mqlGc, err := newMqlAwsRdsGlobalCluster(a.MqlRuntime, region, gc)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlGc)
			}
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}

	// Aurora global clusters surface from any member region's regional
	// endpoint, so deduplicate by ARN across the parallel region reads.
	seen := map[string]bool{}
	res := []any{}
	for _, r := range all {
		gc, ok := r.(*mqlAwsRdsGlobalCluster)
		if !ok {
			continue
		}
		arn := gc.Arn.Data
		if arn == "" || seen[arn] {
			continue
		}
		seen[arn] = true
		res = append(res, gc)
	}
	return res, nil
}

// mqlAwsRdsGlobalClusterInternal carries the region the global cluster was
// discovered through. A global cluster ARN has no region segment, so the tag
// lookup has no other way to pick a regional RDS client.
type mqlAwsRdsGlobalClusterInternal struct {
	lazyTags
	region string
}

func (a *mqlAwsRdsGlobalCluster) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return rdsTagsForArn(a.MqlRuntime, a.region, a.Arn.Data)
	})
}

func newMqlAwsRdsGlobalCluster(runtime *plugin.Runtime, region string, gc rds_types.GlobalCluster) (*mqlAwsRdsGlobalCluster, error) {
	failoverState, err := convert.JsonToDict(gc.FailoverState)
	if err != nil {
		return nil, err
	}
	members, err := convert.JsonToDictSlice(gc.GlobalClusterMembers)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "aws.rds.globalCluster", map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(gc.GlobalClusterArn),
		"arn":                     llx.StringDataPtr(gc.GlobalClusterArn),
		"globalClusterIdentifier": llx.StringDataPtr(gc.GlobalClusterIdentifier),
		"globalClusterResourceId": llx.StringDataPtr(gc.GlobalClusterResourceId),
		"databaseName":            llx.StringDataPtr(gc.DatabaseName),
		"deletionProtection":      llx.BoolDataPtr(gc.DeletionProtection),
		"endpoint":                llx.StringDataPtr(gc.Endpoint),
		"engine":                  llx.StringDataPtr(gc.Engine),
		"engineLifecycleSupport":  llx.StringDataPtr(gc.EngineLifecycleSupport),
		"engineVersion":           llx.StringDataPtr(gc.EngineVersion),
		"status":                  llx.StringDataPtr(gc.Status),
		"storageEncrypted":        llx.BoolDataPtr(gc.StorageEncrypted),
		"storageEncryptionType":   llx.StringData(string(gc.StorageEncryptionType)),
		"failoverState":           llx.DictData(failoverState),
		"members":                 llx.ArrayData(members, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	mqlGc := res.(*mqlAwsRdsGlobalCluster)
	mqlGc.region = region
	return mqlGc, nil
}

func (a *mqlAwsRdsDbcluster) globalCluster() (*mqlAwsRdsGlobalCluster, error) {
	identifier := a.GlobalClusterIdentifier.Data
	if identifier == "" {
		a.GlobalCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Rds(a.Region.Data)
	ctx := context.Background()
	resp, err := svc.DescribeGlobalClusters(ctx, &rds.DescribeGlobalClustersInput{
		GlobalClusterIdentifier: &identifier,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.GlobalCluster.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if len(resp.GlobalClusters) == 0 {
		a.GlobalCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlAwsRdsGlobalCluster(a.MqlRuntime, a.Region.Data, resp.GlobalClusters[0])
}

type mqlAwsRdsDbinstanceAssociatedRoleInternal struct {
	cacheRoleArn string
}
