// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/mq"
	mq_types "github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsMq) id() (string, error) {
	return "aws.mq", nil
}

// mqLogGroupArn turns a CloudWatch Logs log-group *name* (the form MQ returns
// in LogsSummary.GeneralLogGroup / AuditLogGroup) into the canonical ARN that
// the aws.cloudwatch.loggroup init expects. Returns empty when any input is
// empty so callers can keep their null-handling identical.
func mqLogGroupArn(region, accountID, groupName string) string {
	if region == "" || accountID == "" || groupName == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", region, accountID, groupName)
}

func (a *mqlAwsMq) brokers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getBrokers(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsMq) getBrokers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("mq>getBrokers>calling aws with region %s", region)

			svc := conn.Mq(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.ListBrokers(ctx, &mq.ListBrokersInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("MQ service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, broker := range page.BrokerSummaries {
					mqlBroker, err := newMqlAwsMqBroker(a.MqlRuntime, region, conn.AccountId(), broker)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlBroker)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsMq) configurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConfigurations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsMq) getConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("mq>getConfigurations>calling aws with region %s", region)

			svc := conn.Mq(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.ListConfigurations(ctx, &mq.ListConfigurationsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("MQ service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cfg := range page.Configurations {
					mqlCfg, err := newMqlAwsMqConfiguration(a.MqlRuntime, region, cfg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCfg)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsMqBroker(runtime *plugin.Runtime, region string, accountID string, broker mq_types.BrokerSummary) (*mqlAwsMqBroker, error) {
	var createdAt *llx.RawData
	if broker.Created != nil {
		createdAt = llx.TimeData(*broker.Created)
	} else {
		createdAt = llx.NilData
	}

	resource, err := CreateResource(runtime, "aws.mq.broker",
		map[string]*llx.RawData{
			"__id":     llx.StringDataPtr(broker.BrokerArn),
			"arn":      llx.StringDataPtr(broker.BrokerArn),
			"brokerId": llx.StringDataPtr(broker.BrokerId),
			"name":     llx.StringDataPtr(broker.BrokerName),
			"state":    llx.StringData(string(broker.BrokerState)),
			// The SDK's EngineType constants are "ACTIVEMQ"/"RABBITMQ", but the
			// live API returns mixed case ("ActiveMQ", verified via
			// `aws mq list-brokers`). Normalize to the schema-documented
			// uppercase form so consumers can rely on it.
			"engineType":       llx.StringData(strings.ToUpper(string(broker.EngineType))),
			"deploymentMode":   llx.StringData(string(broker.DeploymentMode)),
			"hostInstanceType": llx.StringDataPtr(broker.HostInstanceType),
			"region":           llx.StringData(region),
			"createdAt":        createdAt,
		})
	if err != nil {
		return nil, err
	}

	mqlBroker := resource.(*mqlAwsMqBroker)
	mqlBroker.region = region
	mqlBroker.accountID = accountID
	if broker.BrokerId != nil {
		mqlBroker.cacheBrokerId = *broker.BrokerId
	}
	return mqlBroker, nil
}

func newMqlAwsMqConfiguration(runtime *plugin.Runtime, region string, cfg mq_types.Configuration) (*mqlAwsMqConfiguration, error) {
	var created *llx.RawData
	if cfg.Created != nil {
		created = llx.TimeData(*cfg.Created)
	} else {
		created = llx.NilData
	}

	var latestRevisionNumber *llx.RawData
	var latestRevisionCreated *llx.RawData
	var latestRevisionDescription *llx.RawData
	if cfg.LatestRevision != nil {
		if cfg.LatestRevision.Revision != nil {
			latestRevisionNumber = llx.IntData(int64(*cfg.LatestRevision.Revision))
		} else {
			latestRevisionNumber = llx.NilData
		}
		if cfg.LatestRevision.Created != nil {
			latestRevisionCreated = llx.TimeData(*cfg.LatestRevision.Created)
		} else {
			latestRevisionCreated = llx.NilData
		}
		latestRevisionDescription = llx.StringDataPtr(cfg.LatestRevision.Description)
	} else {
		latestRevisionNumber = llx.NilData
		latestRevisionCreated = llx.NilData
		latestRevisionDescription = llx.NilData
	}

	tags := map[string]any{}
	for k, v := range cfg.Tags {
		tags[k] = v
	}

	resource, err := CreateResource(runtime, "aws.mq.configuration",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(cfg.Arn),
			"arn":         llx.StringDataPtr(cfg.Arn),
			"id":          llx.StringDataPtr(cfg.Id),
			"name":        llx.StringDataPtr(cfg.Name),
			"description": llx.StringDataPtr(cfg.Description),
			// see broker engineType: live API values are mixed case
			"engineType":                llx.StringData(strings.ToUpper(string(cfg.EngineType))),
			"engineVersion":             llx.StringDataPtr(cfg.EngineVersion),
			"authenticationStrategy":    llx.StringData(string(cfg.AuthenticationStrategy)),
			"created":                   created,
			"latestRevisionNumber":      latestRevisionNumber,
			"latestRevisionCreated":     latestRevisionCreated,
			"latestRevisionDescription": latestRevisionDescription,
			"region":                    llx.StringData(region),
			"tags":                      llx.MapData(tags, "string"),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlAwsMqConfiguration), nil
}

type mqlAwsMqBrokerInternal struct {
	securityGroupIdHandler
	cacheKmsKeyId                *string
	cacheSubnetIds               []string
	cacheTags                    map[string]any
	cacheAuditLogGroupArn        string
	cacheGeneralLogGroupArn      string
	cachePendingSecurityGroupIds []string
	region                       string
	accountID                    string
	cacheBrokerId                string
	fetched                      bool
	lock                         sync.Mutex
}

// fetchDetails calls DescribeBroker to populate all lazy-loaded fields.
// Most security-relevant fields are only available from the describe call.
func (a *mqlAwsMqBroker) fetchDetails() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Mq(a.region)
	ctx := context.Background()

	resp, err := svc.DescribeBroker(ctx, &mq.DescribeBrokerInput{
		BrokerId: &a.cacheBrokerId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("brokerId", a.cacheBrokerId).Msg("access denied describing MQ broker")
			a.fetched = true
			return nil
		}
		return err
	}

	// Cache security groups.
	sgs := []string{}
	for _, sg := range resp.SecurityGroups {
		sgs = append(sgs, NewSecurityGroupArn(a.region, a.accountID, sg))
	}
	a.setSecurityGroupArns(sgs)

	// Cache pending security groups for the lazy-loaded typed reference.
	a.cachePendingSecurityGroupIds = resp.PendingSecurityGroups

	// Cache subnets.
	a.cacheSubnetIds = resp.SubnetIds

	// Cache KMS key.
	if resp.EncryptionOptions != nil {
		a.cacheKmsKeyId = resp.EncryptionOptions.KmsKeyId
	}

	// Populate all describe-only fields.
	if resp.EngineVersion != nil {
		a.EngineVersion = plugin.TValue[string]{Data: *resp.EngineVersion, State: plugin.StateIsSet}
	}

	if resp.PubliclyAccessible != nil {
		a.PubliclyAccessible = plugin.TValue[bool]{Data: *resp.PubliclyAccessible, State: plugin.StateIsSet}
	}

	a.AuthenticationStrategy = plugin.TValue[string]{Data: string(resp.AuthenticationStrategy), State: plugin.StateIsSet}
	a.PendingAuthenticationStrategy = plugin.TValue[string]{Data: string(resp.PendingAuthenticationStrategy), State: plugin.StateIsSet}

	useAwsOwnedKey := true
	if resp.EncryptionOptions != nil && resp.EncryptionOptions.UseAwsOwnedKey != nil {
		useAwsOwnedKey = *resp.EncryptionOptions.UseAwsOwnedKey
	}
	a.UseAwsOwnedKey = plugin.TValue[bool]{Data: useAwsOwnedKey, State: plugin.StateIsSet}

	generalLogs := false
	auditLogs := false
	generalLogGroup := ""
	auditLogGroup := ""
	if resp.Logs != nil {
		if resp.Logs.General != nil {
			generalLogs = *resp.Logs.General
		}
		if resp.Logs.Audit != nil {
			auditLogs = *resp.Logs.Audit
		}
		if resp.Logs.GeneralLogGroup != nil {
			generalLogGroup = *resp.Logs.GeneralLogGroup
		}
		if resp.Logs.AuditLogGroup != nil {
			auditLogGroup = *resp.Logs.AuditLogGroup
		}
	}
	a.GeneralLogsEnabled = plugin.TValue[bool]{Data: generalLogs, State: plugin.StateIsSet}
	a.AuditLogsEnabled = plugin.TValue[bool]{Data: auditLogs, State: plugin.StateIsSet}
	// LogsSummary.GeneralLogGroup / AuditLogGroup return CloudWatch log group
	// *names* (e.g. /aws/amazonmq/broker/b-xxx/general), not ARNs. Construct the
	// canonical ARN so the typed cross-ref to aws.cloudwatch.loggroup resolves
	// via its existing ARN-based init.
	a.cacheGeneralLogGroupArn = mqLogGroupArn(a.region, a.accountID, generalLogGroup)
	a.cacheAuditLogGroupArn = mqLogGroupArn(a.region, a.accountID, auditLogGroup)

	autoUpgrade := false
	if resp.AutoMinorVersionUpgrade != nil {
		autoUpgrade = *resp.AutoMinorVersionUpgrade
	}
	a.AutoMinorVersionUpgrade = plugin.TValue[bool]{Data: autoUpgrade, State: plugin.StateIsSet}

	a.StorageType = plugin.TValue[string]{Data: string(resp.StorageType), State: plugin.StateIsSet}

	// Maintenance window (flattened scalars).
	mwDay := ""
	mwTime := ""
	mwZone := ""
	if resp.MaintenanceWindowStartTime != nil {
		mwDay = string(resp.MaintenanceWindowStartTime.DayOfWeek)
		if resp.MaintenanceWindowStartTime.TimeOfDay != nil {
			mwTime = *resp.MaintenanceWindowStartTime.TimeOfDay
		}
		if resp.MaintenanceWindowStartTime.TimeZone != nil {
			mwZone = *resp.MaintenanceWindowStartTime.TimeZone
		}
	}
	a.MaintenanceDayOfWeek = plugin.TValue[string]{Data: mwDay, State: plugin.StateIsSet}
	a.MaintenanceTimeOfDay = plugin.TValue[string]{Data: mwTime, State: plugin.StateIsSet}
	a.MaintenanceTimeZone = plugin.TValue[string]{Data: mwZone, State: plugin.StateIsSet}

	// Data replication.
	a.DataReplicationMode = plugin.TValue[string]{Data: string(resp.DataReplicationMode), State: plugin.StateIsSet}
	a.PendingDataReplicationMode = plugin.TValue[string]{Data: string(resp.PendingDataReplicationMode), State: plugin.StateIsSet}

	dataReplicationRole := ""
	replicationPartnerBrokerId := ""
	replicationPartnerRegion := ""
	if resp.DataReplicationMetadata != nil {
		if resp.DataReplicationMetadata.DataReplicationRole != nil {
			dataReplicationRole = *resp.DataReplicationMetadata.DataReplicationRole
		}
		if cp := resp.DataReplicationMetadata.DataReplicationCounterpart; cp != nil {
			if cp.BrokerId != nil {
				replicationPartnerBrokerId = *cp.BrokerId
			}
			if cp.Region != nil {
				replicationPartnerRegion = *cp.Region
			}
		}
	}
	a.DataReplicationRole = plugin.TValue[string]{Data: dataReplicationRole, State: plugin.StateIsSet}
	a.ReplicationPartnerBrokerId = plugin.TValue[string]{Data: replicationPartnerBrokerId, State: plugin.StateIsSet}
	a.ReplicationPartnerRegion = plugin.TValue[string]{Data: replicationPartnerRegion, State: plugin.StateIsSet}

	// Pending values.
	if resp.PendingEngineVersion != nil {
		a.PendingEngineVersion = plugin.TValue[string]{Data: *resp.PendingEngineVersion, State: plugin.StateIsSet}
	} else {
		a.PendingEngineVersion = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
	}
	if resp.PendingHostInstanceType != nil {
		a.PendingHostInstanceType = plugin.TValue[string]{Data: *resp.PendingHostInstanceType, State: plugin.StateIsSet}
	} else {
		a.PendingHostInstanceType = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
	}

	// LDAP server metadata as a single-element []dict (LDAP is optional and at most one server is configured).
	ldapDicts := []any{}
	if resp.LdapServerMetadata != nil {
		d, err := convert.JsonToDict(resp.LdapServerMetadata)
		if err != nil {
			return err
		}
		ldapDicts = append(ldapDicts, d)
	}
	a.LdapServerMetadata = plugin.TValue[[]any]{Data: ldapDicts, State: plugin.StateIsSet}

	// Configurations: current, pending, history (flattened into a single []dict
	// with a Kind discriminator so callers can filter without descending into a
	// nested object).
	cfgDicts := []any{}
	if resp.Configurations != nil {
		if c := resp.Configurations.Current; c != nil {
			cfgDicts = append(cfgDicts, configurationIdToDict("current", c))
		}
		if c := resp.Configurations.Pending; c != nil {
			cfgDicts = append(cfgDicts, configurationIdToDict("pending", c))
		}
		for i := range resp.Configurations.History {
			cfgDicts = append(cfgDicts, configurationIdToDict("history", &resp.Configurations.History[i]))
		}
	}
	a.Configurations = plugin.TValue[[]any]{Data: cfgDicts, State: plugin.StateIsSet}

	// Actions required.
	actions, err := convert.JsonToDictSlice(resp.ActionsRequired)
	if err != nil {
		return err
	}
	a.ActionsRequired = plugin.TValue[[]any]{Data: actions, State: plugin.StateIsSet}

	// Users (ActiveMQ only; RabbitMQ returns an empty list).
	users, err := convert.JsonToDictSlice(resp.Users)
	if err != nil {
		return err
	}
	a.Users = plugin.TValue[[]any]{Data: users, State: plugin.StateIsSet}

	// Cache tags from the describe response.
	cacheTags := make(map[string]any)
	for k, v := range resp.Tags {
		cacheTags[k] = v
	}
	a.cacheTags = cacheTags

	a.fetched = true
	return nil
}

func configurationIdToDict(kind string, c *mq_types.ConfigurationId) map[string]any {
	out := map[string]any{"Kind": kind}
	if c.Id != nil {
		out["Id"] = *c.Id
	}
	if c.Revision != nil {
		out["Revision"] = int64(*c.Revision)
	}
	return out
}

func (a *mqlAwsMqBroker) engineVersion() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) publiclyAccessible() (bool, error) {
	return false, a.fetchDetails()
}

func (a *mqlAwsMqBroker) authenticationStrategy() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) useAwsOwnedKey() (bool, error) {
	return false, a.fetchDetails()
}

func (a *mqlAwsMqBroker) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsMqBroker) generalLogsEnabled() (bool, error) {
	return false, a.fetchDetails()
}

func (a *mqlAwsMqBroker) auditLogsEnabled() (bool, error) {
	return false, a.fetchDetails()
}

func (a *mqlAwsMqBroker) generalLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheGeneralLogGroupArn == "" {
		a.GeneralLogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsCloudwatchLoggroup,
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cacheGeneralLogGroupArn),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsMqBroker) auditLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheAuditLogGroupArn == "" {
		a.AuditLogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsCloudwatchLoggroup,
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cacheAuditLogGroupArn),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsMqBroker) autoMinorVersionUpgrade() (bool, error) {
	return false, a.fetchDetails()
}

func (a *mqlAwsMqBroker) storageType() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) maintenanceDayOfWeek() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) maintenanceTimeOfDay() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) maintenanceTimeZone() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) dataReplicationMode() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) pendingDataReplicationMode() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) dataReplicationRole() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) replicationPartnerBrokerId() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) replicationPartnerRegion() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) pendingEngineVersion() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) pendingHostInstanceType() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) pendingAuthenticationStrategy() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsMqBroker) pendingSecurityGroups() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := []any{}
	for _, sgId := range a.cachePendingSecurityGroupIds {
		sgArn := NewSecurityGroupArn(a.region, a.accountID, sgId)
		sg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{
				"arn": llx.StringData(sgArn),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, sg)
	}
	return res, nil
}

func (a *mqlAwsMqBroker) ldapServerMetadata() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsMqBroker) configurations() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsMqBroker) actionsRequired() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsMqBroker) users() ([]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsMqBroker) tags() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheTags, nil
}

func (a *mqlAwsMqBroker) securityGroups() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsMqBroker) subnets() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func initAwsMqBroker(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformMqBroker); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws mq broker")
	}

	// When arn or name is supplied (e.g. via asset identifier from discovery),
	// resolve to the broker already populated by `aws.mq.brokers` so cached
	// region/cacheBrokerId/cacheKmsKeyId values are preserved.
	obj, err := CreateResource(runtime, "aws.mq", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	mq := obj.(*mqlAwsMq)
	brokers := mq.GetBrokers()
	if brokers != nil && brokers.Error == nil {
		var arnVal, nameVal string
		if args["arn"] != nil {
			arnVal, _ = args["arn"].Value.(string)
		}
		if args["name"] != nil {
			nameVal, _ = args["name"].Value.(string)
		}
		for _, raw := range brokers.Data {
			b := raw.(*mqlAwsMqBroker)
			if (arnVal != "" && b.Arn.Data == arnVal) || (nameVal != "" && b.Name.Data == nameVal) {
				return args, b, nil
			}
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws mq broker that is not in the brokers list")
	}
	// The broker was not found in `aws.mq.brokers`, so region and cacheBrokerId
	// are unknown and the resource's scalar fields would stay unset. Returning
	// (args, nil, nil) here would let the runtime create a resource whose fields
	// are all unset, which surfaces as malformed nil data when those fields are
	// queried.
	return nil, nil, fmt.Errorf("aws.mq.broker with arn %q not found", args["arn"].Value)
}

func (a *mqlAwsMqConfiguration) id() (string, error) {
	return a.Arn.Data, nil
}
