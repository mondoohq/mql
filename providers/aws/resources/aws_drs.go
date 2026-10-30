// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/drs"
	drstypes "github.com/aws/aws-sdk-go-v2/service/drs/types"
	"github.com/aws/smithy-go/transport/http"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

type mqlAwsDrsSourceServerInternal struct {
	region                                string
	cacheEc2InstanceID                    string
	cacheRecoveryInstanceID               string
	cacheReversedDirectionSourceServerArn string
}

type mqlAwsDrsRecoveryInstanceInternal struct {
	region string
}

type mqlAwsDrsJobInternal struct {
	region string
}

func (a *mqlAwsDrs) id() (string, error) {
	return "aws.drs", nil
}

func (a *mqlAwsDrsSourceServer) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDrsRecoveryInstance) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDrsJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDrsReplicationConfiguration) id() (string, error) {
	return "aws.drs.replicationConfiguration/" + a.SourceServerID.Data, nil
}

func (a *mqlAwsDrsReplicationConfigurationTemplate) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDrsReplicationConfiguration) ebsEncryptionKey() (*mqlAwsKmsKey, error) {
	arnVal := a.cacheEbsEncryptionKeyArn
	if arnVal == "" {
		a.EbsEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsDrsReplicationConfiguration) stagingAreaSubnet() (*mqlAwsVpcSubnet, error) {
	subnetID := a.cacheStagingAreaSubnetId
	if subnetID == "" {
		a.StagingAreaSubnet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
		map[string]*llx.RawData{"id": llx.StringData(subnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcSubnet), nil
}

func (a *mqlAwsDrsLaunchConfiguration) id() (string, error) {
	return "aws.drs.launchConfiguration/" + a.SourceServerID.Data, nil
}

// ---------------------------------------------------------------------------
// Source servers
// ---------------------------------------------------------------------------

func (a *mqlAwsDrs) sourceServers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSourceServers(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDrs) getSourceServers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Drs(region)
			ctx := context.Background()
			res := []any{}

			paginator := drs.NewDescribeSourceServersPaginator(svc, &drs.DescribeSourceServersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DRS API")
						return res, nil
					}
					if IsDrsNotInitializedError(err) {
						log.Debug().Str("region", region).Msg("DRS not initialized in region")
						return res, nil
					}
					return nil, err
				}

				for _, server := range page.Items {
					mqlServer, err := a.createSourceServerResource(server, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlServer)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func parseDrsTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		log.Warn().Err(err).Str("input", *s).Msg("failed to parse DRS timestamp")
		return nil
	}
	return &t
}

func (a *mqlAwsDrs) createSourceServerResource(server drstypes.SourceServer, region string) (*mqlAwsDrsSourceServer, error) {
	dataReplicationInfo, err := convert.JsonToDict(server.DataReplicationInfo)
	if err != nil {
		return nil, err
	}

	lifeCycle, err := convert.JsonToDict(server.LifeCycle)
	if err != nil {
		return nil, err
	}

	sourceProperties, err := convert.JsonToDict(server.SourceProperties)
	if err != nil {
		return nil, err
	}

	stagingArea, err := convert.JsonToDict(server.StagingArea)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]any)
	for k, v := range server.Tags {
		tags[k] = v
	}

	// Lifecycle scalars
	var addedToServiceAt, firstByteAt, lastSeenAt *time.Time
	var elapsedReplicationDuration string
	var lastLaunchStatus string
	if server.LifeCycle != nil {
		addedToServiceAt = parseDrsTime(server.LifeCycle.AddedToServiceDateTime)
		firstByteAt = parseDrsTime(server.LifeCycle.FirstByteDateTime)
		lastSeenAt = parseDrsTime(server.LifeCycle.LastSeenByServiceDateTime)
		if server.LifeCycle.ElapsedReplicationDuration != nil {
			elapsedReplicationDuration = *server.LifeCycle.ElapsedReplicationDuration
		}
		if server.LifeCycle.LastLaunch != nil {
			lastLaunchStatus = string(server.LifeCycle.LastLaunch.Status)
		}
	}

	// DataReplicationInfo scalars
	var dataReplicationState, dataReplicationLagDuration, dataReplicationStagingAZ string
	var dataReplicationEtaAt *time.Time
	if server.DataReplicationInfo != nil {
		dataReplicationState = string(server.DataReplicationInfo.DataReplicationState)
		if server.DataReplicationInfo.LagDuration != nil {
			dataReplicationLagDuration = *server.DataReplicationInfo.LagDuration
		}
		if server.DataReplicationInfo.StagingAvailabilityZone != nil {
			dataReplicationStagingAZ = *server.DataReplicationInfo.StagingAvailabilityZone
		}
		dataReplicationEtaAt = parseDrsTime(server.DataReplicationInfo.EtaDateTime)
	}

	// SourceProperties scalars
	var sourceCpuCount, sourceDiskCount int64
	var sourceRamBytes int64
	var sourceRecommendedInstanceType string
	var sourceSupportsNitro *bool
	var fqdn, hostname, awsInstanceID string
	if server.SourceProperties != nil {
		sourceCpuCount = int64(len(server.SourceProperties.Cpus))
		sourceDiskCount = int64(len(server.SourceProperties.Disks))
		sourceRamBytes = server.SourceProperties.RamBytes
		if server.SourceProperties.RecommendedInstanceType != nil {
			sourceRecommendedInstanceType = *server.SourceProperties.RecommendedInstanceType
		}
		sourceSupportsNitro = server.SourceProperties.SupportsNitroInstances
		if server.SourceProperties.IdentificationHints != nil {
			if server.SourceProperties.IdentificationHints.Fqdn != nil {
				fqdn = *server.SourceProperties.IdentificationHints.Fqdn
			}
			if server.SourceProperties.IdentificationHints.Hostname != nil {
				hostname = *server.SourceProperties.IdentificationHints.Hostname
			}
			if server.SourceProperties.IdentificationHints.AwsInstanceID != nil {
				awsInstanceID = *server.SourceProperties.IdentificationHints.AwsInstanceID
			}
		}
	}

	// SourceCloudProperties scalars
	var sourceCloudOriginAccountID, sourceCloudOriginRegion, sourceCloudOriginAZ string
	if server.SourceCloudProperties != nil {
		if server.SourceCloudProperties.OriginAccountID != nil {
			sourceCloudOriginAccountID = *server.SourceCloudProperties.OriginAccountID
		}
		if server.SourceCloudProperties.OriginRegion != nil {
			sourceCloudOriginRegion = *server.SourceCloudProperties.OriginRegion
		}
		if server.SourceCloudProperties.OriginAvailabilityZone != nil {
			sourceCloudOriginAZ = *server.SourceCloudProperties.OriginAvailabilityZone
		}
	}

	mqlServer, err := CreateResource(a.MqlRuntime, ResourceAwsDrsSourceServer,
		map[string]*llx.RawData{
			"sourceServerID":                         llx.StringDataPtr(server.SourceServerID),
			"arn":                                    llx.StringDataPtr(server.Arn),
			"agentVersion":                           llx.StringDataPtr(server.AgentVersion),
			"dataReplicationInfo":                    llx.DictData(dataReplicationInfo),
			"dataReplicationState":                   llx.StringData(dataReplicationState),
			"dataReplicationLagDuration":             llx.StringData(dataReplicationLagDuration),
			"dataReplicationEtaAt":                   llx.TimeDataPtr(dataReplicationEtaAt),
			"dataReplicationStagingAvailabilityZone": llx.StringData(dataReplicationStagingAZ),
			"lastLaunchResult":                       llx.StringData(string(server.LastLaunchResult)),
			"lifeCycle":                              llx.DictData(lifeCycle),
			"lifeCycleAddedToServiceAt":              llx.TimeDataPtr(addedToServiceAt),
			"lifeCycleFirstByteAt":                   llx.TimeDataPtr(firstByteAt),
			"lifeCycleLastSeenAt":                    llx.TimeDataPtr(lastSeenAt),
			"lifeCycleElapsedReplicationDuration":    llx.StringData(elapsedReplicationDuration),
			"lifeCycleLastLaunchStatus":              llx.StringData(lastLaunchStatus),
			"sourceProperties":                       llx.DictData(sourceProperties),
			"sourceCpuCount":                         llx.IntData(sourceCpuCount),
			"sourceDiskCount":                        llx.IntData(sourceDiskCount),
			"sourceRamBytes":                         llx.IntData(sourceRamBytes),
			"sourceRecommendedInstanceType":          llx.StringData(sourceRecommendedInstanceType),
			"sourceSupportsNitroInstances":           llx.BoolDataPtr(sourceSupportsNitro),
			"sourceIdentificationFqdn":               llx.StringData(fqdn),
			"sourceIdentificationHostname":           llx.StringData(hostname),
			"sourceCloudOriginAccountID":             llx.StringData(sourceCloudOriginAccountID),
			"sourceCloudOriginRegion":                llx.StringData(sourceCloudOriginRegion),
			"sourceCloudOriginAvailabilityZone":      llx.StringData(sourceCloudOriginAZ),
			"sourceNetworkID":                        llx.StringDataPtr(server.SourceNetworkID),
			"stagingArea":                            llx.DictData(stagingArea),
			"replicationDirection":                   llx.StringData(string(server.ReplicationDirection)),
			"tags":                                   llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlSrv := mqlServer.(*mqlAwsDrsSourceServer)
	mqlSrv.region = region
	mqlSrv.cacheEc2InstanceID = awsInstanceID
	if server.RecoveryInstanceId != nil {
		mqlSrv.cacheRecoveryInstanceID = *server.RecoveryInstanceId
	}
	if server.ReversedDirectionSourceServerArn != nil {
		mqlSrv.cacheReversedDirectionSourceServerArn = *server.ReversedDirectionSourceServerArn
	}
	return mqlSrv, nil
}

func (a *mqlAwsDrsSourceServer) sourceEc2Instance() (*mqlAwsEc2Instance, error) {
	ec2ID := a.cacheEc2InstanceID
	originAccount := a.SourceCloudOriginAccountID.Data
	originRegion := a.SourceCloudOriginRegion.Data
	if ec2ID == "" || originAccount == "" || originRegion == "" {
		a.SourceEc2Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	ec2Arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", originRegion, originAccount, ec2ID)
	res, err := NewResource(a.MqlRuntime, "aws.ec2.instance",
		map[string]*llx.RawData{"arn": llx.StringData(ec2Arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Instance), nil
}

func (a *mqlAwsDrsSourceServer) replicationConfiguration() (*mqlAwsDrsReplicationConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	sourceServerID := a.SourceServerID.Data
	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse source server ARN")
	}

	svc := conn.Drs(region)
	ctx := context.Background()

	resp, err := svc.GetReplicationConfiguration(ctx, &drs.GetReplicationConfigurationInput{
		SourceServerID: &sourceServerID,
	})
	if err != nil {
		return nil, err
	}

	stagingAreaTags := make(map[string]any)
	for k, v := range resp.StagingAreaTags {
		stagingAreaTags[k] = v
	}

	replicatedDisks := make([]any, 0, len(resp.ReplicatedDisks))
	for _, disk := range resp.ReplicatedDisks {
		diskMap, err := convert.JsonToDict(disk)
		if err != nil {
			return nil, err
		}
		replicatedDisks = append(replicatedDisks, diskMap)
	}

	mqlConfig, err := CreateResource(a.MqlRuntime, ResourceAwsDrsReplicationConfiguration,
		map[string]*llx.RawData{
			"sourceServerID":                llx.StringDataPtr(resp.SourceServerID),
			"stagingAreaTags":               llx.MapData(stagingAreaTags, types.String),
			"useDedicatedReplicationServer": llx.BoolDataPtr(resp.UseDedicatedReplicationServer),
			"replicationServerInstanceType": llx.StringDataPtr(resp.ReplicationServerInstanceType),
			"ebsEncryption":                 llx.StringData(string(resp.EbsEncryption)),
			"replicatedDisks":               llx.ArrayData(replicatedDisks, types.Dict),
			"bandwidthThrottling":           llx.IntData(int64(resp.BandwidthThrottling)),
			"dataPlaneRouting":              llx.StringData(string(resp.DataPlaneRouting)),
			"internetProtocol":              llx.StringData(string(resp.InternetProtocol)),
			"createPublicIP":                llx.BoolDataPtr(resp.CreatePublicIP),
			"associateDefaultSecurityGroup": llx.BoolDataPtr(resp.AssociateDefaultSecurityGroup),
			"autoReplicateNewDisks":         llx.BoolDataPtr(resp.AutoReplicateNewDisks),
		})
	if err != nil {
		return nil, err
	}
	mqlConfig.(*mqlAwsDrsReplicationConfiguration).cacheStagingAreaSubnetId = convert.ToValue(resp.StagingAreaSubnetId)
	mqlConfig.(*mqlAwsDrsReplicationConfiguration).cacheEbsEncryptionKeyArn = convert.ToValue(resp.EbsEncryptionKeyArn)

	return mqlConfig.(*mqlAwsDrsReplicationConfiguration), nil
}

func (a *mqlAwsDrsSourceServer) launchConfiguration() (*mqlAwsDrsLaunchConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	sourceServerID := a.SourceServerID.Data
	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse source server ARN")
	}

	svc := conn.Drs(region)
	ctx := context.Background()

	resp, err := svc.GetLaunchConfiguration(ctx, &drs.GetLaunchConfigurationInput{
		SourceServerID: &sourceServerID,
	})
	if err != nil {
		return nil, err
	}

	licensing, err := convert.JsonToDict(resp.Licensing)
	if err != nil {
		return nil, err
	}

	launchIntoInstanceProperties, err := convert.JsonToDict(resp.LaunchIntoInstanceProperties)
	if err != nil {
		return nil, err
	}

	mqlConfig, err := CreateResource(a.MqlRuntime, ResourceAwsDrsLaunchConfiguration,
		map[string]*llx.RawData{
			"sourceServerID":                      llx.StringDataPtr(resp.SourceServerID),
			"targetInstanceTypeRightSizingMethod": llx.StringData(string(resp.TargetInstanceTypeRightSizingMethod)),
			"launchDisposition":                   llx.StringData(string(resp.LaunchDisposition)),
			"copyPrivateIp":                       llx.BoolDataPtr(resp.CopyPrivateIp),
			"copyTags":                            llx.BoolDataPtr(resp.CopyTags),
			"ec2LaunchTemplateID":                 llx.StringDataPtr(resp.Ec2LaunchTemplateID),
			"licensing":                           llx.DictData(licensing),
			"postLaunchEnabled":                   llx.BoolDataPtr(resp.PostLaunchEnabled),
			"launchIntoInstanceProperties":        llx.DictData(launchIntoInstanceProperties),
		})
	if err != nil {
		return nil, err
	}

	return mqlConfig.(*mqlAwsDrsLaunchConfiguration), nil
}

func (a *mqlAwsDrsSourceServer) recoveryInstance() (*mqlAwsDrsRecoveryInstance, error) {
	recoveryID := a.cacheRecoveryInstanceID
	if recoveryID == "" {
		a.RecoveryInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	region := a.region
	if region == "" {
		// fall back to ARN parsing if region wasn't cached
		r, err := GetRegionFromArn(a.Arn.Data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse source server ARN")
		}
		region = r
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := fmt.Sprintf("arn:aws:drs:%s:%s:recovery-instance/%s", region, conn.AccountId(), recoveryID)

	res, err := NewResource(a.MqlRuntime, ResourceAwsDrsRecoveryInstance,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDrsRecoveryInstance), nil
}

func (a *mqlAwsDrsSourceServer) reversedDirectionSourceServer() (*mqlAwsDrsSourceServer, error) {
	arnVal := a.cacheReversedDirectionSourceServerArn
	if arnVal == "" {
		a.ReversedDirectionSourceServer.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsDrsSourceServer,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDrsSourceServer), nil
}

// ---------------------------------------------------------------------------
// Recovery instances
// ---------------------------------------------------------------------------

func (a *mqlAwsDrs) recoveryInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getRecoveryInstances(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDrs) getRecoveryInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Drs(region)
			ctx := context.Background()
			res := []any{}

			paginator := drs.NewDescribeRecoveryInstancesPaginator(svc, &drs.DescribeRecoveryInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DRS API")
						return res, nil
					}
					if IsDrsNotInitializedError(err) {
						log.Debug().Str("region", region).Msg("DRS not initialized in region")
						return res, nil
					}
					return nil, err
				}

				for _, instance := range page.Items {
					mqlInstance, err := a.createRecoveryInstanceResource(instance, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlInstance)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDrs) createRecoveryInstanceResource(instance drstypes.RecoveryInstance, region string) (*mqlAwsDrsRecoveryInstance, error) {
	dataReplicationInfo, err := convert.JsonToDict(instance.DataReplicationInfo)
	if err != nil {
		return nil, err
	}

	failback, err := convert.JsonToDict(instance.Failback)
	if err != nil {
		return nil, err
	}

	recoveryInstanceProperties, err := convert.JsonToDict(instance.RecoveryInstanceProperties)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]any)
	for k, v := range instance.Tags {
		tags[k] = v
	}

	var dataReplicationState, dataReplicationLagDuration string
	if instance.DataReplicationInfo != nil {
		dataReplicationState = string(instance.DataReplicationInfo.DataReplicationState)
		if instance.DataReplicationInfo.LagDuration != nil {
			dataReplicationLagDuration = *instance.DataReplicationInfo.LagDuration
		}
	}

	pointInTimeSnapshotAt := parseDrsTime(instance.PointInTimeSnapshotDateTime)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := ""
	if instance.Arn != nil && *instance.Arn != "" {
		arnVal = *instance.Arn
	} else if instance.RecoveryInstanceID != nil && *instance.RecoveryInstanceID != "" {
		arnVal = fmt.Sprintf("arn:aws:drs:%s:%s:recovery-instance/%s", region, conn.AccountId(), *instance.RecoveryInstanceID)
	} else {
		return nil, errors.New("DRS recovery instance has neither ARN nor recoveryInstanceID")
	}

	mqlInstance, err := CreateResource(a.MqlRuntime, ResourceAwsDrsRecoveryInstance,
		map[string]*llx.RawData{
			"recoveryInstanceID":         llx.StringDataPtr(instance.RecoveryInstanceID),
			"arn":                        llx.StringData(arnVal),
			"agentVersion":               llx.StringDataPtr(instance.AgentVersion),
			"ec2InstanceID":              llx.StringDataPtr(instance.Ec2InstanceID),
			"ec2InstanceState":           llx.StringData(string(instance.Ec2InstanceState)),
			"sourceServerID":             llx.StringDataPtr(instance.SourceServerID),
			"jobID":                      llx.StringDataPtr(instance.JobID),
			"isDrill":                    llx.BoolDataPtr(instance.IsDrill),
			"originAvailabilityZone":     llx.StringDataPtr(instance.OriginAvailabilityZone),
			"originEnvironment":          llx.StringData(string(instance.OriginEnvironment)),
			"pointInTimeSnapshotAt":      llx.TimeDataPtr(pointInTimeSnapshotAt),
			"dataReplicationInfo":        llx.DictData(dataReplicationInfo),
			"dataReplicationState":       llx.StringData(dataReplicationState),
			"dataReplicationLagDuration": llx.StringData(dataReplicationLagDuration),
			"failback":                   llx.DictData(failback),
			"recoveryInstanceProperties": llx.DictData(recoveryInstanceProperties),
			"sourceOutpostArn":           llx.StringDataPtr(instance.SourceOutpostArn),
			"tags":                       llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlInst := mqlInstance.(*mqlAwsDrsRecoveryInstance)
	mqlInst.region = region
	return mqlInst, nil
}

func (a *mqlAwsDrsRecoveryInstance) ec2Instance() (*mqlAwsEc2Instance, error) {
	ec2ID := a.Ec2InstanceID.Data
	if ec2ID == "" {
		a.Ec2Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	region := a.region
	if region == "" {
		r, err := GetRegionFromArn(a.Arn.Data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse recovery instance ARN")
		}
		region = r
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ec2Arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, conn.AccountId(), ec2ID)

	res, err := NewResource(a.MqlRuntime, "aws.ec2.instance",
		map[string]*llx.RawData{"arn": llx.StringData(ec2Arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Instance), nil
}

func (a *mqlAwsDrsRecoveryInstance) sourceServer() (*mqlAwsDrsSourceServer, error) {
	srcID := a.SourceServerID.Data
	if srcID == "" {
		a.SourceServer.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	region := a.region
	if region == "" {
		r, err := GetRegionFromArn(a.Arn.Data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse recovery instance ARN")
		}
		region = r
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	srcArn := fmt.Sprintf("arn:aws:drs:%s:%s:source-server/%s", region, conn.AccountId(), srcID)

	res, err := NewResource(a.MqlRuntime, ResourceAwsDrsSourceServer,
		map[string]*llx.RawData{"arn": llx.StringData(srcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDrsSourceServer), nil
}

func (a *mqlAwsDrsRecoveryInstance) job() (*mqlAwsDrsJob, error) {
	jobID := a.JobID.Data
	if jobID == "" {
		a.Job.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	region := a.region
	if region == "" {
		r, err := GetRegionFromArn(a.Arn.Data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse recovery instance ARN")
		}
		region = r
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	jobArn := fmt.Sprintf("arn:aws:drs:%s:%s:job/%s", region, conn.AccountId(), jobID)

	res, err := NewResource(a.MqlRuntime, ResourceAwsDrsJob,
		map[string]*llx.RawData{"arn": llx.StringData(jobArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDrsJob), nil
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

func (a *mqlAwsDrs) jobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDrs) getJobs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Drs(region)
			ctx := context.Background()
			res := []any{}

			paginator := drs.NewDescribeJobsPaginator(svc, &drs.DescribeJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DRS API")
						return res, nil
					}
					if IsDrsNotInitializedError(err) {
						log.Debug().Str("region", region).Msg("DRS not initialized in region")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.Items {
					mqlJob, err := a.createJobResource(job, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlJob)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDrs) createJobResource(job drstypes.Job, region string) (*mqlAwsDrsJob, error) {
	participatingServers := make([]any, 0, len(job.ParticipatingServers))
	for _, server := range job.ParticipatingServers {
		serverMap, err := convert.JsonToDict(server)
		if err != nil {
			return nil, err
		}
		participatingServers = append(participatingServers, serverMap)
	}

	participatingResources := make([]any, 0, len(job.ParticipatingResources))
	for _, r := range job.ParticipatingResources {
		resourceMap, err := convert.JsonToDict(r)
		if err != nil {
			return nil, err
		}
		participatingResources = append(participatingResources, resourceMap)
	}

	tags := make(map[string]any)
	for k, v := range job.Tags {
		tags[k] = v
	}

	// Use provided ARN or construct one
	jobArn := ""
	if job.Arn != nil && *job.Arn != "" {
		jobArn = *job.Arn
	} else {
		jobID := convert.ToValue(job.JobID)
		if jobID == "" {
			return nil, errors.New("DRS job has neither ARN nor JobID, cannot construct resource identifier")
		}
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		jobArn = fmt.Sprintf("arn:aws:drs:%s:%s:job/%s", region, conn.AccountId(), jobID)
	}

	createdAt := parseDrsTime(job.CreationDateTime)
	endedAt := parseDrsTime(job.EndDateTime)

	mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsDrsJob,
		map[string]*llx.RawData{
			"jobID":                  llx.StringDataPtr(job.JobID),
			"arn":                    llx.StringData(jobArn),
			"type":                   llx.StringData(string(job.Type)),
			"status":                 llx.StringData(string(job.Status)),
			"initiatedBy":            llx.StringData(string(job.InitiatedBy)),
			"createdAt":              llx.TimeDataPtr(createdAt),
			"endedAt":                llx.TimeDataPtr(endedAt),
			"participatingServers":   llx.ArrayData(participatingServers, types.Dict),
			"participatingResources": llx.ArrayData(participatingResources, types.Dict),
			"tags":                   llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlJ := mqlJob.(*mqlAwsDrsJob)
	mqlJ.region = region
	return mqlJ, nil
}

// ---------------------------------------------------------------------------
// Replication configuration templates
// ---------------------------------------------------------------------------

func (a *mqlAwsDrs) replicationConfigurationTemplates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplicationConfigurationTemplates(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDrs) getReplicationConfigurationTemplates(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Drs(region)
			ctx := context.Background()
			res := []any{}

			paginator := drs.NewDescribeReplicationConfigurationTemplatesPaginator(svc, &drs.DescribeReplicationConfigurationTemplatesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DRS API")
						return res, nil
					}
					if IsDrsNotInitializedError(err) {
						log.Debug().Str("region", region).Msg("DRS not initialized in region")
						return res, nil
					}
					return nil, err
				}

				for _, tmpl := range page.Items {
					mqlTmpl, err := a.createReplicationConfigurationTemplateResource(tmpl, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTmpl)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDrs) createReplicationConfigurationTemplateResource(tmpl drstypes.ReplicationConfigurationTemplate, region string) (*mqlAwsDrsReplicationConfigurationTemplate, error) {
	stagingAreaTags := make(map[string]any)
	for k, v := range tmpl.StagingAreaTags {
		stagingAreaTags[k] = v
	}

	tags := make(map[string]any)
	for k, v := range tmpl.Tags {
		tags[k] = v
	}

	pitPolicy := make([]any, 0, len(tmpl.PitPolicy))
	for _, rule := range tmpl.PitPolicy {
		ruleMap, err := convert.JsonToDict(rule)
		if err != nil {
			return nil, err
		}
		pitPolicy = append(pitPolicy, ruleMap)
	}

	sgIDs := make([]any, 0, len(tmpl.ReplicationServersSecurityGroupsIDs))
	for _, sg := range tmpl.ReplicationServersSecurityGroupsIDs {
		sgIDs = append(sgIDs, sg)
	}

	// Construct ARN if not provided
	arnVal := ""
	if tmpl.Arn != nil && *tmpl.Arn != "" {
		arnVal = *tmpl.Arn
	} else if tmpl.ReplicationConfigurationTemplateID != nil && *tmpl.ReplicationConfigurationTemplateID != "" {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		arnVal = fmt.Sprintf("arn:aws:drs:%s:%s:replication-configuration-template/%s", region, conn.AccountId(), *tmpl.ReplicationConfigurationTemplateID)
	} else {
		return nil, errors.New("DRS replication configuration template missing both ARN and ID")
	}

	mqlTmpl, err := CreateResource(a.MqlRuntime, ResourceAwsDrsReplicationConfigurationTemplate,
		map[string]*llx.RawData{
			"replicationConfigurationTemplateID":  llx.StringDataPtr(tmpl.ReplicationConfigurationTemplateID),
			"arn":                                 llx.StringData(arnVal),
			"associateDefaultSecurityGroup":       llx.BoolDataPtr(tmpl.AssociateDefaultSecurityGroup),
			"autoReplicateNewDisks":               llx.BoolDataPtr(tmpl.AutoReplicateNewDisks),
			"bandwidthThrottling":                 llx.IntData(tmpl.BandwidthThrottling),
			"createPublicIP":                      llx.BoolDataPtr(tmpl.CreatePublicIP),
			"dataPlaneRouting":                    llx.StringData(string(tmpl.DataPlaneRouting)),
			"defaultLargeStagingDiskType":         llx.StringData(string(tmpl.DefaultLargeStagingDiskType)),
			"ebsEncryption":                       llx.StringData(string(tmpl.EbsEncryption)),
			"ebsEncryptionKeyArn":                 llx.StringDataPtr(tmpl.EbsEncryptionKeyArn),
			"internetProtocol":                    llx.StringData(string(tmpl.InternetProtocol)),
			"pitPolicy":                           llx.ArrayData(pitPolicy, types.Dict),
			"replicationServerInstanceType":       llx.StringDataPtr(tmpl.ReplicationServerInstanceType),
			"replicationServersSecurityGroupsIDs": llx.ArrayData(sgIDs, types.String),
			"stagingAreaSubnetId":                 llx.StringDataPtr(tmpl.StagingAreaSubnetId),
			"stagingAreaTags":                     llx.MapData(stagingAreaTags, types.String),
			"useDedicatedReplicationServer":       llx.BoolDataPtr(tmpl.UseDedicatedReplicationServer),
			"tags":                                llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, err
	}

	return mqlTmpl.(*mqlAwsDrsReplicationConfigurationTemplate), nil
}

func (a *mqlAwsDrsReplicationConfigurationTemplate) ebsEncryptionKey() (*mqlAwsKmsKey, error) {
	arnVal := a.EbsEncryptionKeyArn.Data
	if arnVal == "" {
		a.EbsEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsDrsReplicationConfigurationTemplate) stagingAreaSubnet() (*mqlAwsVpcSubnet, error) {
	subnetID := a.StagingAreaSubnetId.Data
	if subnetID == "" {
		a.StagingAreaSubnet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
		map[string]*llx.RawData{"id": llx.StringData(subnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcSubnet), nil
}

func (a *mqlAwsDrsReplicationConfigurationTemplate) replicationServersSecurityGroups() ([]any, error) {
	res := []any{}
	for _, raw := range a.ReplicationServersSecurityGroupsIDs.Data {
		sgID, ok := raw.(string)
		if !ok || sgID == "" {
			continue
		}
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{"id": llx.StringData(sgID)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}
	return res, nil
}

// IsDrsNotInitializedError checks if the error indicates DRS is not initialized in the region
func IsDrsNotInitializedError(err error) bool {
	if err == nil {
		return false
	}

	var respErr *http.ResponseError
	if errors.As(err, &respErr) {
		// DRS returns UninitializedAccountException when DRS is not initialized in the region
		errMsg := respErr.Error()
		if strings.Contains(errMsg, "UninitializedAccountException") ||
			strings.Contains(errMsg, "not initialized") ||
			strings.Contains(errMsg, "is not enabled") {
			return true
		}
	}
	return false
}

type mqlAwsDrsReplicationConfigurationInternal struct {
	cacheStagingAreaSubnetId string
	cacheEbsEncryptionKeyArn string
}
