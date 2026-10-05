// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafka_types "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsMsk) id() (string, error) {
	return "aws.msk", nil
}

// ===== Internal struct layouts =====

type mqlAwsMskClusterInternal struct {
	securityGroupIdHandler
	cacheKmsKeyId  *string
	cacheSubnetIds []string
	region         string
	accountID      string
	provisioned    *kafka_types.Provisioned
	serverless     *kafka_types.Serverless

	describeOnce sync.Once
	describeResp *kafka.DescribeClusterV2Output
	describeErr  error

	bootstrapOnce sync.Once
	bootstrapResp *kafka.GetBootstrapBrokersOutput
	bootstrapErr  error

	policyOnce sync.Once
	policyResp *kafka.GetClusterPolicyOutput
	policyErr  error

	scramOnce    sync.Once
	scramSecrets []string
	scramErr     error

	nodesOnce sync.Once
	nodesData []kafka_types.NodeInfo
	nodesErr  error

	opsOnce sync.Once
	opsData []kafka_types.ClusterOperationV2Summary
	opsErr  error

	clientVpcOnce sync.Once
	clientVpcs    []kafka_types.ClientVpcConnection
	clientVpcsErr error
}

type mqlAwsMskClusterEncryptionInfoInternal struct {
	cacheKmsKeyArn *string
}

type mqlAwsMskClusterClientAuthenticationInternal struct {
	clusterArn     string
	region         string
	cacheTlsCaArns []string
}

type mqlAwsMskClusterBrokerNodeGroupInternal struct {
	securityGroupIdHandler
	region         string
	accountID      string
	cacheSubnetIds []string
	cacheVpcConn   *kafka_types.VpcConnectivity
	clusterArn     string
}

type mqlAwsMskClusterLoggingInfoInternal struct {
	region          string
	accountID       string
	cacheCloudwatch *kafka_types.CloudWatchLogs
	cacheFirehose   *kafka_types.Firehose
	cacheS3         *kafka_types.S3
	clusterArn      string
}

type mqlAwsMskClusterLoggingInfoCloudwatchLogsInternal struct {
	region        string
	accountID     string
	cacheLogGroup *string
}

type mqlAwsMskClusterLoggingInfoFirehoseInternal struct {
	region              string
	accountID           string
	cacheDeliveryStream *string
}

type mqlAwsMskClusterLoggingInfoS3Internal struct {
	cacheBucket *string
}

type mqlAwsMskClusterNodeInternal struct {
	region        string
	accountID     string
	cacheSubnetId *string
	cacheEniId    *string
}

type mqlAwsMskClusterServerlessConfigVpcConfigInternal struct {
	securityGroupIdHandler
	region         string
	accountID      string
	cacheSubnetIds []string
}

type mqlAwsMskConfigurationInternal struct {
	region         string
	latestRevision int64
	propsOnce      sync.Once
	propsData      string
	propsErr       error
}

type mqlAwsMskReplicatorInternal struct {
	region       string
	accountID    string
	describeOnce sync.Once
	describeResp *kafka.DescribeReplicatorOutput
	describeErr  error
}

type mqlAwsMskReplicatorKafkaClusterInternal struct {
	securityGroupIdHandler
	region         string
	accountID      string
	cacheSubnetIds []string
	cacheMskArn    *string
	cacheSecretArn *string
}

type mqlAwsMskReplicatorReplicationInfoInternal struct {
	sourceArn *string
	targetArn *string
}

type mqlAwsMskReplicatorLogDeliveryInternal struct {
	replicatorArn string
	region        string
	accountID     string
	cacheCW       *kafka_types.ReplicatorCloudWatchLogs
	cacheFirehose *kafka_types.ReplicatorFirehose
	cacheS3       *kafka_types.ReplicatorS3
}

type mqlAwsMskReplicatorLogDeliveryCloudwatchLogsInternal struct {
	region        string
	accountID     string
	cacheLogGroup *string
}

type mqlAwsMskReplicatorLogDeliveryFirehoseInternal struct {
	region              string
	accountID           string
	cacheDeliveryStream *string
}

type mqlAwsMskReplicatorLogDeliveryS3Internal struct {
	cacheBucket *string
}

// ===== aws.msk =====

func (a *mqlAwsMsk) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClusters(conn), 5)
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

func (a *mqlAwsMsk) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("msk>getClusters>calling aws with region %s", region)

			svc := conn.Kafka(region)
			ctx := context.Background()
			res := []any{}

			paginator := kafka.NewListClustersV2Paginator(svc, &kafka.ListClustersV2Input{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("MSK service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range page.ClusterInfoList {
					mqlCluster, err := newMqlAwsMskCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCluster)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsMsk) configurations() ([]any, error) {
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

func (a *mqlAwsMsk) getConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("msk>getConfigurations>calling aws with region %s", region)

			svc := conn.Kafka(region)
			ctx := context.Background()
			res := []any{}

			paginator := kafka.NewListConfigurationsPaginator(svc, &kafka.ListConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("MSK service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cfg := range page.Configurations {
					mqlCfg, err := newMqlAwsMskConfiguration(a.MqlRuntime, region, cfg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCfg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsMsk) replicators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplicators(conn), 5)
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

func (a *mqlAwsMsk) getReplicators(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("msk>getReplicators>calling aws with region %s", region)

			svc := conn.Kafka(region)
			ctx := context.Background()
			res := []any{}

			paginator := kafka.NewListReplicatorsPaginator(svc, &kafka.ListReplicatorsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("MSK service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, rep := range page.Replicators {
					if rep.ReplicatorArn == nil {
						continue
					}
					mqlRep, err := newMqlAwsMskReplicator(a.MqlRuntime, region, conn.AccountId(), rep)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRep)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// ===== aws.msk.cluster =====

func newMqlAwsMskCluster(runtime *plugin.Runtime, region string, accountID string, cluster kafka_types.Cluster) (*mqlAwsMskCluster, error) {
	tags := make(map[string]any)
	for k, v := range cluster.Tags {
		tags[k] = v
	}

	var createdAt *llx.RawData
	if cluster.CreationTime != nil {
		createdAt = llx.TimeData(*cluster.CreationTime)
	} else {
		createdAt = llx.NilData
	}

	clusterType := ""
	if cluster.ClusterType != "" {
		clusterType = string(cluster.ClusterType)
	}

	resource, err := CreateResource(runtime, "aws.msk.cluster",
		map[string]*llx.RawData{
			"__id":           llx.StringDataPtr(cluster.ClusterArn),
			"arn":            llx.StringDataPtr(cluster.ClusterArn),
			"name":           llx.StringDataPtr(cluster.ClusterName),
			"state":          llx.StringData(string(cluster.State)),
			"clusterType":    llx.StringData(clusterType),
			"region":         llx.StringData(region),
			"currentVersion": llx.StringDataPtr(cluster.CurrentVersion),
			"createdAt":      createdAt,
			"tags":           llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlCluster := resource.(*mqlAwsMskCluster)
	mqlCluster.region = region
	mqlCluster.accountID = accountID

	if cluster.Provisioned != nil {
		p := cluster.Provisioned
		mqlCluster.provisioned = p

		if p.BrokerNodeGroupInfo != nil {
			bni := p.BrokerNodeGroupInfo
			sgs := []string{}
			for _, sg := range bni.SecurityGroups {
				sgs = append(sgs, NewSecurityGroupArn(region, accountID, sg))
			}
			mqlCluster.setSecurityGroupArns(sgs)
			mqlCluster.cacheSubnetIds = bni.ClientSubnets
		}

		if p.EncryptionInfo != nil && p.EncryptionInfo.EncryptionAtRest != nil {
			mqlCluster.cacheKmsKeyId = p.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
		}
	}
	if cluster.Serverless != nil {
		mqlCluster.serverless = cluster.Serverless
	}

	return mqlCluster, nil
}

// initAwsMskCluster tolerates a bare arn (for cross-account typed refs from Pipes/Firehose/Replicator).
// When the cluster is accessible, DescribeClusterV2 populates all scalar fields; on access denied (cross-account)
// the resource falls back to a minimal shell with just arn/__id so callers can still traverse other fields.
// When invoked with no args (e.g. via asset identifier from platform discovery),
// it pulls the arn from the discovered asset.
func initAwsMskCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) >= 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformMskCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws msk cluster")
	}
	arnVal := args["arn"].Value.(string)
	parsed, err := arn.Parse(arnVal)
	if err != nil {
		args["__id"] = llx.StringData(arnVal)
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Kafka(parsed.Region)
	out, err := svc.DescribeClusterV2(context.Background(), &kafka.DescribeClusterV2Input{ClusterArn: &arnVal})
	if err != nil {
		if Is400AccessDeniedError(err) {
			args["__id"] = llx.StringData(arnVal)
			return args, nil, nil
		}
		return nil, nil, err
	}
	if out.ClusterInfo == nil {
		args["__id"] = llx.StringData(arnVal)
		return args, nil, nil
	}
	mqlCluster, err := newMqlAwsMskCluster(runtime, parsed.Region, parsed.AccountID, *out.ClusterInfo)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlCluster, nil
}

func (a *mqlAwsMskCluster) fetchDescribe() (*kafka.DescribeClusterV2Output, error) {
	a.describeOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		out, err := svc.DescribeClusterV2(context.Background(), &kafka.DescribeClusterV2Input{ClusterArn: &a.Arn.Data})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.describeErr = nil
				return
			}
			a.describeErr = err
			return
		}
		a.describeResp = out
	})
	return a.describeResp, a.describeErr
}

func (a *mqlAwsMskCluster) fetchBootstrap() (*kafka.GetBootstrapBrokersOutput, error) {
	a.bootstrapOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		out, err := svc.GetBootstrapBrokers(context.Background(), &kafka.GetBootstrapBrokersInput{ClusterArn: &a.Arn.Data})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.bootstrapErr = nil
				return
			}
			a.bootstrapErr = err
			return
		}
		a.bootstrapResp = out
	})
	return a.bootstrapResp, a.bootstrapErr
}

func (a *mqlAwsMskCluster) fetchPolicy() (*kafka.GetClusterPolicyOutput, error) {
	a.policyOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		out, err := svc.GetClusterPolicy(context.Background(), &kafka.GetClusterPolicyInput{ClusterArn: &a.Arn.Data})
		if err != nil {
			var notFound *kafka_types.NotFoundException
			if errors.As(err, &notFound) {
				a.policyErr = nil
				return
			}
			if Is400AccessDeniedError(err) {
				a.policyErr = nil
				return
			}
			a.policyErr = err
			return
		}
		a.policyResp = out
	})
	return a.policyResp, a.policyErr
}

func (a *mqlAwsMskCluster) fetchScramSecrets() ([]string, error) {
	a.scramOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		ctx := context.Background()
		paginator := kafka.NewListScramSecretsPaginator(svc, &kafka.ListScramSecretsInput{ClusterArn: &a.Arn.Data})
		var secrets []string
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					a.scramErr = nil
					return
				}
				a.scramErr = err
				return
			}
			secrets = append(secrets, page.SecretArnList...)
		}
		a.scramSecrets = secrets
	})
	return a.scramSecrets, a.scramErr
}

func (a *mqlAwsMskCluster) fetchNodes() ([]kafka_types.NodeInfo, error) {
	a.nodesOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		ctx := context.Background()
		paginator := kafka.NewListNodesPaginator(svc, &kafka.ListNodesInput{ClusterArn: &a.Arn.Data})
		var nodes []kafka_types.NodeInfo
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					a.nodesErr = nil
					return
				}
				a.nodesErr = err
				return
			}
			nodes = append(nodes, page.NodeInfoList...)
		}
		a.nodesData = nodes
	})
	return a.nodesData, a.nodesErr
}

func (a *mqlAwsMskCluster) fetchOperations() ([]kafka_types.ClusterOperationV2Summary, error) {
	a.opsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		ctx := context.Background()
		paginator := kafka.NewListClusterOperationsV2Paginator(svc, &kafka.ListClusterOperationsV2Input{ClusterArn: &a.Arn.Data})
		var ops []kafka_types.ClusterOperationV2Summary
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					a.opsErr = nil
					return
				}
				a.opsErr = err
				return
			}
			ops = append(ops, page.ClusterOperationInfoList...)
		}
		a.opsData = ops
	})
	return a.opsData, a.opsErr
}

func (a *mqlAwsMskCluster) fetchClientVpcConnections() ([]kafka_types.ClientVpcConnection, error) {
	a.clientVpcOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		ctx := context.Background()
		paginator := kafka.NewListClientVpcConnectionsPaginator(svc, &kafka.ListClientVpcConnectionsInput{ClusterArn: &a.Arn.Data})
		var cvs []kafka_types.ClientVpcConnection
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					a.clientVpcsErr = nil
					return
				}
				a.clientVpcsErr = err
				return
			}
			cvs = append(cvs, page.ClientVpcConnections...)
		}
		a.clientVpcs = cvs
	})
	return a.clientVpcs, a.clientVpcsErr
}

// ===== existing scalar accessors =====

func (a *mqlAwsMskCluster) kafkaVersion() (string, error) {
	if a.provisioned == nil {
		a.KafkaVersion.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	if a.provisioned.CurrentBrokerSoftwareInfo != nil && a.provisioned.CurrentBrokerSoftwareInfo.KafkaVersion != nil {
		return *a.provisioned.CurrentBrokerSoftwareInfo.KafkaVersion, nil
	}
	a.KafkaVersion.State = plugin.StateIsNull | plugin.StateIsSet
	return "", nil
}

func (a *mqlAwsMskCluster) numberOfBrokerNodes() (int64, error) {
	if a.provisioned == nil {
		a.NumberOfBrokerNodes.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	if a.provisioned.NumberOfBrokerNodes != nil {
		return int64(*a.provisioned.NumberOfBrokerNodes), nil
	}
	a.NumberOfBrokerNodes.State = plugin.StateIsNull | plugin.StateIsSet
	return 0, nil
}

func (a *mqlAwsMskCluster) brokerInstanceType() (string, error) {
	if a.provisioned == nil {
		a.BrokerInstanceType.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	if a.provisioned.BrokerNodeGroupInfo != nil && a.provisioned.BrokerNodeGroupInfo.InstanceType != nil {
		return *a.provisioned.BrokerNodeGroupInfo.InstanceType, nil
	}
	a.BrokerInstanceType.State = plugin.StateIsNull | plugin.StateIsSet
	return "", nil
}

func (a *mqlAwsMskCluster) encryptionInTransitClientBroker() (string, error) {
	if a.provisioned == nil {
		a.EncryptionInTransitClientBroker.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	if a.provisioned.EncryptionInfo != nil && a.provisioned.EncryptionInfo.EncryptionInTransit != nil {
		return string(a.provisioned.EncryptionInfo.EncryptionInTransit.ClientBroker), nil
	}
	a.EncryptionInTransitClientBroker.State = plugin.StateIsNull | plugin.StateIsSet
	return "", nil
}

func (a *mqlAwsMskCluster) encryptionInTransitInCluster() (bool, error) {
	if a.provisioned == nil {
		a.EncryptionInTransitInCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if a.provisioned.EncryptionInfo != nil && a.provisioned.EncryptionInfo.EncryptionInTransit != nil {
		if a.provisioned.EncryptionInfo.EncryptionInTransit.InCluster != nil {
			return *a.provisioned.EncryptionInfo.EncryptionInTransit.InCluster, nil
		}
	}
	a.EncryptionInTransitInCluster.State = plugin.StateIsNull | plugin.StateIsSet
	return false, nil
}

func (a *mqlAwsMskCluster) kmsKey() (*mqlAwsKmsKey, error) {
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

func (a *mqlAwsMskCluster) iamAuthEnabled() (bool, error) {
	if a.provisioned == nil {
		a.IamAuthEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if ca := a.provisioned.ClientAuthentication; ca != nil && ca.Sasl != nil && ca.Sasl.Iam != nil && ca.Sasl.Iam.Enabled != nil {
		return *ca.Sasl.Iam.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) scramAuthEnabled() (bool, error) {
	if a.provisioned == nil {
		a.ScramAuthEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if ca := a.provisioned.ClientAuthentication; ca != nil && ca.Sasl != nil && ca.Sasl.Scram != nil && ca.Sasl.Scram.Enabled != nil {
		return *ca.Sasl.Scram.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) tlsAuthEnabled() (bool, error) {
	if a.provisioned == nil {
		a.TlsAuthEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if ca := a.provisioned.ClientAuthentication; ca != nil && ca.Tls != nil && ca.Tls.Enabled != nil {
		return *ca.Tls.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) unauthenticatedEnabled() (bool, error) {
	if a.provisioned == nil {
		a.UnauthenticatedEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if ca := a.provisioned.ClientAuthentication; ca != nil && ca.Unauthenticated != nil && ca.Unauthenticated.Enabled != nil {
		return *ca.Unauthenticated.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) anyAuthEnabled() (bool, error) {
	if a.provisioned != nil {
		if ca := a.provisioned.ClientAuthentication; ca != nil {
			if ca.Sasl != nil {
				if ca.Sasl.Iam != nil && ca.Sasl.Iam.Enabled != nil && *ca.Sasl.Iam.Enabled {
					return true, nil
				}
				if ca.Sasl.Scram != nil && ca.Sasl.Scram.Enabled != nil && *ca.Sasl.Scram.Enabled {
					return true, nil
				}
			}
			if ca.Tls != nil && ca.Tls.Enabled != nil && *ca.Tls.Enabled {
				return true, nil
			}
		}
		return false, nil
	}
	if a.serverless != nil {
		if sca := a.serverless.ClientAuthentication; sca != nil && sca.Sasl != nil && sca.Sasl.Iam != nil && sca.Sasl.Iam.Enabled != nil {
			return *sca.Sasl.Iam.Enabled, nil
		}
	}
	return false, nil
}

func (a *mqlAwsMskCluster) publicAccess() (bool, error) {
	if a.provisioned == nil {
		a.PublicAccess.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if a.provisioned.BrokerNodeGroupInfo != nil {
		ci := a.provisioned.BrokerNodeGroupInfo.ConnectivityInfo
		if ci != nil && ci.PublicAccess != nil && ci.PublicAccess.Type != nil {
			return *ci.PublicAccess.Type != "DISABLED", nil
		}
	}
	return false, nil
}

func (a *mqlAwsMskCluster) cloudwatchLogsEnabled() (bool, error) {
	if a.provisioned == nil {
		a.CloudwatchLogsEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if li := a.provisioned.LoggingInfo; li != nil && li.BrokerLogs != nil && li.BrokerLogs.CloudWatchLogs != nil && li.BrokerLogs.CloudWatchLogs.Enabled != nil {
		return *li.BrokerLogs.CloudWatchLogs.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) cloudwatchLogsGroup() (string, error) {
	if a.provisioned == nil {
		a.CloudwatchLogsGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	if li := a.provisioned.LoggingInfo; li != nil && li.BrokerLogs != nil && li.BrokerLogs.CloudWatchLogs != nil && li.BrokerLogs.CloudWatchLogs.LogGroup != nil {
		return *li.BrokerLogs.CloudWatchLogs.LogGroup, nil
	}
	a.CloudwatchLogsGroup.State = plugin.StateIsNull | plugin.StateIsSet
	return "", nil
}

func (a *mqlAwsMskCluster) s3LogsEnabled() (bool, error) {
	if a.provisioned == nil {
		a.S3LogsEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if li := a.provisioned.LoggingInfo; li != nil && li.BrokerLogs != nil && li.BrokerLogs.S3 != nil && li.BrokerLogs.S3.Enabled != nil {
		return *li.BrokerLogs.S3.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) s3LogsBucket() (string, error) {
	if a.provisioned == nil {
		a.S3LogsBucket.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	if li := a.provisioned.LoggingInfo; li != nil && li.BrokerLogs != nil && li.BrokerLogs.S3 != nil && li.BrokerLogs.S3.Bucket != nil {
		return *li.BrokerLogs.S3.Bucket, nil
	}
	a.S3LogsBucket.State = plugin.StateIsNull | plugin.StateIsSet
	return "", nil
}

func (a *mqlAwsMskCluster) firehoseLogsEnabled() (bool, error) {
	if a.provisioned == nil {
		a.FirehoseLogsEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if li := a.provisioned.LoggingInfo; li != nil && li.BrokerLogs != nil && li.BrokerLogs.Firehose != nil && li.BrokerLogs.Firehose.Enabled != nil {
		return *li.BrokerLogs.Firehose.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) enhancedMonitoring() (string, error) {
	if a.provisioned == nil {
		a.EnhancedMonitoring.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(a.provisioned.EnhancedMonitoring), nil
}

func (a *mqlAwsMskCluster) jmxExporterEnabled() (bool, error) {
	if a.provisioned == nil {
		a.JmxExporterEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if om := a.provisioned.OpenMonitoring; om != nil && om.Prometheus != nil && om.Prometheus.JmxExporter != nil && om.Prometheus.JmxExporter.EnabledInBroker != nil {
		return *om.Prometheus.JmxExporter.EnabledInBroker, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) nodeExporterEnabled() (bool, error) {
	if a.provisioned == nil {
		a.NodeExporterEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	if om := a.provisioned.OpenMonitoring; om != nil && om.Prometheus != nil && om.Prometheus.NodeExporter != nil && om.Prometheus.NodeExporter.EnabledInBroker != nil {
		return *om.Prometheus.NodeExporter.EnabledInBroker, nil
	}
	return false, nil
}

func (a *mqlAwsMskCluster) securityGroups() ([]any, error) {
	if a.provisioned == nil {
		a.SecurityGroups.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsMskCluster) subnets() ([]any, error) {
	if a.provisioned == nil {
		a.Subnets.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
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

// ===== new cluster scalar accessors =====

func (a *mqlAwsMskCluster) storageMode() (string, error) {
	if a.provisioned == nil {
		a.StorageMode.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(a.provisioned.StorageMode), nil
}

func (a *mqlAwsMskCluster) networkType() (string, error) {
	if a.provisioned != nil {
		if bni := a.provisioned.BrokerNodeGroupInfo; bni != nil && bni.ConnectivityInfo != nil {
			return string(bni.ConnectivityInfo.NetworkType), nil
		}
		a.NetworkType.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	if a.serverless != nil && a.serverless.ConnectivityInfo != nil {
		return string(a.serverless.ConnectivityInfo.NetworkType), nil
	}
	a.NetworkType.State = plugin.StateIsNull | plugin.StateIsSet
	return "", nil
}

func (a *mqlAwsMskCluster) ebsVolumeSizeGiB() (int64, error) {
	if a.provisioned == nil {
		a.EbsVolumeSizeGiB.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	if bni := a.provisioned.BrokerNodeGroupInfo; bni != nil && bni.StorageInfo != nil && bni.StorageInfo.EbsStorageInfo != nil && bni.StorageInfo.EbsStorageInfo.VolumeSize != nil {
		return int64(*bni.StorageInfo.EbsStorageInfo.VolumeSize), nil
	}
	a.EbsVolumeSizeGiB.State = plugin.StateIsNull | plugin.StateIsSet
	return 0, nil
}

func (a *mqlAwsMskCluster) zookeeperConnectString() (string, error) {
	if a.provisioned == nil || a.provisioned.ZookeeperConnectString == nil {
		a.ZookeeperConnectString.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *a.provisioned.ZookeeperConnectString, nil
}

func (a *mqlAwsMskCluster) zookeeperConnectStringTls() (string, error) {
	if a.provisioned == nil || a.provisioned.ZookeeperConnectStringTls == nil {
		a.ZookeeperConnectStringTls.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *a.provisioned.ZookeeperConnectStringTls, nil
}

func (a *mqlAwsMskCluster) configurationArn() (string, error) {
	if a.provisioned == nil {
		a.ConfigurationArn.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.ClusterInfo == nil || resp.ClusterInfo.Provisioned == nil || resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo == nil || resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.ConfigurationArn == nil {
		a.ConfigurationArn.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.ConfigurationArn, nil
}

func (a *mqlAwsMskCluster) configurationRevision() (int64, error) {
	if a.provisioned == nil {
		a.ConfigurationRevision.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	resp, err := a.fetchDescribe()
	if err != nil {
		return 0, err
	}
	if resp == nil || resp.ClusterInfo == nil || resp.ClusterInfo.Provisioned == nil || resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo == nil || resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.ConfigurationRevision == nil {
		a.ConfigurationRevision.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return *resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.ConfigurationRevision, nil
}

func (a *mqlAwsMskCluster) configuration() (*mqlAwsMskConfiguration, error) {
	if a.provisioned == nil {
		a.Configuration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	resp, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.ClusterInfo == nil || resp.ClusterInfo.Provisioned == nil || resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo == nil || resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.ConfigurationArn == nil {
		a.Configuration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	cfgArn := *resp.ClusterInfo.Provisioned.CurrentBrokerSoftwareInfo.ConfigurationArn
	mqlCfg, err := NewResource(a.MqlRuntime, "aws.msk.configuration",
		map[string]*llx.RawData{"arn": llx.StringData(cfgArn)})
	if err != nil {
		return nil, err
	}
	return mqlCfg.(*mqlAwsMskConfiguration), nil
}

// ===== grouping sub-resources =====

func (a *mqlAwsMskCluster) encryptionInfo() (*mqlAwsMskClusterEncryptionInfo, error) {
	var (
		atRestArn string
		ct        string
		inCluster bool
		hasInfo   bool
		kmsArn    *string
	)
	if a.provisioned != nil {
		ei := a.provisioned.EncryptionInfo
		if ei != nil {
			hasInfo = true
			if ei.EncryptionAtRest != nil && ei.EncryptionAtRest.DataVolumeKMSKeyId != nil {
				atRestArn = *ei.EncryptionAtRest.DataVolumeKMSKeyId
				kmsArn = ei.EncryptionAtRest.DataVolumeKMSKeyId
			}
			if ei.EncryptionInTransit != nil {
				ct = string(ei.EncryptionInTransit.ClientBroker)
				if ei.EncryptionInTransit.InCluster != nil {
					inCluster = *ei.EncryptionInTransit.InCluster
				}
			}
		}
	}
	if !hasInfo && a.serverless != nil {
		hasInfo = true
	}
	if !hasInfo {
		a.EncryptionInfo.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"__id":                  llx.StringData(a.Arn.Data + "/encryptionInfo"),
		"atRestKmsKeyArn":       llx.StringData(atRestArn),
		"inTransitClientBroker": llx.StringData(ct),
		"inTransitInCluster":    llx.BoolData(inCluster),
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.encryptionInfo", args)
	if err != nil {
		return nil, err
	}
	mqlEI := resource.(*mqlAwsMskClusterEncryptionInfo)
	mqlEI.cacheKmsKeyArn = kmsArn

	if a.provisioned != nil && a.provisioned.EncryptionInfo != nil && a.provisioned.EncryptionInfo.EncryptionInTransit == nil {
		mqlEI.InTransitClientBroker.State = plugin.StateIsNull | plugin.StateIsSet
		mqlEI.InTransitInCluster.State = plugin.StateIsNull | plugin.StateIsSet
	}
	if kmsArn == nil || *kmsArn == "" {
		mqlEI.AtRestKmsKeyArn.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return mqlEI, nil
}

func (a *mqlAwsMskClusterEncryptionInfo) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsMskCluster) clientAuthentication() (*mqlAwsMskClusterClientAuthentication, error) {
	var (
		iam, scram, tls, unauth bool
		caArns                  []string
	)
	any_ := false
	if a.provisioned != nil {
		if ca := a.provisioned.ClientAuthentication; ca != nil {
			if ca.Sasl != nil {
				if ca.Sasl.Iam != nil && ca.Sasl.Iam.Enabled != nil && *ca.Sasl.Iam.Enabled {
					iam = true
				}
				if ca.Sasl.Scram != nil && ca.Sasl.Scram.Enabled != nil && *ca.Sasl.Scram.Enabled {
					scram = true
				}
			}
			if ca.Tls != nil {
				if ca.Tls.Enabled != nil && *ca.Tls.Enabled {
					tls = true
				}
				caArns = append(caArns, ca.Tls.CertificateAuthorityArnList...)
			}
			if ca.Unauthenticated != nil && ca.Unauthenticated.Enabled != nil && *ca.Unauthenticated.Enabled {
				unauth = true
			}
		}
	} else if a.serverless != nil {
		if sca := a.serverless.ClientAuthentication; sca != nil && sca.Sasl != nil && sca.Sasl.Iam != nil && sca.Sasl.Iam.Enabled != nil {
			iam = *sca.Sasl.Iam.Enabled
		}
	}
	any_ = iam || scram || tls

	caArnsAny := make([]any, 0, len(caArns))
	for _, v := range caArns {
		caArnsAny = append(caArnsAny, v)
	}

	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.clientAuthentication",
		map[string]*llx.RawData{
			"__id":                     llx.StringData(a.Arn.Data + "/clientAuthentication"),
			"iamEnabled":               llx.BoolData(iam),
			"scramEnabled":             llx.BoolData(scram),
			"tlsEnabled":               llx.BoolData(tls),
			"unauthenticatedEnabled":   llx.BoolData(unauth),
			"anyEnabled":               llx.BoolData(any_),
			"certificateAuthorityArns": llx.ArrayData(caArnsAny, types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlCA := resource.(*mqlAwsMskClusterClientAuthentication)
	mqlCA.clusterArn = a.Arn.Data
	mqlCA.region = a.region
	mqlCA.cacheTlsCaArns = caArns
	return mqlCA, nil
}

func (a *mqlAwsMskClusterClientAuthentication) scramSecrets() ([]any, error) {
	// Need cluster arn — stored in internal.
	parent, err := NewResource(a.MqlRuntime, "aws.msk.cluster",
		map[string]*llx.RawData{"arn": llx.StringData(a.clusterArn)})
	if err != nil {
		return nil, err
	}
	mqlCluster := parent.(*mqlAwsMskCluster)
	secrets, err := mqlCluster.fetchScramSecrets()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(secrets))
	for _, arnVal := range secrets {
		mqlSecret, err := NewResource(a.MqlRuntime, ResourceAwsSecretsmanagerSecret,
			map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSecret)
	}
	return res, nil
}

func (a *mqlAwsMskClusterClientAuthentication) tlsCertificateAuthorities() ([]any, error) {
	res := make([]any, 0, len(a.cacheTlsCaArns))
	for _, caArn := range a.cacheTlsCaArns {
		mqlCA, err := NewResource(a.MqlRuntime, ResourceAwsPrivatecaCertificateAuthority,
			map[string]*llx.RawData{"arn": llx.StringData(caArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCA)
	}
	return res, nil
}

func (a *mqlAwsMskCluster) brokerNodeGroup() (*mqlAwsMskClusterBrokerNodeGroup, error) {
	if a.provisioned == nil || a.provisioned.BrokerNodeGroupInfo == nil {
		a.BrokerNodeGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	bni := a.provisioned.BrokerNodeGroupInfo

	instanceType := ""
	if bni.InstanceType != nil {
		instanceType = *bni.InstanceType
	}

	networkType := ""
	publicAccessType := ""
	var vpcConn *kafka_types.VpcConnectivity
	if bni.ConnectivityInfo != nil {
		networkType = string(bni.ConnectivityInfo.NetworkType)
		if pa := bni.ConnectivityInfo.PublicAccess; pa != nil && pa.Type != nil {
			publicAccessType = *pa.Type
		}
		vpcConn = bni.ConnectivityInfo.VpcConnectivity
	}
	publicAccessEnabled := publicAccessType != "" && publicAccessType != "DISABLED"

	var volumeSize int64
	var ebsProvThroughEnabled bool
	var ebsProvThroughMBps int64
	if bni.StorageInfo != nil && bni.StorageInfo.EbsStorageInfo != nil {
		if bni.StorageInfo.EbsStorageInfo.VolumeSize != nil {
			volumeSize = int64(*bni.StorageInfo.EbsStorageInfo.VolumeSize)
		}
		if pt := bni.StorageInfo.EbsStorageInfo.ProvisionedThroughput; pt != nil {
			if pt.Enabled != nil {
				ebsProvThroughEnabled = *pt.Enabled
			}
			if pt.VolumeThroughput != nil {
				ebsProvThroughMBps = int64(*pt.VolumeThroughput)
			}
		}
	}

	zoneIds := make([]any, 0, len(bni.ZoneIds))
	for _, z := range bni.ZoneIds {
		zoneIds = append(zoneIds, z)
	}

	args := map[string]*llx.RawData{
		"__id":                            llx.StringData(a.Arn.Data + "/brokerNodeGroup"),
		"instanceType":                    llx.StringData(instanceType),
		"brokerAZDistribution":            llx.StringData(string(bni.BrokerAZDistribution)),
		"zoneIds":                         llx.ArrayData(zoneIds, types.String),
		"networkType":                     llx.StringData(networkType),
		"ebsVolumeSizeGiB":                llx.IntData(volumeSize),
		"ebsProvisionedThroughputEnabled": llx.BoolData(ebsProvThroughEnabled),
		"ebsProvisionedThroughputMBps":    llx.IntData(ebsProvThroughMBps),
		"storageMode":                     llx.StringData(string(a.provisioned.StorageMode)),
		"publicAccessType":                llx.StringData(publicAccessType),
		"publicAccessEnabled":             llx.BoolData(publicAccessEnabled),
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.brokerNodeGroup", args)
	if err != nil {
		return nil, err
	}
	mqlBNG := resource.(*mqlAwsMskClusterBrokerNodeGroup)
	mqlBNG.region = a.region
	mqlBNG.accountID = a.accountID
	mqlBNG.clusterArn = a.Arn.Data
	mqlBNG.cacheSubnetIds = bni.ClientSubnets
	mqlBNG.cacheVpcConn = vpcConn
	sgs := make([]string, 0, len(bni.SecurityGroups))
	for _, sg := range bni.SecurityGroups {
		sgs = append(sgs, NewSecurityGroupArn(a.region, a.accountID, sg))
	}
	mqlBNG.setSecurityGroupArns(sgs)
	return mqlBNG, nil
}

func (a *mqlAwsMskClusterBrokerNodeGroup) subnets() ([]any, error) {
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

func (a *mqlAwsMskClusterBrokerNodeGroup) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsMskClusterBrokerNodeGroup) vpcConnectivity() (*mqlAwsMskClusterVpcConnectivity, error) {
	var iam, scram, tls bool
	if a.cacheVpcConn != nil && a.cacheVpcConn.ClientAuthentication != nil {
		cva := a.cacheVpcConn.ClientAuthentication
		if cva.Sasl != nil {
			if cva.Sasl.Iam != nil && cva.Sasl.Iam.Enabled != nil && *cva.Sasl.Iam.Enabled {
				iam = true
			}
			if cva.Sasl.Scram != nil && cva.Sasl.Scram.Enabled != nil && *cva.Sasl.Scram.Enabled {
				scram = true
			}
		}
		if cva.Tls != nil && cva.Tls.Enabled != nil && *cva.Tls.Enabled {
			tls = true
		}
	}
	any_ := iam || scram || tls
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.vpcConnectivity",
		map[string]*llx.RawData{
			"__id":         llx.StringData(a.clusterArn + "/brokerNodeGroup/vpcConnectivity"),
			"iamEnabled":   llx.BoolData(iam),
			"scramEnabled": llx.BoolData(scram),
			"tlsEnabled":   llx.BoolData(tls),
			"anyEnabled":   llx.BoolData(any_),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMskClusterVpcConnectivity), nil
}

func (a *mqlAwsMskCluster) loggingInfo() (*mqlAwsMskClusterLoggingInfo, error) {
	if a.provisioned == nil {
		a.LoggingInfo.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	var cw *kafka_types.CloudWatchLogs
	var fh *kafka_types.Firehose
	var s3 *kafka_types.S3
	var hasAny bool
	if li := a.provisioned.LoggingInfo; li != nil && li.BrokerLogs != nil {
		cw = li.BrokerLogs.CloudWatchLogs
		fh = li.BrokerLogs.Firehose
		s3 = li.BrokerLogs.S3
		if cw != nil && cw.Enabled != nil && *cw.Enabled {
			hasAny = true
		}
		if fh != nil && fh.Enabled != nil && *fh.Enabled {
			hasAny = true
		}
		if s3 != nil && s3.Enabled != nil && *s3.Enabled {
			hasAny = true
		}
	}

	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.loggingInfo",
		map[string]*llx.RawData{
			"__id":          llx.StringData(a.Arn.Data + "/loggingInfo"),
			"hasAnyEnabled": llx.BoolData(hasAny),
		})
	if err != nil {
		return nil, err
	}
	mqlLI := resource.(*mqlAwsMskClusterLoggingInfo)
	mqlLI.region = a.region
	mqlLI.accountID = a.accountID
	mqlLI.clusterArn = a.Arn.Data
	mqlLI.cacheCloudwatch = cw
	mqlLI.cacheFirehose = fh
	mqlLI.cacheS3 = s3
	return mqlLI, nil
}

func (a *mqlAwsMskClusterLoggingInfo) cloudwatchLogs() (*mqlAwsMskClusterLoggingInfoCloudwatchLogs, error) {
	if a.cacheCloudwatch == nil {
		a.CloudwatchLogs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enabled := false
	if a.cacheCloudwatch.Enabled != nil {
		enabled = *a.cacheCloudwatch.Enabled
	}
	logGroupName := ""
	var lgPtr *string
	if a.cacheCloudwatch.LogGroup != nil {
		logGroupName = *a.cacheCloudwatch.LogGroup
		lgPtr = a.cacheCloudwatch.LogGroup
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.loggingInfo.cloudwatchLogs",
		map[string]*llx.RawData{
			"__id":         llx.StringData(a.clusterArn + "/loggingInfo/cloudwatchLogs"),
			"enabled":      llx.BoolData(enabled),
			"logGroupName": llx.StringData(logGroupName),
		})
	if err != nil {
		return nil, err
	}
	mqlCW := resource.(*mqlAwsMskClusterLoggingInfoCloudwatchLogs)
	mqlCW.region = a.region
	mqlCW.accountID = a.accountID
	mqlCW.cacheLogGroup = lgPtr
	return mqlCW, nil
}

func (a *mqlAwsMskClusterLoggingInfoCloudwatchLogs) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroup == nil || *a.cacheLogGroup == "" {
		a.LogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s:*", a.region, a.accountID, *a.cacheLogGroup)
	mqlLG, err := NewResource(a.MqlRuntime, ResourceAwsCloudwatchLoggroup,
		map[string]*llx.RawData{"arn": llx.StringData(logGroupArn)})
	if err != nil {
		return nil, err
	}
	return mqlLG.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsMskClusterLoggingInfo) firehose() (*mqlAwsMskClusterLoggingInfoFirehose, error) {
	if a.cacheFirehose == nil {
		a.Firehose.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enabled := false
	if a.cacheFirehose.Enabled != nil {
		enabled = *a.cacheFirehose.Enabled
	}
	streamName := ""
	var streamPtr *string
	if a.cacheFirehose.DeliveryStream != nil {
		streamName = *a.cacheFirehose.DeliveryStream
		streamPtr = a.cacheFirehose.DeliveryStream
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.loggingInfo.firehose",
		map[string]*llx.RawData{
			"__id":               llx.StringData(a.clusterArn + "/loggingInfo/firehose"),
			"enabled":            llx.BoolData(enabled),
			"deliveryStreamName": llx.StringData(streamName),
		})
	if err != nil {
		return nil, err
	}
	mqlFH := resource.(*mqlAwsMskClusterLoggingInfoFirehose)
	mqlFH.region = a.region
	mqlFH.accountID = a.accountID
	mqlFH.cacheDeliveryStream = streamPtr
	return mqlFH, nil
}

func (a *mqlAwsMskClusterLoggingInfoFirehose) deliveryStream() (*mqlAwsKinesisFirehoseDeliveryStream, error) {
	if a.cacheDeliveryStream == nil || *a.cacheDeliveryStream == "" {
		a.DeliveryStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	streamArn := fmt.Sprintf("arn:aws:firehose:%s:%s:deliverystream/%s", a.region, a.accountID, *a.cacheDeliveryStream)
	mqlFH, err := NewResource(a.MqlRuntime, ResourceAwsKinesisFirehoseDeliveryStream,
		map[string]*llx.RawData{"arn": llx.StringData(streamArn)})
	if err != nil {
		return nil, err
	}
	return mqlFH.(*mqlAwsKinesisFirehoseDeliveryStream), nil
}

func (a *mqlAwsMskClusterLoggingInfo) s3() (*mqlAwsMskClusterLoggingInfoS3, error) {
	if a.cacheS3 == nil {
		a.S3.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enabled := false
	if a.cacheS3.Enabled != nil {
		enabled = *a.cacheS3.Enabled
	}
	bucketName := ""
	var bucketPtr *string
	if a.cacheS3.Bucket != nil {
		bucketName = *a.cacheS3.Bucket
		bucketPtr = a.cacheS3.Bucket
	}
	prefix := ""
	if a.cacheS3.Prefix != nil {
		prefix = *a.cacheS3.Prefix
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.loggingInfo.s3",
		map[string]*llx.RawData{
			"__id":       llx.StringData(a.clusterArn + "/loggingInfo/s3"),
			"enabled":    llx.BoolData(enabled),
			"bucketName": llx.StringData(bucketName),
			"prefix":     llx.StringData(prefix),
		})
	if err != nil {
		return nil, err
	}
	mqlS3 := resource.(*mqlAwsMskClusterLoggingInfoS3)
	mqlS3.cacheBucket = bucketPtr
	return mqlS3, nil
}

func (a *mqlAwsMskClusterLoggingInfoS3) bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheBucket == nil || *a.cacheBucket == "" {
		a.Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket,
		map[string]*llx.RawData{"name": llx.StringDataPtr(a.cacheBucket)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsMskCluster) monitoring() (*mqlAwsMskClusterMonitoring, error) {
	if a.provisioned == nil {
		a.Monitoring.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enhanced := string(a.provisioned.EnhancedMonitoring)
	var jmx, node bool
	if om := a.provisioned.OpenMonitoring; om != nil && om.Prometheus != nil {
		if om.Prometheus.JmxExporter != nil && om.Prometheus.JmxExporter.EnabledInBroker != nil {
			jmx = *om.Prometheus.JmxExporter.EnabledInBroker
		}
		if om.Prometheus.NodeExporter != nil && om.Prometheus.NodeExporter.EnabledInBroker != nil {
			node = *om.Prometheus.NodeExporter.EnabledInBroker
		}
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.monitoring",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(a.Arn.Data + "/monitoring"),
			"enhancedMonitoring":   llx.StringData(enhanced),
			"jmxExporterEnabled":   llx.BoolData(jmx),
			"nodeExporterEnabled":  llx.BoolData(node),
			"prometheusAnyEnabled": llx.BoolData(jmx || node),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMskClusterMonitoring), nil
}

func (a *mqlAwsMskCluster) bootstrapBrokers() (*mqlAwsMskClusterBootstrapBrokers, error) {
	resp, err := a.fetchBootstrap()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		a.BootstrapBrokers.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	strOrEmpty := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	plaintext := strOrEmpty(resp.BootstrapBrokerString)
	tls := strOrEmpty(resp.BootstrapBrokerStringTls)
	saslIam := strOrEmpty(resp.BootstrapBrokerStringSaslIam)
	saslScram := strOrEmpty(resp.BootstrapBrokerStringSaslScram)
	publicTls := strOrEmpty(resp.BootstrapBrokerStringPublicTls)
	publicSaslIam := strOrEmpty(resp.BootstrapBrokerStringPublicSaslIam)
	publicSaslScram := strOrEmpty(resp.BootstrapBrokerStringPublicSaslScram)
	vpcTls := strOrEmpty(resp.BootstrapBrokerStringVpcConnectivityTls)
	vpcSaslIam := strOrEmpty(resp.BootstrapBrokerStringVpcConnectivitySaslIam)
	vpcSaslScram := strOrEmpty(resp.BootstrapBrokerStringVpcConnectivitySaslScram)
	ipv6Tls := strOrEmpty(resp.BootstrapBrokerStringTlsIpv6)
	ipv6SaslIam := strOrEmpty(resp.BootstrapBrokerStringSaslIamIpv6)
	ipv6SaslScram := strOrEmpty(resp.BootstrapBrokerStringSaslScramIpv6)

	hasPublic := publicTls != "" || publicSaslIam != "" || publicSaslScram != ""
	hasPlaintext := plaintext != ""

	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.bootstrapBrokers",
		map[string]*llx.RawData{
			"__id":                     llx.StringData(a.Arn.Data + "/bootstrapBrokers"),
			"plaintext":                llx.StringData(plaintext),
			"tls":                      llx.StringData(tls),
			"saslIam":                  llx.StringData(saslIam),
			"saslScram":                llx.StringData(saslScram),
			"publicTls":                llx.StringData(publicTls),
			"publicSaslIam":            llx.StringData(publicSaslIam),
			"publicSaslScram":          llx.StringData(publicSaslScram),
			"vpcConnectivityTls":       llx.StringData(vpcTls),
			"vpcConnectivitySaslIam":   llx.StringData(vpcSaslIam),
			"vpcConnectivitySaslScram": llx.StringData(vpcSaslScram),
			"ipv6Tls":                  llx.StringData(ipv6Tls),
			"ipv6SaslIam":              llx.StringData(ipv6SaslIam),
			"ipv6SaslScram":            llx.StringData(ipv6SaslScram),
			"hasPublicEndpoint":        llx.BoolData(hasPublic),
			"hasPlaintextEndpoint":     llx.BoolData(hasPlaintext),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMskClusterBootstrapBrokers), nil
}

func (a *mqlAwsMskCluster) clusterPolicy() (*mqlAwsMskClusterClusterPolicy, error) {
	resp, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	hasPolicy := resp != nil && resp.Policy != nil && *resp.Policy != ""
	policy := ""
	version := ""
	if resp != nil {
		if resp.Policy != nil {
			policy = *resp.Policy
		}
		if resp.CurrentVersion != nil {
			version = *resp.CurrentVersion
		}
	}
	hasExternal, wildcard := analyzeMskPolicy(policy, a.accountID)

	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.clusterPolicy",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(a.Arn.Data + "/clusterPolicy"),
			"currentVersion":          llx.StringData(version),
			"policy":                  llx.StringData(policy),
			"hasPolicy":               llx.BoolData(hasPolicy),
			"hasExternalPrincipals":   llx.BoolData(hasExternal),
			"allowsWildcardPrincipal": llx.BoolData(wildcard),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMskClusterClusterPolicy), nil
}

func analyzeMskPolicy(policy string, accountID string) (hasExternal bool, wildcard bool) {
	if policy == "" {
		return false, false
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return false, false
	}
	statements, ok := doc["Statement"].([]any)
	if !ok {
		if st, ok2 := doc["Statement"].(map[string]any); ok2 {
			statements = []any{st}
		}
	}
	for _, s := range statements {
		stmt, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(toString(stmt["Effect"]), "Deny") {
			continue
		}
		principal := stmt["Principal"]
		if principal == nil {
			continue
		}
		switch p := principal.(type) {
		case string:
			if p == "*" {
				wildcard = true
				hasExternal = true
			}
		case map[string]any:
			for _, v := range p {
				switch vv := v.(type) {
				case string:
					if vv == "*" {
						wildcard = true
						hasExternal = true
						continue
					}
					if isExternalMskArn(vv, accountID) {
						hasExternal = true
					}
				case []any:
					for _, item := range vv {
						s := toString(item)
						if s == "*" {
							wildcard = true
							hasExternal = true
							continue
						}
						if isExternalMskArn(s, accountID) {
							hasExternal = true
						}
					}
				}
			}
		}
	}
	return hasExternal, wildcard
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func isExternalMskArn(candidate, accountID string) bool {
	if accountID == "" || candidate == "" {
		return false
	}
	if parsed, err := arn.Parse(candidate); err == nil {
		return parsed.AccountID != "" && parsed.AccountID != accountID
	}
	return false
}

func (a *mqlAwsMskCluster) operations() ([]any, error) {
	ops, err := a.fetchOperations()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(ops))
	for _, op := range ops {
		opState := ""
		if op.OperationState != nil {
			opState = *op.OperationState
		}
		opType := ""
		if op.OperationType != nil {
			opType = *op.OperationType
		}
		var created *llx.RawData
		if op.StartTime != nil {
			created = llx.TimeData(*op.StartTime)
		} else {
			created = llx.NilData
		}
		var ended *llx.RawData
		if op.EndTime != nil {
			ended = llx.TimeData(*op.EndTime)
		} else {
			ended = llx.NilData
		}
		resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.operation",
			map[string]*llx.RawData{
				"__id":           llx.StringDataPtr(op.OperationArn),
				"arn":            llx.StringDataPtr(op.OperationArn),
				"operationType":  llx.StringData(opType),
				"operationState": llx.StringData(opState),
				"createdAt":      created,
				"endTime":        ended,
				"errorCode":      llx.StringData(""),
				"errorString":    llx.StringData(""),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (a *mqlAwsMskCluster) nodes() ([]any, error) {
	nodes, err := a.fetchNodes()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(nodes))
	for _, node := range nodes {
		instanceType := ""
		if node.InstanceType != nil {
			instanceType = *node.InstanceType
		}
		addedAt := ""
		if node.AddedToClusterTime != nil {
			addedAt = *node.AddedToClusterTime
		}
		var brokerId int64
		var clientSubnetId, clientVpcIp, eniId string
		endpoints := make([]any, 0)
		var subnetPtr, eniPtr *string
		if node.BrokerNodeInfo != nil {
			if node.BrokerNodeInfo.BrokerId != nil {
				brokerId = int64(*node.BrokerNodeInfo.BrokerId)
			}
			if node.BrokerNodeInfo.ClientSubnet != nil {
				clientSubnetId = *node.BrokerNodeInfo.ClientSubnet
				subnetPtr = node.BrokerNodeInfo.ClientSubnet
			}
			if node.BrokerNodeInfo.ClientVpcIpAddress != nil {
				clientVpcIp = *node.BrokerNodeInfo.ClientVpcIpAddress
			}
			if node.BrokerNodeInfo.AttachedENIId != nil {
				eniId = *node.BrokerNodeInfo.AttachedENIId
				eniPtr = node.BrokerNodeInfo.AttachedENIId
			}
			for _, ep := range node.BrokerNodeInfo.Endpoints {
				endpoints = append(endpoints, ep)
			}
		}
		args := map[string]*llx.RawData{
			"__id":               llx.StringDataPtr(node.NodeARN),
			"nodeArn":            llx.StringDataPtr(node.NodeARN),
			"nodeType":           llx.StringData(string(node.NodeType)),
			"instanceType":       llx.StringData(instanceType),
			"addedToClusterTime": llx.StringData(addedAt),
			"brokerId":           llx.IntData(brokerId),
			"clientSubnetId":     llx.StringData(clientSubnetId),
			"clientVpcIpAddress": llx.StringData(clientVpcIp),
			"attachedENIId":      llx.StringData(eniId),
			"endpoints":          llx.ArrayData(endpoints, types.String),
		}
		resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.node", args)
		if err != nil {
			return nil, err
		}
		mqlNode := resource.(*mqlAwsMskClusterNode)
		mqlNode.region = a.region
		mqlNode.accountID = a.accountID
		mqlNode.cacheSubnetId = subnetPtr
		mqlNode.cacheEniId = eniPtr
		res = append(res, mqlNode)
	}
	return res, nil
}

func (a *mqlAwsMskClusterNode) subnet() (*mqlAwsVpcSubnet, error) {
	if a.cacheSubnetId == nil || *a.cacheSubnetId == "" {
		a.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	subnetArn := fmt.Sprintf(subnetArnPattern, a.region, a.accountID, *a.cacheSubnetId)
	mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
		map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlAwsVpcSubnet), nil
}

func (a *mqlAwsMskClusterNode) networkInterface() (*mqlAwsEc2Networkinterface, error) {
	if a.cacheEniId == nil || *a.cacheEniId == "" {
		a.NetworkInterface.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlEni, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
		map[string]*llx.RawData{
			"id": llx.StringDataPtr(a.cacheEniId),
		})
	if err != nil {
		return nil, err
	}
	return mqlEni.(*mqlAwsEc2Networkinterface), nil
}

func (a *mqlAwsMskCluster) clientVpcConnections() ([]any, error) {
	conns, err := a.fetchClientVpcConnections()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(conns))
	for _, c := range conns {
		auth := ""
		if c.Authentication != nil {
			auth = *c.Authentication
		}
		owner := ""
		if c.Owner != nil {
			owner = *c.Owner
		}
		var created *llx.RawData
		if c.CreationTime != nil {
			created = llx.TimeData(*c.CreationTime)
		} else {
			created = llx.NilData
		}
		crossAccount := owner != "" && a.accountID != "" && owner != a.accountID
		resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.clientVpcConnection",
			map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(c.VpcConnectionArn),
				"vpcConnectionArn": llx.StringDataPtr(c.VpcConnectionArn),
				"authentication":   llx.StringData(auth),
				"state":            llx.StringData(string(c.State)),
				"owner":            llx.StringData(owner),
				"createdAt":        created,
				"isCrossAccount":   llx.BoolData(crossAccount),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (a *mqlAwsMskCluster) serverlessConfig() (*mqlAwsMskClusterServerlessConfig, error) {
	if a.serverless == nil {
		a.ServerlessConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	iamEnabled := false
	if sca := a.serverless.ClientAuthentication; sca != nil && sca.Sasl != nil && sca.Sasl.Iam != nil && sca.Sasl.Iam.Enabled != nil {
		iamEnabled = *sca.Sasl.Iam.Enabled
	}
	networkType := ""
	if a.serverless.ConnectivityInfo != nil {
		networkType = string(a.serverless.ConnectivityInfo.NetworkType)
	}

	vpcConfigs := make([]any, 0, len(a.serverless.VpcConfigs))
	for _, vc := range a.serverless.VpcConfigs {
		subnetIds := make([]any, 0, len(vc.SubnetIds))
		for _, s := range vc.SubnetIds {
			subnetIds = append(subnetIds, s)
		}
		sgIds := make([]any, 0, len(vc.SecurityGroupIds))
		for _, s := range vc.SecurityGroupIds {
			sgIds = append(sgIds, s)
		}
		idHash := hashSorted(vc.SubnetIds)
		subArns := make([]string, 0, len(vc.SecurityGroupIds))
		for _, sg := range vc.SecurityGroupIds {
			subArns = append(subArns, NewSecurityGroupArn(a.region, a.accountID, sg))
		}
		vcRes, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.serverlessConfig.vpcConfig",
			map[string]*llx.RawData{
				"__id": llx.StringData(a.Arn.Data + "/serverless/vpc/" + idHash),
			})
		if err != nil {
			return nil, err
		}
		mqlVC := vcRes.(*mqlAwsMskClusterServerlessConfigVpcConfig)
		mqlVC.region = a.region
		mqlVC.accountID = a.accountID
		mqlVC.cacheSubnetIds = append(mqlVC.cacheSubnetIds, vc.SubnetIds...)
		mqlVC.setSecurityGroupArns(subArns)
		vpcConfigs = append(vpcConfigs, mqlVC)
	}

	resource, err := CreateResource(a.MqlRuntime, "aws.msk.cluster.serverlessConfig",
		map[string]*llx.RawData{
			"__id":        llx.StringData(a.Arn.Data + "/serverlessConfig"),
			"iamEnabled":  llx.BoolData(iamEnabled),
			"networkType": llx.StringData(networkType),
			"vpcConfigs":  llx.ArrayData(vpcConfigs, types.Resource("aws.msk.cluster.serverlessConfig.vpcConfig")),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsMskClusterServerlessConfig), nil
}

func hashSorted(vals []string) string {
	copied := make([]string, len(vals))
	copy(copied, vals)
	sort.Strings(copied)
	h := sha1.Sum([]byte(strings.Join(copied, ",")))
	return hex.EncodeToString(h[:])
}

func (a *mqlAwsMskClusterServerlessConfigVpcConfig) subnets() ([]any, error) {
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

func (a *mqlAwsMskClusterServerlessConfigVpcConfig) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

// ===== aws.msk.configuration =====

func newMqlAwsMskConfiguration(runtime *plugin.Runtime, region string, cfg kafka_types.Configuration) (*mqlAwsMskConfiguration, error) {
	description := ""
	if cfg.Description != nil {
		description = *cfg.Description
	}
	var latest int64
	if cfg.LatestRevision != nil && cfg.LatestRevision.Revision != nil {
		latest = *cfg.LatestRevision.Revision
	}
	kafkaVersions := make([]any, 0, len(cfg.KafkaVersions))
	for _, v := range cfg.KafkaVersions {
		kafkaVersions = append(kafkaVersions, v)
	}
	var created *llx.RawData
	if cfg.CreationTime != nil {
		created = llx.TimeData(*cfg.CreationTime)
	} else {
		created = llx.NilData
	}

	resource, err := CreateResource(runtime, "aws.msk.configuration",
		map[string]*llx.RawData{
			"__id":           llx.StringDataPtr(cfg.Arn),
			"arn":            llx.StringDataPtr(cfg.Arn),
			"name":           llx.StringDataPtr(cfg.Name),
			"description":    llx.StringData(description),
			"state":          llx.StringData(string(cfg.State)),
			"kafkaVersions":  llx.ArrayData(kafkaVersions, types.String),
			"latestRevision": llx.IntData(latest),
			"createdAt":      created,
			"region":         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlCfg := resource.(*mqlAwsMskConfiguration)
	mqlCfg.region = region
	mqlCfg.latestRevision = latest
	return mqlCfg, nil
}

func initAwsMskConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) >= 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws msk configuration")
	}
	arnVal := args["arn"].Value.(string)
	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, err
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Kafka(parsed.Region)
	out, err := svc.DescribeConfiguration(context.Background(), &kafka.DescribeConfigurationInput{Arn: &arnVal})
	if err != nil {
		if Is400AccessDeniedError(err) {
			args["__id"] = llx.StringData(arnVal)
			args["region"] = llx.StringData(parsed.Region)
			args["name"] = llx.StringData("")
			args["description"] = llx.StringData("")
			args["state"] = llx.StringData("")
			args["kafkaVersions"] = llx.ArrayData([]any{}, types.String)
			args["latestRevision"] = llx.IntData(0)
			args["createdAt"] = llx.NilData
			return args, nil, nil
		}
		return nil, nil, err
	}
	mqlCfg, err := newMqlAwsMskConfiguration(runtime, parsed.Region, kafka_types.Configuration{
		Arn:            out.Arn,
		Name:           out.Name,
		Description:    out.Description,
		State:          out.State,
		KafkaVersions:  out.KafkaVersions,
		LatestRevision: out.LatestRevision,
		CreationTime:   out.CreationTime,
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlCfg, nil
}

func (a *mqlAwsMskConfiguration) serverProperties() (string, error) {
	a.propsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		rev := a.latestRevision
		if rev == 0 {
			a.propsErr = nil
			a.propsData = ""
			return
		}
		out, err := svc.DescribeConfigurationRevision(context.Background(), &kafka.DescribeConfigurationRevisionInput{
			Arn:      &a.Arn.Data,
			Revision: &rev,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.propsErr = nil
				return
			}
			a.propsErr = err
			return
		}
		if out != nil {
			a.propsData = string(out.ServerProperties)
		}
	})
	return a.propsData, a.propsErr
}

// ===== aws.msk.replicator =====

func newMqlAwsMskReplicator(runtime *plugin.Runtime, region, accountID string, summary kafka_types.ReplicatorSummary) (*mqlAwsMskReplicator, error) {
	var createdAt *llx.RawData
	if summary.CreationTime != nil {
		createdAt = llx.TimeData(*summary.CreationTime)
	} else {
		createdAt = llx.NilData
	}
	curVersion := ""
	if summary.CurrentVersion != nil {
		curVersion = *summary.CurrentVersion
	}

	resource, err := CreateResource(runtime, "aws.msk.replicator",
		map[string]*llx.RawData{
			"__id":           llx.StringDataPtr(summary.ReplicatorArn),
			"arn":            llx.StringDataPtr(summary.ReplicatorArn),
			"name":           llx.StringDataPtr(summary.ReplicatorName),
			"state":          llx.StringData(string(summary.ReplicatorState)),
			"currentVersion": llx.StringData(curVersion),
			"createdAt":      createdAt,
			"region":         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlRep := resource.(*mqlAwsMskReplicator)
	mqlRep.region = region
	mqlRep.accountID = accountID
	return mqlRep, nil
}

func (a *mqlAwsMskReplicator) fetchDescribe() (*kafka.DescribeReplicatorOutput, error) {
	a.describeOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kafka(a.region)
		out, err := svc.DescribeReplicator(context.Background(), &kafka.DescribeReplicatorInput{ReplicatorArn: &a.Arn.Data})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.describeErr = nil
				return
			}
			a.describeErr = err
			return
		}
		a.describeResp = out
	})
	return a.describeResp, a.describeErr
}

func (a *mqlAwsMskReplicator) description() (string, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if d == nil || d.ReplicatorDescription == nil {
		a.Description.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *d.ReplicatorDescription, nil
}

func (a *mqlAwsMskReplicator) tags() (map[string]any, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if d == nil {
		return map[string]any{}, nil
	}
	out := make(map[string]any, len(d.Tags))
	for k, v := range d.Tags {
		out[k] = v
	}
	return out, nil
}

func (a *mqlAwsMskReplicator) stateCode() (string, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if d == nil || d.StateInfo == nil || d.StateInfo.Code == nil {
		a.StateCode.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *d.StateInfo.Code, nil
}

func (a *mqlAwsMskReplicator) stateMessage() (string, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if d == nil || d.StateInfo == nil || d.StateInfo.Message == nil {
		a.StateMessage.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *d.StateInfo.Message, nil
}

func (a *mqlAwsMskReplicator) serviceExecutionRole() (*mqlAwsIamRole, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if d == nil || d.ServiceExecutionRoleArn == nil || *d.ServiceExecutionRoleArn == "" {
		a.ServiceExecutionRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(d.ServiceExecutionRoleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsMskReplicator) kafkaClusters() ([]any, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if d == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(d.KafkaClusters))
	for _, kc := range d.KafkaClusters {
		alias := ""
		if kc.KafkaClusterAlias != nil {
			alias = *kc.KafkaClusterAlias
		}
		var mskArnPtr *string
		mskArn := ""
		if kc.AmazonMskCluster != nil && kc.AmazonMskCluster.MskClusterArn != nil {
			mskArn = *kc.AmazonMskCluster.MskClusterArn
			mskArnPtr = kc.AmazonMskCluster.MskClusterArn
		}
		var subnetIdsRaw []string
		var sgIdsRaw []string
		if kc.VpcConfig != nil {
			subnetIdsRaw = kc.VpcConfig.SubnetIds
			sgIdsRaw = kc.VpcConfig.SecurityGroupIds
		}
		subnetIds := make([]any, 0, len(subnetIdsRaw))
		for _, s := range subnetIdsRaw {
			subnetIds = append(subnetIds, s)
		}
		sgIds := make([]any, 0, len(sgIdsRaw))
		for _, s := range sgIdsRaw {
			sgIds = append(sgIds, s)
		}

		bootstrapBrokers := ""
		if kc.ApacheKafkaCluster != nil && kc.ApacheKafkaCluster.BootstrapBrokerString != nil {
			bootstrapBrokers = *kc.ApacheKafkaCluster.BootstrapBrokerString
		}
		authType := ""
		saslMechanism := ""
		var secretArnPtr *string
		if kc.ClientAuthentication != nil {
			if kc.ClientAuthentication.SaslScram != nil {
				authType = "SASL_SCRAM"
				saslMechanism = string(kc.ClientAuthentication.SaslScram.Mechanism)
				secretArnPtr = kc.ClientAuthentication.SaslScram.SecretArn
			} else {
				authType = "NONE"
			}
		}
		encType := ""
		rootCa := ""
		if kc.EncryptionInTransit != nil {
			encType = string(kc.EncryptionInTransit.EncryptionType)
			if kc.EncryptionInTransit.RootCaCertificate != nil {
				rootCa = *kc.EncryptionInTransit.RootCaCertificate
			}
		}

		resource, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.kafkaCluster",
			map[string]*llx.RawData{
				"__id":                        llx.StringData(a.Arn.Data + "/cluster/" + alias),
				"amazonMskClusterArn":         llx.StringData(mskArn),
				"kafkaClusterAlias":           llx.StringData(alias),
				"apacheKafkaBootstrapBrokers": llx.StringData(bootstrapBrokers),
				"authenticationType":          llx.StringData(authType),
				"saslScramMechanism":          llx.StringData(saslMechanism),
				"encryptionInTransitType":     llx.StringData(encType),
				"rootCaCertificate":           llx.StringData(rootCa),
			})
		if err != nil {
			return nil, err
		}
		mqlKC := resource.(*mqlAwsMskReplicatorKafkaCluster)
		mqlKC.region = a.region
		mqlKC.accountID = a.accountID
		mqlKC.cacheMskArn = mskArnPtr
		mqlKC.cacheSecretArn = secretArnPtr
		mqlKC.cacheSubnetIds = append(mqlKC.cacheSubnetIds, subnetIdsRaw...)
		sgArns := make([]string, 0, len(sgIdsRaw))
		for _, sg := range sgIdsRaw {
			sgArns = append(sgArns, NewSecurityGroupArn(a.region, a.accountID, sg))
		}
		mqlKC.setSecurityGroupArns(sgArns)
		res = append(res, mqlKC)
	}
	return res, nil
}

func (a *mqlAwsMskReplicatorKafkaCluster) saslScramSecret() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheSecretArn == nil || *a.cacheSecretArn == "" {
		a.SaslScramSecret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlSecret, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheSecretArn)})
	if err != nil {
		return nil, err
	}
	return mqlSecret.(*mqlAwsSecretsmanagerSecret), nil
}

func (a *mqlAwsMskReplicatorKafkaCluster) cluster() (*mqlAwsMskCluster, error) {
	if a.cacheMskArn == nil || *a.cacheMskArn == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.msk.cluster",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheMskArn)})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsMskCluster), nil
}

func (a *mqlAwsMskReplicatorKafkaCluster) subnets() ([]any, error) {
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

func (a *mqlAwsMskReplicatorKafkaCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsMskReplicator) replicationInfoList() ([]any, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if d == nil {
		return []any{}, nil
	}
	aliasToArn := map[string]string{}
	for _, kc := range d.KafkaClusters {
		if kc.KafkaClusterAlias == nil || kc.AmazonMskCluster == nil || kc.AmazonMskCluster.MskClusterArn == nil {
			continue
		}
		aliasToArn[*kc.KafkaClusterAlias] = *kc.AmazonMskCluster.MskClusterArn
	}

	res := make([]any, 0, len(d.ReplicationInfoList))
	for _, ri := range d.ReplicationInfoList {
		srcAlias := ""
		if ri.SourceKafkaClusterAlias != nil {
			srcAlias = *ri.SourceKafkaClusterAlias
		}
		tgtAlias := ""
		if ri.TargetKafkaClusterAlias != nil {
			tgtAlias = *ri.TargetKafkaClusterAlias
		}
		var srcArn, tgtArn *string
		if v, ok := aliasToArn[srcAlias]; ok {
			srcArn = stringPtr(v)
		}
		if v, ok := aliasToArn[tgtAlias]; ok {
			tgtArn = stringPtr(v)
		}

		resource, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.replicationInfo",
			map[string]*llx.RawData{
				"__id":                    llx.StringData(a.Arn.Data + "/" + srcAlias + "/" + tgtAlias),
				"sourceKafkaClusterAlias": llx.StringData(srcAlias),
				"targetKafkaClusterAlias": llx.StringData(tgtAlias),
				"targetCompressionType":   llx.StringData(string(ri.TargetCompressionType)),
			})
		if err != nil {
			return nil, err
		}
		mqlRI := resource.(*mqlAwsMskReplicatorReplicationInfo)
		mqlRI.sourceArn = srcArn
		mqlRI.targetArn = tgtArn

		// Topic replication sub-resource
		if ri.TopicReplication != nil {
			toReplicate := make([]any, 0, len(ri.TopicReplication.TopicsToReplicate))
			for _, t := range ri.TopicReplication.TopicsToReplicate {
				toReplicate = append(toReplicate, t)
			}
			toExclude := make([]any, 0, len(ri.TopicReplication.TopicsToExclude))
			for _, t := range ri.TopicReplication.TopicsToExclude {
				toExclude = append(toExclude, t)
			}
			startingType := ""
			if ri.TopicReplication.StartingPosition != nil {
				startingType = string(ri.TopicReplication.StartingPosition.Type)
			}
			nameCfgType := ""
			if ri.TopicReplication.TopicNameConfiguration != nil {
				nameCfgType = string(ri.TopicReplication.TopicNameConfiguration.Type)
			}
			copyAcl := false
			if ri.TopicReplication.CopyAccessControlListsForTopics != nil {
				copyAcl = *ri.TopicReplication.CopyAccessControlListsForTopics
			}
			copyCfg := false
			if ri.TopicReplication.CopyTopicConfigurations != nil {
				copyCfg = *ri.TopicReplication.CopyTopicConfigurations
			}
			detectNew := false
			if ri.TopicReplication.DetectAndCopyNewTopics != nil {
				detectNew = *ri.TopicReplication.DetectAndCopyNewTopics
			}
			trRes, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.topicReplication",
				map[string]*llx.RawData{
					"__id":                            llx.StringData(a.Arn.Data + "/" + srcAlias + "/" + tgtAlias + "/topicReplication"),
					"topicsToReplicate":               llx.ArrayData(toReplicate, types.String),
					"topicsToExclude":                 llx.ArrayData(toExclude, types.String),
					"startingPositionType":            llx.StringData(startingType),
					"topicNameConfigurationType":      llx.StringData(nameCfgType),
					"copyAccessControlListsForTopics": llx.BoolData(copyAcl),
					"copyTopicConfigurations":         llx.BoolData(copyCfg),
					"detectAndCopyNewTopics":          llx.BoolData(detectNew),
				})
			if err != nil {
				return nil, err
			}
			mqlRI.TopicReplication.Data = trRes.(*mqlAwsMskReplicatorTopicReplication)
			mqlRI.TopicReplication.State = plugin.StateIsSet
		} else {
			mqlRI.TopicReplication.State = plugin.StateIsSet | plugin.StateIsNull
		}

		// Consumer group replication sub-resource
		if ri.ConsumerGroupReplication != nil {
			toReplicate := make([]any, 0, len(ri.ConsumerGroupReplication.ConsumerGroupsToReplicate))
			for _, t := range ri.ConsumerGroupReplication.ConsumerGroupsToReplicate {
				toReplicate = append(toReplicate, t)
			}
			toExclude := make([]any, 0, len(ri.ConsumerGroupReplication.ConsumerGroupsToExclude))
			for _, t := range ri.ConsumerGroupReplication.ConsumerGroupsToExclude {
				toExclude = append(toExclude, t)
			}
			synchronise := false
			if ri.ConsumerGroupReplication.SynchroniseConsumerGroupOffsets != nil {
				synchronise = *ri.ConsumerGroupReplication.SynchroniseConsumerGroupOffsets
			}
			detectNew := false
			if ri.ConsumerGroupReplication.DetectAndCopyNewConsumerGroups != nil {
				detectNew = *ri.ConsumerGroupReplication.DetectAndCopyNewConsumerGroups
			}
			cgRes, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.consumerGroupReplication",
				map[string]*llx.RawData{
					"__id":                            llx.StringData(a.Arn.Data + "/" + srcAlias + "/" + tgtAlias + "/consumerGroupReplication"),
					"consumerGroupsToReplicate":       llx.ArrayData(toReplicate, types.String),
					"consumerGroupsToExclude":         llx.ArrayData(toExclude, types.String),
					"synchroniseConsumerGroupOffsets": llx.BoolData(synchronise),
					"detectAndCopyNewConsumerGroups":  llx.BoolData(detectNew),
					"offsetSyncMode":                  llx.StringData(string(ri.ConsumerGroupReplication.ConsumerGroupOffsetSyncMode)),
				})
			if err != nil {
				return nil, err
			}
			mqlRI.ConsumerGroupReplication.Data = cgRes.(*mqlAwsMskReplicatorConsumerGroupReplication)
			mqlRI.ConsumerGroupReplication.State = plugin.StateIsSet
		} else {
			mqlRI.ConsumerGroupReplication.State = plugin.StateIsSet | plugin.StateIsNull
		}

		res = append(res, mqlRI)
	}
	return res, nil
}

func (a *mqlAwsMskReplicatorReplicationInfo) sourceCluster() (*mqlAwsMskCluster, error) {
	if a.sourceArn == nil || *a.sourceArn == "" {
		a.SourceCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.msk.cluster",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.sourceArn)})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsMskCluster), nil
}

func (a *mqlAwsMskReplicatorReplicationInfo) targetCluster() (*mqlAwsMskCluster, error) {
	if a.targetArn == nil || *a.targetArn == "" {
		a.TargetCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.msk.cluster",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.targetArn)})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsMskCluster), nil
}

func (a *mqlAwsMskReplicatorReplicationInfo) topicReplication() (*mqlAwsMskReplicatorTopicReplication, error) {
	if a.TopicReplication.State&plugin.StateIsSet != 0 && a.TopicReplication.State&plugin.StateIsNull != 0 {
		return nil, nil
	}
	return a.TopicReplication.Data, nil
}

func (a *mqlAwsMskReplicatorReplicationInfo) consumerGroupReplication() (*mqlAwsMskReplicatorConsumerGroupReplication, error) {
	if a.ConsumerGroupReplication.State&plugin.StateIsSet != 0 && a.ConsumerGroupReplication.State&plugin.StateIsNull != 0 {
		return nil, nil
	}
	return a.ConsumerGroupReplication.Data, nil
}

func (a *mqlAwsMskReplicator) isCrossRegion() (bool, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, nil
	}
	regions := map[string]struct{}{}
	for _, kc := range d.KafkaClusters {
		if kc.AmazonMskCluster == nil || kc.AmazonMskCluster.MskClusterArn == nil {
			continue
		}
		if parsed, err := arn.Parse(*kc.AmazonMskCluster.MskClusterArn); err == nil {
			regions[parsed.Region] = struct{}{}
		}
	}
	return len(regions) > 1, nil
}

func (a *mqlAwsMskReplicator) isCrossAccount() (bool, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, nil
	}
	accounts := map[string]struct{}{}
	for _, kc := range d.KafkaClusters {
		if kc.AmazonMskCluster == nil || kc.AmazonMskCluster.MskClusterArn == nil {
			continue
		}
		if parsed, err := arn.Parse(*kc.AmazonMskCluster.MskClusterArn); err == nil {
			accounts[parsed.AccountID] = struct{}{}
		}
	}
	return len(accounts) > 1, nil
}

func stringPtr(s string) *string {
	return &s
}

func (a *mqlAwsMskReplicator) logDelivery() (*mqlAwsMskReplicatorLogDelivery, error) {
	d, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if d == nil || d.LogDelivery == nil || d.LogDelivery.ReplicatorLogDelivery == nil {
		a.LogDelivery.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	ld := d.LogDelivery.ReplicatorLogDelivery

	hasAny := false
	if ld.CloudWatchLogs != nil && ld.CloudWatchLogs.Enabled != nil && *ld.CloudWatchLogs.Enabled {
		hasAny = true
	}
	if ld.Firehose != nil && ld.Firehose.Enabled != nil && *ld.Firehose.Enabled {
		hasAny = true
	}
	if ld.S3 != nil && ld.S3.Enabled != nil && *ld.S3.Enabled {
		hasAny = true
	}

	resource, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.logDelivery",
		map[string]*llx.RawData{
			"__id":          llx.StringData(a.Arn.Data + "/logDelivery"),
			"hasAnyEnabled": llx.BoolData(hasAny),
		})
	if err != nil {
		return nil, err
	}
	mqlLD := resource.(*mqlAwsMskReplicatorLogDelivery)
	mqlLD.replicatorArn = a.Arn.Data
	mqlLD.region = a.region
	mqlLD.accountID = a.accountID
	mqlLD.cacheCW = ld.CloudWatchLogs
	mqlLD.cacheFirehose = ld.Firehose
	mqlLD.cacheS3 = ld.S3
	return mqlLD, nil
}

func (a *mqlAwsMskReplicatorLogDelivery) cloudwatchLogs() (*mqlAwsMskReplicatorLogDeliveryCloudwatchLogs, error) {
	if a.cacheCW == nil {
		a.CloudwatchLogs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enabled := false
	if a.cacheCW.Enabled != nil {
		enabled = *a.cacheCW.Enabled
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.logDelivery.cloudwatchLogs",
		map[string]*llx.RawData{
			"__id":    llx.StringData(a.replicatorArn + "/logDelivery/cloudwatchLogs"),
			"enabled": llx.BoolData(enabled),
		})
	if err != nil {
		return nil, err
	}
	mqlCW := resource.(*mqlAwsMskReplicatorLogDeliveryCloudwatchLogs)
	mqlCW.region = a.region
	mqlCW.accountID = a.accountID
	mqlCW.cacheLogGroup = a.cacheCW.LogGroup
	return mqlCW, nil
}

func (a *mqlAwsMskReplicatorLogDeliveryCloudwatchLogs) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroup == nil || *a.cacheLogGroup == "" {
		a.LogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s:*", a.region, a.accountID, *a.cacheLogGroup)
	mqlLG, err := NewResource(a.MqlRuntime, ResourceAwsCloudwatchLoggroup,
		map[string]*llx.RawData{"arn": llx.StringData(logGroupArn)})
	if err != nil {
		return nil, err
	}
	return mqlLG.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsMskReplicatorLogDelivery) firehose() (*mqlAwsMskReplicatorLogDeliveryFirehose, error) {
	if a.cacheFirehose == nil {
		a.Firehose.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enabled := false
	if a.cacheFirehose.Enabled != nil {
		enabled = *a.cacheFirehose.Enabled
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.logDelivery.firehose",
		map[string]*llx.RawData{
			"__id":    llx.StringData(a.replicatorArn + "/logDelivery/firehose"),
			"enabled": llx.BoolData(enabled),
		})
	if err != nil {
		return nil, err
	}
	mqlFH := resource.(*mqlAwsMskReplicatorLogDeliveryFirehose)
	mqlFH.region = a.region
	mqlFH.accountID = a.accountID
	mqlFH.cacheDeliveryStream = a.cacheFirehose.DeliveryStream
	return mqlFH, nil
}

func (a *mqlAwsMskReplicatorLogDeliveryFirehose) deliveryStream() (*mqlAwsKinesisFirehoseDeliveryStream, error) {
	if a.cacheDeliveryStream == nil || *a.cacheDeliveryStream == "" {
		a.DeliveryStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	streamArn := fmt.Sprintf("arn:aws:firehose:%s:%s:deliverystream/%s", a.region, a.accountID, *a.cacheDeliveryStream)
	mqlFH, err := NewResource(a.MqlRuntime, ResourceAwsKinesisFirehoseDeliveryStream,
		map[string]*llx.RawData{"arn": llx.StringData(streamArn)})
	if err != nil {
		return nil, err
	}
	return mqlFH.(*mqlAwsKinesisFirehoseDeliveryStream), nil
}

func (a *mqlAwsMskReplicatorLogDelivery) s3() (*mqlAwsMskReplicatorLogDeliveryS3, error) {
	if a.cacheS3 == nil {
		a.S3.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	enabled := false
	if a.cacheS3.Enabled != nil {
		enabled = *a.cacheS3.Enabled
	}
	prefix := ""
	if a.cacheS3.Prefix != nil {
		prefix = *a.cacheS3.Prefix
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.msk.replicator.logDelivery.s3",
		map[string]*llx.RawData{
			"__id":    llx.StringData(a.replicatorArn + "/logDelivery/s3"),
			"enabled": llx.BoolData(enabled),
			"prefix":  llx.StringData(prefix),
		})
	if err != nil {
		return nil, err
	}
	mqlS3 := resource.(*mqlAwsMskReplicatorLogDeliveryS3)
	mqlS3.cacheBucket = a.cacheS3.Bucket
	return mqlS3, nil
}

func (a *mqlAwsMskReplicatorLogDeliveryS3) bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheBucket == nil || *a.cacheBucket == "" {
		a.Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringDataPtr(a.cacheBucket)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}
