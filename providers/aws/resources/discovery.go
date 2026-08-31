// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/utils/stringx"
)

// Discovery Flags
const (
	DiscoveryInstances    = "instances"
	DiscoverySSMInstances = "ssm-instances"
	DiscoveryECR          = "ecr"
	DiscoveryECS          = "ecs"

	DiscoveryAll  = "all"  // all discovery targets
	DiscoveryAuto = "auto" // account + resources

	// API scan
	DiscoveryAccounts                    = "accounts"
	DiscoveryOrg                         = "organization"
	DiscoveryResources                   = "resources"          // all the resources
	DiscoveryECSContainersAPI            = "ecs-containers-api" // need dedup story
	DiscoveryECRImageAPI                 = "ecr-image-api"      // need policy + dedup story
	DiscoveryEC2InstanceAPI              = "ec2-instances-api"  // need policy + dedup story
	DiscoverySSMInstanceAPI              = "ssm-instances-api"  // need policy + dedup story
	DiscoveryS3Buckets                   = "s3-buckets"
	DiscoveryEKSClusters                 = "eks-clusters"
	DiscoveryCloudtrailTrails            = "cloudtrail-trails"
	DiscoveryRdsDbInstances              = "rds-dbinstances"
	DiscoveryRdsDbClusters               = "rds-dbclusters"
	DiscoveryRdsSnapshots                = "rds-snapshots"
	DiscoveryVPCs                        = "vpcs"
	DiscoverySecurityGroups              = "security-groups"
	DiscoveryIAMUsers                    = "iam-users"
	DiscoveryIAMGroups                   = "iam-groups"
	DiscoveryCloudwatchLoggroups         = "cloudwatch-loggroups"
	DiscoveryLambdaFunctions             = "lambda-functions"
	DiscoveryDynamoDBTables              = "dynamodb-tables"
	DiscoveryDynamoDBGlobalTables        = "dynamodb-global-tables"
	DiscoveryRedshiftClusters            = "redshift-clusters"
	DiscoveryVolumes                     = "ec2-volumes"
	DiscoverySnapshots                   = "ec2-snapshots"
	DiscoveryEFSFilesystems              = "efs-filesystems"
	DiscoveryAPIGatewayRestAPIs          = "gateway-restapis"
	DiscoveryELBLoadBalancers            = "elb-loadbalancers"
	DiscoveryESDomains                   = "es-domains"
	DiscoveryOpenSearchDomains           = "opensearch-domains"
	DiscoveryKMSKeys                     = "kms-keys"
	DiscoverySagemakerNotebookInstances  = "sagemaker-notebookinstances"
	DiscoverySagemakerProcessingJobs     = "sagemaker-processingjobs"
	DiscoverySagemakerTrainingJobs       = "sagemaker-trainingjobs"
	DiscoverySagemakerDomains            = "sagemaker-domains"
	DiscoverySagemakerModels             = "sagemaker-models"
	DiscoverySecretsManagerSecrets       = "secretsmanager-secrets"
	DiscoveryElasticacheClusters         = "elasticache-clusters"
	DiscoveryCloudfrontDistributions     = "cloudfront-distributions"
	DiscoveryNeptuneClusters             = "neptune-clusters"
	DiscoveryEMRClusters                 = "emr-clusters"
	DiscoveryDocumentDBClusters          = "documentdb-clusters"
	DiscoveryMskClusters                 = "msk-clusters"
	DiscoveryMqBrokers                   = "mq-brokers"
	DiscoveryEcsTaskDefinitions          = "ecs-taskdefinitions"
	DiscoveryRoute53HostedZones          = "route53-hostedzones"
	DiscoveryEcrRepositories             = "ecr-repositories"
	DiscoveryMemorydbClusters            = "memorydb-clusters"
	DiscoveryCodebuildProjects           = "codebuild-projects"
	DiscoveryCognitoUserPools            = "cognito-userpools"
	DiscoveryTransferServers             = "transfer-servers"
	DiscoveryAPIGatewayV2APIs            = "apigatewayv2-apis"
	DiscoveryAthenaWorkgroups            = "athena-workgroups"
	DiscoveryAppStreamFleets             = "appstream-fleets"
	DiscoveryBatchJobDefinitions         = "batch-jobdefinitions"
	DiscoveryDirectoryServiceDirectories = "directoryservice-directories"
	DiscoveryDocumentDBInstances         = "documentdb-instances"
	DiscoverySnsTopics                   = "sns-topics"
	DiscoverySqsQueues                   = "sqs-queues"
)

var AllAPIResources = []string{
	// DiscoveryECSContainersAPI,
	// DiscoveryECRImageAPI,
	// DiscoveryEC2InstanceAPI,
	// DiscoverySSMInstanceAPI,
	DiscoveryS3Buckets,
	DiscoveryEKSClusters,
	DiscoveryCloudtrailTrails,
	DiscoveryRdsDbInstances,
	DiscoveryRdsDbClusters,
	DiscoveryVPCs,
	DiscoverySecurityGroups,
	DiscoveryIAMUsers,
	DiscoveryIAMGroups,
	DiscoveryCloudwatchLoggroups,
	DiscoveryLambdaFunctions,
	DiscoveryDynamoDBTables,
	DiscoveryDynamoDBGlobalTables,
	DiscoveryRedshiftClusters,
	DiscoveryRdsSnapshots,
	DiscoveryVolumes,
	DiscoverySnapshots,
	DiscoveryEFSFilesystems,
	DiscoveryAPIGatewayRestAPIs,
	DiscoveryELBLoadBalancers,
	DiscoveryESDomains,
	DiscoveryOpenSearchDomains,
	DiscoveryKMSKeys,
	DiscoverySagemakerNotebookInstances,
	DiscoverySagemakerProcessingJobs,
	DiscoverySagemakerTrainingJobs,
	DiscoverySagemakerDomains,
	DiscoverySagemakerModels,
	DiscoverySecretsManagerSecrets,
	DiscoveryElasticacheClusters,
	DiscoveryCloudfrontDistributions,
	DiscoveryNeptuneClusters,
	DiscoveryEMRClusters,
	DiscoveryDocumentDBClusters,
	DiscoveryMskClusters,
	DiscoveryMqBrokers,
	DiscoveryEcsTaskDefinitions,
	DiscoveryRoute53HostedZones,
	DiscoveryEcrRepositories,
	DiscoveryMemorydbClusters,
	DiscoveryCodebuildProjects,
	DiscoveryCognitoUserPools,
	DiscoveryTransferServers,
	DiscoveryAPIGatewayV2APIs,
	DiscoveryAthenaWorkgroups,
	DiscoveryAppStreamFleets,
	DiscoveryBatchJobDefinitions,
	DiscoveryDirectoryServiceDirectories,
	DiscoveryDocumentDBInstances,
	DiscoverySnsTopics,
	DiscoverySqsQueues,
}

var Auto = append(
	[]string{DiscoveryAccounts},
	AllAPIResources...,
)

// All includes every discovery target: Auto plus OS-level instance discovery,
// SSM instances, ECR, and ECS.
var All = append(
	slices.Clone(Auto),
	DiscoveryInstances,
	DiscoverySSMInstances,
	DiscoveryECR,
	DiscoveryECS,
)

func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	res, err := NewResource(runtime, ResourceAwsAccount, map[string]*llx.RawData{"id": llx.StringData("aws.account/" + conn.AccountId())})
	if err != nil {
		return nil, err
	}

	awsAccount := res.(*mqlAwsAccount)

	targets := getDiscoveryTargets(conn.Conf)
	for _, target := range targets {
		list, err := discover(runtime, awsAccount, target, conn.Filters)
		if err != nil {
			log.Error().Err(err).Msg("error during discovery")
			continue
		}
		in.Spec.Assets = append(in.Spec.Assets, list...)
	}

	if conn.Filters.PropagateAccountTags {
		accountTags := conn.Filters.AccountTags
		if len(accountTags) == 0 {
			accountTags = fetchPrimaryAccountTags(awsAccount)
		}
		primaryAccountId := trimAwsAccountIdToJustId(awsAccount.Id.Data)
		applyAccountTagsToAssets(in.Spec.Assets, accountTags, primaryAccountId)
	}

	return in, nil
}

// fetchPrimaryAccountTags returns the primary AWS account's tags as a plain
// string map. Any error reading tags is logged and an empty map is returned so
// discovery can proceed.
func fetchPrimaryAccountTags(awsAccount *mqlAwsAccount) map[string]string {
	t := awsAccount.GetTags()
	if t == nil {
		return map[string]string{}
	}
	if t.Error != nil {
		log.Warn().Err(t.Error).Msg("failed to read AWS account tags; proceeding without account-level tag propagation")
		return map[string]string{}
	}
	if t.Data == nil {
		return map[string]string{}
	}
	return mapStringInterfaceToStringString(t.Data)
}

func getDiscoveryTargets(config *inventory.Config) []string {
	targets := config.GetDiscover().GetTargets()

	if stringx.Contains(targets, DiscoveryAll) {
		// return all discovery targets
		return All
	}

	// the targets we return.
	res := []string{}
	for _, target := range targets {
		switch target {
		case DiscoveryAuto:
			res = append(res, Auto...)
		case DiscoveryResources:
			res = append(res, AllAPIResources...)
		default:
			res = append(res, target)
		}
	}

	return stringx.DedupStringArray(res)
}

// for now we have to post process the filters
// more ideally, we should pass the filters in when discovering
// so that we don't unnecessarily discover assets we will later discard
func discover(runtime *plugin.Runtime, awsAccount *mqlAwsAccount, target string, filters connection.DiscoveryFilters) ([]*inventory.Asset, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	accountId := trimAwsAccountIdToJustId(awsAccount.Id.Data)
	assetList := []*inventory.Asset{}
	switch target {
	case DiscoveryOrg:
		res, err := NewResource(runtime, "aws.organization", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}
		org := res.(*mqlAwsOrganization)

		accounts := org.GetAccounts()
		if accounts == nil {
			return assetList, nil
		}

		for i := range accounts.Data {
			awsAccount := accounts.Data[i].(*mqlAwsAccount)
			assetList = append(assetList, accountAsset(conn, awsAccount))
		}
	case DiscoveryAccounts:
		assetList = append(assetList, accountAsset(conn, awsAccount))
	case DiscoveryInstances:
		res, err := NewResource(runtime, "aws.ec2", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ec2 := res.(*mqlAwsEc2)

		// get instances already filters out instances not matched by the filters specified in the AwsConnection
		ins := ec2.GetInstances()
		if ins == nil {
			return assetList, nil
		}

		for i := range ins.Data {
			instance := ins.Data[i].(*mqlAwsEc2Instance)
			if !ec2InstanceIsDiscoverable(instance.State.Data) {
				continue
			}
			assetList = append(assetList, addConnectionInfoToEc2Asset(instance, accountId, conn))
		}
	case DiscoverySSMInstances:
		res, err := NewResource(runtime, "aws.ssm", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ssm := res.(*mqlAwsSsm)

		ins := ssm.GetInstances()
		if ins == nil {
			return assetList, nil
		}

		for i := range ins.Data {
			instance := ins.Data[i].(*mqlAwsSsmInstance)
			assetList = append(assetList, addConnectionInfoToSSMAsset(instance, accountId, conn))
		}
	case DiscoveryECR:
		res, err := NewResource(runtime, "aws.ecr", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ecr := res.(*mqlAwsEcr)

		images := ecr.GetImages()
		if images == nil {
			return assetList, nil
		}

		for i := range images.Data {
			a := images.Data[i].(*mqlAwsEcrImage)
			ecrAsset := addConnectionInfoToEcrAsset(a, conn)
			if len(ecrAsset.Connections) > 0 {
				assetList = append(assetList, ecrAsset)
			} else {
				log.Warn().Str("name", ecrAsset.Name).Msg("cannot scan ecr image with no tag")
			}
		}
	case DiscoveryECS:
		res, err := NewResource(runtime, "aws.ecs", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ecs := res.(*mqlAwsEcs)

		containers := ecs.GetContainers()
		if containers == nil {
			return assetList, nil
		}

		for i := range containers.Data {
			c := containers.Data[i].(*mqlAwsEcsContainer)
			assetList = append(assetList, addConnectionInfoToECSContainerAsset(c, accountId, conn))
		}
		if filters.Ecs.DiscoverInstances {
			containerInst := ecs.GetContainerInstances()
			if containerInst == nil {
				return assetList, nil
			}

			for i := range containerInst.Data {
				if a, ok := containerInst.Data[i].(*mqlAwsEc2Instance); ok {
					assetList = append(assetList, addConnectionInfoToEc2Asset(a, accountId, conn))
				} else if b, ok := containerInst.Data[i].(*mqlAwsEcsInstance); ok {
					assetList = append(assetList, addConnectionInfoToECSContainerInstanceAsset(b, accountId, conn))
				}
			}
		}
	case DiscoveryECSContainersAPI:
		res, err := NewResource(runtime, "aws.ecs", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ecs := res.(*mqlAwsEcs)

		containers := ecs.GetContainers()
		if containers == nil {
			return assetList, nil
		}

		for i := range containers.Data {
			c := containers.Data[i].(*mqlAwsEcsContainer)
			assetList = append(assetList, MqlObjectToAsset(accountId,
				mqlObject{
					name: c.ContainerName.Data, labels: map[string]string{},
					awsObject: awsObject{
						account: accountId, region: c.Region.Data, arn: c.Arn.Data,
						id: c.Arn.Data, service: "ecs", objectType: "container",
					},
				}, conn))
		}

	case DiscoveryECRImageAPI:
		res, err := NewResource(runtime, ResourceAwsEcr, map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ecr := res.(*mqlAwsEcr)

		images := ecr.GetImages()
		if images == nil {
			return assetList, nil
		}

		for i := range images.Data {
			a := images.Data[i].(*mqlAwsEcrImage)
			l := make(map[string]string)
			for i := range a.Tags.Data {
				l[a.Tags.Data[i].(string)] = ""
			}

			assetList = append(assetList, MqlObjectToAsset(accountId,
				mqlObject{
					name: l["Name"], labels: l,
					awsObject: awsObject{
						account: accountId, region: a.Region.Data, arn: a.Arn.Data,
						id: a.Uri.Data + "/" + a.Digest.Data, service: "ecr", objectType: "image",
					},
				}, conn))
		}
	case DiscoveryEC2InstanceAPI:
		res, err := NewResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ec2 := res.(*mqlAwsEc2)

		// get instances already filters out instances not matched by the filters specified in the AwsConnection
		ins := ec2.GetInstances()
		if ins == nil {
			return assetList, nil
		}

		for i := range ins.Data {
			instance := ins.Data[i].(*mqlAwsEc2Instance)
			l := mapStringInterfaceToStringString(instance.Tags.Data)
			assetList = append(assetList, MqlObjectToAsset(accountId,
				mqlObject{
					name: getInstanceName(instance.InstanceId.Data, l), labels: l,
					awsObject: awsObject{
						account: accountId, region: instance.Region.Data, arn: instance.Arn.Data,
						id: instance.InstanceId.Data, service: "ec2", objectType: "instance",
					},
				}, conn))
		}
	case DiscoverySSMInstanceAPI:
		res, err := NewResource(runtime, ResourceAwsSsm, map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ssm := res.(*mqlAwsSsm)

		ins := ssm.GetInstances()
		if ins == nil {
			return assetList, nil
		}

		for i := range ins.Data {
			instance := ins.Data[i].(*mqlAwsSsmInstance)
			l := mapStringInterfaceToStringString(instance.Tags.Data)
			assetList = append(assetList, MqlObjectToAsset(accountId,
				mqlObject{
					name: getInstanceName(instance.InstanceId.Data, l), labels: l,
					awsObject: awsObject{
						account: accountId, region: instance.Region.Data, arn: instance.Arn.Data,
						id: instance.InstanceId.Data, service: "ssm", objectType: "instance",
					},
				}, conn))
		}
	case DiscoveryS3Buckets:
		res, err := NewResource(runtime, ResourceAwsS3, map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		s := res.(*mqlAwsS3)

		bs := s.GetBuckets()
		if bs == nil {
			return assetList, nil
		}

		for i := range bs.Data {
			f := bs.Data[i].(*mqlAwsS3Bucket)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Location.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "s3", objectType: "bucket",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryEKSClusters:
		res, err := NewResource(runtime, "aws.eks", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		s := res.(*mqlAwsEks)

		bs := s.GetClusters()
		if bs == nil {
			return assetList, nil
		}

		for i := range bs.Data {
			f := bs.Data[i].(*mqlAwsEksCluster)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "eks", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryCloudtrailTrails:
		res, err := NewResource(runtime, "aws.cloudtrail", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		l := res.(*mqlAwsCloudtrail)

		fs := l.GetTrails()
		if fs == nil {
			return assetList, nil
		}

		for i := range fs.Data {
			f := fs.Data[i].(*mqlAwsCloudtrailTrail)

			m := mqlObject{
				name: f.Name.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "cloudtrail", objectType: "trail",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryRdsDbInstances:
		res, err := NewResource(runtime, "aws.rds", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		r := res.(*mqlAwsRds)

		dbs := r.GetInstances()
		if dbs == nil {
			return assetList, nil
		}

		for i := range dbs.Data {
			f := dbs.Data[i].(*mqlAwsRdsDbinstance)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "rds", objectType: "dbinstance",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryRdsDbClusters:
		res, err := NewResource(runtime, "aws.rds", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		r := res.(*mqlAwsRds)

		clusters := r.GetClusters()
		if clusters == nil {
			return assetList, nil
		}

		for i := range clusters.Data {
			f := clusters.Data[i].(*mqlAwsRdsDbcluster)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Id.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "rds", objectType: "dbcluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryVPCs:
		res, err := NewResource(runtime, "aws", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		a := res.(*mqlAws)

		vpcs := a.GetVpcs()
		if vpcs == nil {
			return assetList, nil
		}

		for i := range vpcs.Data {
			f := vpcs.Data[i].(*mqlAwsVpc)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Id.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "vpc", objectType: "vpc",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySecurityGroups:
		res, err := NewResource(runtime, "aws.ec2", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsEc2)

		sgs := e.GetSecurityGroups()
		if sgs == nil {
			return assetList, nil
		}

		for i := range sgs.Data {
			f := sgs.Data[i].(*mqlAwsEc2Securitygroup)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "ec2", objectType: "securitygroup",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryIAMGroups:
		res, err := NewResource(runtime, "aws.iam", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		iam := res.(*mqlAwsIam)

		groups := iam.GetGroups()
		if groups == nil {
			return assetList, nil
		}

		for i := range groups.Data {
			group := groups.Data[i].(*mqlAwsIamGroup)
			labels := map[string]string{}

			m := mqlObject{
				name: group.Name.Data, labels: labels,
				awsObject: awsObject{
					account: accountId, region: "us-east-1", arn: group.Arn.Data,
					id: group.Id.Data, service: "iam", objectType: "group",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryCloudwatchLoggroups:
		res, err := NewResource(runtime, "aws.cloudwatch", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		cw := res.(*mqlAwsCloudwatch)

		lgroups := cw.GetLogGroups()
		if lgroups == nil {
			return assetList, nil
		}

		for i := range lgroups.Data {
			group := lgroups.Data[i].(*mqlAwsCloudwatchLoggroup)
			labels := map[string]string{}

			m := mqlObject{
				name: group.Name.Data, labels: labels,
				awsObject: awsObject{
					account: accountId, region: group.Region.Data, arn: group.Arn.Data,
					id: group.Name.Data, service: "cloudwatch", objectType: "loggroup",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryLambdaFunctions:
		res, err := NewResource(runtime, "aws.lambda", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		l := res.(*mqlAwsLambda)

		fs := l.GetFunctions()
		if fs == nil {
			return assetList, nil
		}

		for i := range fs.Data {
			f := fs.Data[i].(*mqlAwsLambdaFunction)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "lambda", objectType: "function",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryDynamoDBTables:
		res, err := NewResource(runtime, "aws.dynamodb", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		d := res.(*mqlAwsDynamodb)

		ts := d.GetTables()
		if ts == nil {
			return assetList, nil
		}

		for i := range ts.Data {
			f := ts.Data[i].(*mqlAwsDynamodbTable)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "dynamodb", objectType: "table",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryDynamoDBGlobalTables:
		res, err := NewResource(runtime, "aws.dynamodb", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		d := res.(*mqlAwsDynamodb)

		ts := d.GetGlobalTables()
		if ts == nil {
			return assetList, nil
		}

		for i := range ts.Data {
			f := ts.Data[i].(*mqlAwsDynamodbGlobaltable)

			m := mqlObject{
				name: f.Name.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: "us-east-1", arn: f.Arn.Data,
					// Distinct from the regular table objectType: a global table
					// and its us-east-1 replica share a name, so both mapped to
					// the same platform id and merged into one asset.
					id: f.Name.Data, service: "dynamodb", objectType: "globaltable",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryIAMUsers:
		res, err := NewResource(runtime, "aws.iam", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		iam := res.(*mqlAwsIam)

		users := iam.GetUsers()
		if users == nil {
			return assetList, nil
		}

		for i := range users.Data {
			user := users.Data[i].(*mqlAwsIamUser)
			labels := map[string]string{}

			m := mqlObject{
				name: user.Name.Data, labels: labels,
				awsObject: awsObject{
					account: accountId, region: "us-east-1", arn: user.Arn.Data,
					id: user.Id.Data, service: "iam", objectType: "user",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryRedshiftClusters:
		res, err := NewResource(runtime, "aws.redshift", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		r := res.(*mqlAwsRedshift)

		cs := r.GetClusters()
		if cs == nil {
			return assetList, nil
		}

		for i := range cs.Data {
			f := cs.Data[i].(*mqlAwsRedshiftCluster)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "redshift", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryVolumes:
		res, err := NewResource(runtime, "aws.ec2", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsEc2)

		vs := e.GetVolumes()
		if vs == nil {
			return assetList, nil
		}

		for i := range vs.Data {
			f := vs.Data[i].(*mqlAwsEc2Volume)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Id.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "ec2", objectType: "volume",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySnapshots:
		res, err := NewResource(runtime, "aws.ec2", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsEc2)

		s := e.GetSnapshots()
		if s == nil {
			return assetList, nil
		}

		for i := range s.Data {
			f := s.Data[i].(*mqlAwsEc2Snapshot)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Id.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "ec2", objectType: "snapshot",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryEFSFilesystems:
		res, err := NewResource(runtime, "aws.efs", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsEfs)

		fs := e.GetFilesystems()
		if fs == nil {
			return assetList, nil
		}

		for i := range fs.Data {
			f := fs.Data[i].(*mqlAwsEfsFilesystem)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "efs", objectType: "filesystem",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryAPIGatewayRestAPIs:
		res, err := NewResource(runtime, "aws.apigateway", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsApigateway)

		ras := e.GetRestApis()
		if ras == nil {
			return assetList, nil
		}

		for i := range ras.Data {
			f := ras.Data[i].(*mqlAwsApigatewayRestapi)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "gateway", objectType: "restapi",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryRdsSnapshots:
		res, err := NewResource(runtime, "aws.rds", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		r := res.(*mqlAwsRds)

		ras := r.GetSnapshots()
		if ras == nil {
			return assetList, nil
		}

		for i := range ras.Data {
			f := ras.Data[i].(*mqlAwsRdsSnapshot)

			var tags map[string]string
			tagsResult := f.GetTags()
			if tagsResult != nil && tagsResult.Data != nil {
				tags = mapStringInterfaceToStringString(tagsResult.Data)
			}
			m := mqlObject{
				name: f.Id.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "rds", objectType: "snapshot",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryELBLoadBalancers:
		res, err := NewResource(runtime, "aws.elb", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsElb)

		lbs := e.GetLoadBalancers()
		if lbs == nil {
			return assetList, nil
		}

		for i := range lbs.Data {
			f := lbs.Data[i].(*mqlAwsElbLoadbalancer)
			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "elb", objectType: "loadbalancer",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}

		classicLbs := e.GetClassicLoadBalancers()
		if classicLbs == nil {
			return assetList, nil
		}
		for i := range classicLbs.Data {
			f := classicLbs.Data[i].(*mqlAwsElbLoadbalancer)
			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "elb", objectType: "loadbalancer",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryESDomains:
		res, err := NewResource(runtime, "aws.es", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsEs)

		ras := e.GetDomains()
		if ras == nil {
			return assetList, nil
		}

		for i := range ras.Data {
			f := ras.Data[i].(*mqlAwsEsDomain)

			// The legacy ES ListDomainNames API returns domains of BOTH engine
			// types. Domains running the OpenSearch engine belong to
			// DiscoveryOpenSearchDomains (platform aws-opensearch-domain);
			// claiming them here would shadow that platform for every domain.
			if strings.HasPrefix(f.ElasticsearchVersion.Data, "OpenSearch") {
				continue
			}

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "es", objectType: "domain",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryOpenSearchDomains:
		res, err := NewResource(runtime, "aws.opensearch", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		os := res.(*mqlAwsOpensearch)

		ras := os.GetDomains()
		if ras == nil {
			return assetList, nil
		}

		for i := range ras.Data {
			f := ras.Data[i].(*mqlAwsOpensearchDomain)

			// The OpenSearch ListDomainNames API also returns legacy
			// Elasticsearch-engine domains; those are DiscoveryESDomains'
			// assets (platform aws-es-domain).
			if strings.HasPrefix(f.EngineVersion.Data, "Elasticsearch") {
				continue
			}

			var tags map[string]string
			tagsResult := f.GetTags()
			if tagsResult != nil && tagsResult.Data != nil {
				tags = mapStringInterfaceToStringString(tagsResult.Data)
			}
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "opensearch", objectType: "domain",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryKMSKeys:
		res, err := NewResource(runtime, "aws.kms", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsKms)

		ras := e.GetKeys()
		if ras == nil {
			return assetList, nil
		}

		for i := range ras.Data {
			f := ras.Data[i].(*mqlAwsKmsKey)

			m := mqlObject{
				name: f.Id.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "kms", objectType: "key",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySagemakerNotebookInstances:
		res, err := NewResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsSagemaker)

		ras := e.GetNotebookInstances()
		if ras == nil {
			return assetList, nil
		}

		for i := range ras.Data {
			f := ras.Data[i].(*mqlAwsSagemakerNotebookinstance)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "sagemaker", objectType: "notebookinstance",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySecretsManagerSecrets:
		res, err := NewResource(runtime, "aws.secretsmanager", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		sm := res.(*mqlAwsSecretsmanager)

		secrets := sm.GetSecrets()
		if secrets == nil {
			return assetList, nil
		}

		for i := range secrets.Data {
			f := secrets.Data[i].(*mqlAwsSecretsmanagerSecret)

			var region string
			if arn.IsARN(f.Arn.Data) {
				if p, err := arn.Parse(f.Arn.Data); err == nil {
					region = p.Region
				}
			}
			tags := mapStringInterfaceToStringString(f.Tags.Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: region, arn: f.Arn.Data,
					id: f.Name.Data, service: "secretsmanager", objectType: "secret",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryElasticacheClusters:
		res, err := NewResource(runtime, "aws.elasticache", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ec := res.(*mqlAwsElasticache)

		clusters := ec.GetCacheClusters()
		if clusters == nil {
			return assetList, nil
		}
		if clusters.Error != nil {
			return nil, clusters.Error
		}

		for i := range clusters.Data {
			f := clusters.Data[i].(*mqlAwsElasticacheCluster)

			m := mqlObject{
				name: f.CacheClusterId.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.CacheClusterId.Data, service: "elasticache", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryCloudfrontDistributions:
		res, err := NewResource(runtime, "aws.cloudfront", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		cf := res.(*mqlAwsCloudfront)

		distributions := cf.GetDistributions()
		if distributions == nil {
			return assetList, nil
		}
		if distributions.Error != nil {
			return nil, distributions.Error
		}

		for i := range distributions.Data {
			f := distributions.Data[i].(*mqlAwsCloudfrontDistribution)

			m := mqlObject{
				name: f.DomainName.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: "global", arn: f.Arn.Data,
					id: f.DomainName.Data, service: "cloudfront", objectType: "distribution",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryNeptuneClusters:
		res, err := NewResource(runtime, "aws.neptune", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		n := res.(*mqlAwsNeptune)

		cs := n.GetClusters()
		if cs == nil {
			return assetList, nil
		}

		for i := range cs.Data {
			f := cs.Data[i].(*mqlAwsNeptuneCluster)

			name := f.ClusterIdentifier.Data
			if name == "" {
				name = f.Name.Data
			}
			m := mqlObject{
				name: name, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.ClusterIdentifier.Data, service: "neptune", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryEMRClusters:
		res, err := NewResource(runtime, "aws.emr", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		e := res.(*mqlAwsEmr)

		cs := e.GetClusters()
		if cs == nil {
			return assetList, nil
		}

		for i := range cs.Data {
			f := cs.Data[i].(*mqlAwsEmrCluster)

			region, err := GetRegionFromArn(f.Arn.Data)
			if err != nil {
				log.Warn().Err(err).Str("arn", f.Arn.Data).Msg("failed to parse region from EMR cluster ARN")
				continue
			}
			m := mqlObject{
				name: f.Name.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: region, arn: f.Arn.Data,
					id: f.Id.Data, service: "emr", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryDocumentDBClusters:
		res, err := NewResource(runtime, "aws.documentdb", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		d := res.(*mqlAwsDocumentdb)

		cs := d.GetClusters()
		if cs == nil {
			return assetList, nil
		}

		for i := range cs.Data {
			f := cs.Data[i].(*mqlAwsDocumentdbCluster)

			m := mqlObject{
				name: f.Name.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.ClusterIdentifier.Data, service: "documentdb", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySagemakerProcessingJobs:
		res, err := NewResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		sm := res.(*mqlAwsSagemaker)

		jobs := sm.GetProcessingJobs()
		if jobs == nil {
			return assetList, nil
		}

		for i := range jobs.Data {
			f := jobs.Data[i].(*mqlAwsSagemakerProcessingjob)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "sagemaker", objectType: "processingjob",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySagemakerTrainingJobs:
		res, err := NewResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		sm := res.(*mqlAwsSagemaker)

		jobs := sm.GetTrainingJobs()
		if jobs == nil {
			return assetList, nil
		}

		for i := range jobs.Data {
			f := jobs.Data[i].(*mqlAwsSagemakerTrainingjob)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "sagemaker", objectType: "trainingjob",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySagemakerDomains:
		res, err := NewResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		sm := res.(*mqlAwsSagemaker)

		domains := sm.GetDomains()
		if domains == nil {
			return assetList, nil
		}

		for i := range domains.Data {
			f := domains.Data[i].(*mqlAwsSagemakerDomain)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "sagemaker", objectType: "domain",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoverySagemakerModels:
		res, err := NewResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		sm := res.(*mqlAwsSagemaker)

		models := sm.GetModels()
		if models == nil {
			return assetList, nil
		}

		for i := range models.Data {
			f := models.Data[i].(*mqlAwsSagemakerModel)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "sagemaker", objectType: "model",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryMskClusters:
		res, err := NewResource(runtime, "aws.msk", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		msk := res.(*mqlAwsMsk)

		clusters := msk.GetClusters()
		if clusters == nil {
			return assetList, nil
		}

		for i := range clusters.Data {
			f := clusters.Data[i].(*mqlAwsMskCluster)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "msk", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryMqBrokers:
		res, err := NewResource(runtime, "aws.mq", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		m := res.(*mqlAwsMq)

		brokers := m.GetBrokers()
		if brokers == nil {
			return assetList, nil
		}

		for i := range brokers.Data {
			f := brokers.Data[i].(*mqlAwsMqBroker)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.BrokerId.Data, service: "mq", objectType: "broker",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryEcsTaskDefinitions:
		res, err := NewResource(runtime, "aws.ecs", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ecs := res.(*mqlAwsEcs)

		tds := ecs.GetTaskDefinitions()
		if tds == nil {
			return assetList, nil
		}

		for i := range tds.Data {
			f := tds.Data[i].(*mqlAwsEcsTaskDefinition)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			name := f.Arn.Data
			if family := f.GetFamily(); family != nil && family.Data != "" {
				if rev := f.GetRevision(); rev != nil {
					name = family.Data + ":" + strconv.FormatInt(rev.Data, 10)
				} else {
					name = family.Data
				}
			}
			m := mqlObject{
				name: name, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Arn.Data, service: "ecs", objectType: "taskdefinition",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryRoute53HostedZones:
		res, err := NewResource(runtime, "aws.route53", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		r53 := res.(*mqlAwsRoute53)

		zones := r53.GetHostedZones()
		if zones == nil {
			return assetList, nil
		}

		for i := range zones.Data {
			f := zones.Data[i].(*mqlAwsRoute53HostedZone)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: "global", arn: f.Arn.Data,
					id: f.Id.Data, service: "route53", objectType: "hostedzone",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryEcrRepositories:
		res, err := NewResource(runtime, ResourceAwsEcr, map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		ecr := res.(*mqlAwsEcr)

		repos := []any{}
		if priv, err := ecr.privateRepositories(); err == nil {
			repos = append(repos, priv...)
		} else {
			log.Warn().Err(err).Msg("error discovering private ecr repositories")
		}
		if pub, err := ecr.publicRepositories(); err == nil {
			repos = append(repos, pub...)
		} else {
			log.Warn().Err(err).Msg("error discovering public ecr repositories")
		}

		for i := range repos {
			f := repos[i].(*mqlAwsEcrRepository)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			m := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "ecr", objectType: "repository",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, m, conn))
		}
	case DiscoveryMemorydbClusters:
		res, err := NewResource(runtime, "aws.memorydb", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		m := res.(*mqlAwsMemorydb)

		clusters := m.GetClusters()
		if clusters == nil {
			return assetList, nil
		}

		for i := range clusters.Data {
			f := clusters.Data[i].(*mqlAwsMemorydbCluster)

			obj := mqlObject{
				name: f.Name.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "memorydb", objectType: "cluster",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryCodebuildProjects:
		res, err := NewResource(runtime, "aws.codebuild", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		cb := res.(*mqlAwsCodebuild)

		projects := cb.GetProjects()
		if projects == nil {
			return assetList, nil
		}

		for i := range projects.Data {
			f := projects.Data[i].(*mqlAwsCodebuildProject)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "codebuild", objectType: "project",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryCognitoUserPools:
		res, err := NewResource(runtime, "aws.cognito", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		c := res.(*mqlAwsCognito)

		pools := c.GetUserPools()
		if pools == nil {
			return assetList, nil
		}

		for i := range pools.Data {
			f := pools.Data[i].(*mqlAwsCognitoUserPool)

			obj := mqlObject{
				name: f.Name.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Id.Data, service: "cognito", objectType: "userpool",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryTransferServers:
		res, err := NewResource(runtime, "aws.transfer", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		t := res.(*mqlAwsTransfer)

		servers := t.GetServers()
		if servers == nil {
			return assetList, nil
		}

		for i := range servers.Data {
			f := servers.Data[i].(*mqlAwsTransferServer)

			obj := mqlObject{
				name: f.ServerId.Data, labels: map[string]string{},
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.ServerId.Data, service: "transfer", objectType: "server",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryAPIGatewayV2APIs:
		res, err := NewResource(runtime, "aws.apigatewayv2", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		a := res.(*mqlAwsApigatewayv2)

		apis := a.GetApis()
		if apis == nil {
			return assetList, nil
		}
		if apis.Error != nil {
			return nil, apis.Error
		}

		for i := range apis.Data {
			f := apis.Data[i].(*mqlAwsApigatewayv2Api)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.ApiId.Data, service: "apigatewayv2", objectType: "api",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryAthenaWorkgroups:
		res, err := NewResource(runtime, "aws.athena", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		a := res.(*mqlAwsAthena)

		wgs := a.GetWorkgroups()
		if wgs == nil {
			return assetList, nil
		}
		if wgs.Error != nil {
			return nil, wgs.Error
		}

		for i := range wgs.Data {
			f := wgs.Data[i].(*mqlAwsAthenaWorkgroup)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "athena", objectType: "workgroup",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryAppStreamFleets:
		res, err := NewResource(runtime, "aws.appstream", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		a := res.(*mqlAwsAppstream)

		fleets := a.GetFleets()
		if fleets == nil {
			return assetList, nil
		}
		if fleets.Error != nil {
			return nil, fleets.Error
		}

		for i := range fleets.Data {
			f := fleets.Data[i].(*mqlAwsAppstreamFleet)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Name.Data, service: "appstream", objectType: "fleet",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryBatchJobDefinitions:
		res, err := NewResource(runtime, "aws.batch", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		b := res.(*mqlAwsBatch)

		jds := b.GetJobDefinitions()
		if jds == nil {
			return assetList, nil
		}
		if jds.Error != nil {
			return nil, jds.Error
		}

		for i := range jds.Data {
			f := jds.Data[i].(*mqlAwsBatchJobDefinition)

			tags := mapStringInterfaceToStringString(f.Tags.Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Arn.Data, service: "batch", objectType: "jobdefinition",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryDirectoryServiceDirectories:
		res, err := NewResource(runtime, "aws.directoryservice", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		d := res.(*mqlAwsDirectoryservice)

		dirs := d.GetDirectories()
		if dirs == nil {
			return assetList, nil
		}
		if dirs.Error != nil {
			return nil, dirs.Error
		}

		for i := range dirs.Data {
			f := dirs.Data[i].(*mqlAwsDirectoryserviceDirectory)

			// Directory Service directories have no ARN in the API response;
			// synthesize the canonical directory ARN for the platform id.
			dirArn := directoryServiceDirectoryArn(f.Region.Data, accountId, f.DirectoryId.Data)
			name := f.Name.Data
			if name == "" {
				name = f.DirectoryId.Data
			}
			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: name, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: dirArn,
					id: f.DirectoryId.Data, service: "ds", objectType: "directory",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoveryDocumentDBInstances:
		res, err := NewResource(runtime, "aws.documentdb", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		d := res.(*mqlAwsDocumentdb)

		instances := d.GetInstances()
		if instances == nil {
			return assetList, nil
		}
		if instances.Error != nil {
			return nil, instances.Error
		}

		for i := range instances.Data {
			f := instances.Data[i].(*mqlAwsDocumentdbInstance)

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: f.Name.Data, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Arn.Data, service: "documentdb", objectType: "instance",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoverySnsTopics:
		res, err := NewResource(runtime, "aws.sns", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		s := res.(*mqlAwsSns)

		topics := s.GetTopics()
		if topics == nil {
			return assetList, nil
		}
		if topics.Error != nil {
			return nil, topics.Error
		}

		for i := range topics.Data {
			f := topics.Data[i].(*mqlAwsSnsTopic)

			// The resource segment of an SNS topic ARN is the bare topic name.
			topicArn, err := arn.Parse(f.Arn.Data)
			if err != nil {
				log.Error().Err(err).Str("arn", f.Arn.Data).Msg("unable to parse sns topic arn")
				continue
			}

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: topicArn.Resource, labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: f.Arn.Data,
					id: f.Arn.Data, service: "sns", objectType: "topic",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	case DiscoverySqsQueues:
		res, err := NewResource(runtime, "aws.sqs", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}

		s := res.(*mqlAwsSqs)

		queues := s.GetQueues()
		if queues == nil {
			return assetList, nil
		}
		if queues.Error != nil {
			return nil, queues.Error
		}

		for i := range queues.Data {
			f := queues.Data[i].(*mqlAwsSqsQueue)

			// Queues are listed by URL only; the ARN comes from the queue
			// attributes, so skip any queue whose attributes are unreadable
			// rather than emitting an asset with no platform id.
			queueArn := f.GetArn()
			if queueArn.Error != nil {
				log.Error().Err(queueArn.Error).Str("url", f.Url.Data).Msg("unable to fetch sqs queue arn")
				continue
			}

			tags := mapStringInterfaceToStringString(f.GetTags().Data)
			obj := mqlObject{
				name: sqsQueueName(f.Url.Data), labels: tags,
				awsObject: awsObject{
					account: accountId, region: f.Region.Data, arn: queueArn.Data,
					id: queueArn.Data, service: "sqs", objectType: "queue",
				},
			}
			assetList = append(assetList, MqlObjectToAsset(accountId, obj, conn))
		}
	}
	return assetList, nil
}
