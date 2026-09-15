// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/providers/aws/connection/awsec2ebsconn"
	"go.mondoo.com/mql/providers/aws/provider"
	"go.mondoo.com/mql/providers/aws/resources"
)

var Config = plugin.Provider{
	Name:            "aws",
	ID:              "go.mondoo.com/cnquery/v9/providers/aws",
	Version:         "13.53.5",
	ConnectionTypes: []string{provider.DefaultConnectionType, string(awsec2ebsconn.EBSConnectionType)},
	// Throttling is per service and per region, and an organization scan spreads
	// its calls over separate accounts, so the limits are rarely the binding
	// constraint before the CPU cap is.
	DefaultParallelism: 8,
	Connectors: []plugin.Connector{
		{
			Name:  "aws",
			Use:   "aws",
			Short: "an AWS account",
			Long: `Use the aws provider to query the resources in an AWS account.

To query or scan AWS resources, you must have an AWS credentials file. To learn how to create one, read https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html. Mondoo uses the default profile in the credentials file unless you specify a different one using the --profile flag.

Available commands:
  ec2                  		Query or scan an AWS EC2 instance
													Subcommands:
														instance-connect			Access the EC2 instance using Amazon EC2 Instance Connect
																									Provide <user@host>
														ssm										Access the EC2 instance using AWS Systems Manager
																									Provide a path to the identity file
																									--identity-file <path>
														ebs										Query or scan an EBS volume
																									Provide the volume ID
														ebs snapshot					Query or scan an EBS volume snapshot
																									Provide the snapshot ID

Examples:
  cnspec shell aws
	cnspec scan aws
	cnspec scan aws -f mondoo-aws-incident-response.mql.yaml --querypack mondoo-incident-response-aws
	cnspec shell aws --role <role-arn>
	cnspec scan aws ec2 instance-connect <user@host>
	cnspec scan aws ec2 instance-connect <user@host> --identity-file <path>
	cnspec scan aws ec2 ebs <snapshot-id>
	cnspec scan aws --filters regions=ap-south-1,us-east-1

Notes:
  If you set the AWS_PROFILE environment variable, you can omit the profile flag.
	To learn about setting up your AWS credentials, read https://mondoo.com/docs/cnspec/cloud/aws.
`,
			MinArgs: 0,
			MaxArgs: 4,
			Discovery: []string{
				resources.DiscoveryAccounts,
				resources.DiscoveryCloudfrontDistributions,
				resources.DiscoveryCloudtrailTrails,
				resources.DiscoveryCloudwatchLoggroups,
				resources.DiscoveryCodebuildProjects,
				resources.DiscoveryCognitoUserPools,
				resources.DiscoveryDocumentDBClusters,
				resources.DiscoveryDynamoDBGlobalTables,
				resources.DiscoveryDynamoDBTables,
				resources.DiscoveryEC2InstanceAPI,
				resources.DiscoverySnapshots,
				resources.DiscoveryVolumes,
				resources.DiscoveryECR,
				resources.DiscoveryECRImageAPI,
				resources.DiscoveryEcrRepositories,
				resources.DiscoveryECS,
				resources.DiscoveryECSContainersAPI,
				resources.DiscoveryEcsTaskDefinitions,
				resources.DiscoveryEFSFilesystems,
				resources.DiscoveryEKSClusters,
				resources.DiscoveryElasticacheClusters,
				resources.DiscoveryELBLoadBalancers,
				resources.DiscoveryEMRClusters,
				resources.DiscoveryESDomains,
				resources.DiscoveryOpenSearchDomains,
				resources.DiscoveryAPIGatewayRestAPIs,
				resources.DiscoveryIAMGroups,
				resources.DiscoveryIAMUsers,
				resources.DiscoveryInstances,
				resources.DiscoveryKMSKeys,
				resources.DiscoveryLambdaFunctions,
				resources.DiscoveryMemorydbClusters,
				resources.DiscoveryMqBrokers,
				resources.DiscoveryMskClusters,
				resources.DiscoveryNeptuneClusters,
				resources.DiscoveryOrg,
				resources.DiscoveryRdsDbClusters,
				resources.DiscoveryRdsDbInstances,
				resources.DiscoveryRedshiftClusters,
				resources.DiscoveryResources,
				resources.DiscoveryRoute53HostedZones,
				resources.DiscoveryS3Buckets,
				resources.DiscoverySagemakerNotebookInstances,
				resources.DiscoverySagemakerProcessingJobs,
				resources.DiscoverySagemakerTrainingJobs,
				resources.DiscoverySagemakerDomains,
				resources.DiscoverySagemakerModels,
				resources.DiscoverySecretsManagerSecrets,
				resources.DiscoverySecurityGroups,
				resources.DiscoverySSMInstances,
				resources.DiscoverySSMInstanceAPI,
				resources.DiscoveryTransferServers,
				resources.DiscoveryAPIGatewayV2APIs,
				resources.DiscoveryAthenaWorkgroups,
				resources.DiscoveryAppStreamFleets,
				resources.DiscoveryBatchJobDefinitions,
				resources.DiscoveryDirectoryServiceDirectories,
				resources.DiscoveryDocumentDBInstances,
				resources.DiscoverySnsTopics,
				resources.DiscoverySqsQueues,
				resources.DiscoveryVPCs,
			},
			Flags: []plugin.Flag{
				{
					Long:    "profile",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Profile to use when reading from ~/.aws/credentials",
				},
				{
					Long:    "region",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Region to use for authentication with the API (Note: This does not limit the discovery to the region.)",
				},
				{
					Long:    "role",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "ARN of the role to use for authentication with the API",
				},
				{
					Long:    "endpoint-url",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Endpoint URL override for authentication with the API",
				},
				{
					Long:    "no-setup",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Override option for EBS scanning that tells it to not create the snapshot or volume",
				},
				{
					Long:    "scope",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Set the scope for the AWS WAFV2 to either CLOUDFRONT or REGIONAL",
				},
				{
					Long:    "filters",
					Type:    plugin.FlagType_KeyValue,
					Default: "",
					Desc:    "Filter options, e.g., --filters regions=us-east-2,us-east-1 --filters ec2:instance-ids=i-093439483935 --filters s3:bucket-names=my-bucket --filters tag:Environment=production --filters tag:Team=platform --filters exclude:tag:Environment=dev",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=aws"},
			Key:          "account",
			Title:        "Account",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": {
					Key:   "service",
					Title: "Service",
					Values: map[string]*inventory.AssetUrlBranch{
						"account":    nil,
						"s3":         nil,
						"cloudtrail": nil,
						"rds":        nil,
						"vpc":        nil,
						"ec2":        nil,
						"iam":        nil,
						"cloudwatch": nil,
						"lambda":     nil,
						"ecs":        nil,
						"efs":        nil,
						"apigateway": nil,
						"es":         nil,
						"opensearch": nil,
						"kms":        nil,
						"sagemaker":  nil,
						"ecr":        nil,
						"dynamodb":   nil,
						"elb":        nil,
						"msk":        nil,
						"mq":         nil,
						"route53":    nil,
						"memorydb":   nil,
						"codebuild":  nil,
						"cognito":    nil,
						"transfer":   nil,
						"athena":     nil,
						"appstream":  nil,
						"batch":      nil,
						"ds":         nil,
						"documentdb": nil,
						"other":      nil,
					},
				},
			},
		},
	},
	Platforms: connection.Platforms,
}
