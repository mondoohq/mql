// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms the AWS provider can emit via
// GetPlatformForObject: the account root plus one entry per discoverable AWS
// object type. Each object is an "aws-object" running in the "aws" runtime;
// the account root is an "api" platform. This is the single source of truth for
// both the provider config (config.Config.Platforms) and the runtime builder.
// Platform names, one per discoverable AWS object type plus the account root.
// Referencing these instead of string literals means a mistyped platform is a
// compile error rather than a silently unmatched asset: code that gates on the
// scanned asset's platform (see getAssetIdentifier) fails closed, so a typo
// would quietly stop asset-scoped resolution for that resource with no error.
const (
	PlatformAccount                   = "aws"
	PlatformS3Bucket                  = "aws-s3-bucket"
	PlatformCloudtrailTrail           = "aws-cloudtrail-trail"
	PlatformRdsDbinstance             = "aws-rds-dbinstance"
	PlatformRdsDbcluster              = "aws-rds-dbcluster"
	PlatformRdsSnapshot               = "aws-rds-snapshot"
	PlatformDynamodbTable             = "aws-dynamodb-table"
	PlatformDynamodbGlobaltable       = "aws-dynamodb-globaltable"
	PlatformRedshiftCluster           = "aws-redshift-cluster"
	PlatformVpc                       = "aws-vpc"
	PlatformSecurityGroup             = "aws-security-group"
	PlatformEbsVolume                 = "aws-ebs-volume"
	PlatformEbsSnapshot               = "aws-ebs-snapshot"
	PlatformIamUser                   = "aws-iam-user"
	PlatformIamGroup                  = "aws-iam-group"
	PlatformCloudwatchLoggroup        = "aws-cloudwatch-loggroup"
	PlatformLambdaFunction            = "aws-lambda-function"
	PlatformEcsContainer              = "aws-ecs-container"
	PlatformEcsInstance               = "aws-ecs-instance"
	PlatformEfsFilesystem             = "aws-efs-filesystem"
	PlatformGatewayRestapi            = "aws-gateway-restapi"
	PlatformElbLoadbalancer           = "aws-elb-loadbalancer"
	PlatformEsDomain                  = "aws-es-domain"
	PlatformOpensearchDomain          = "aws-opensearch-domain"
	PlatformKmsKey                    = "aws-kms-key"
	PlatformSagemakerNotebookinstance = "aws-sagemaker-notebookinstance"
	PlatformSagemakerProcessingjob    = "aws-sagemaker-processingjob"
	PlatformSagemakerTrainingjob      = "aws-sagemaker-trainingjob"
	PlatformSagemakerDomain           = "aws-sagemaker-domain"
	PlatformSagemakerModel            = "aws-sagemaker-model"
	PlatformEc2Instance               = "aws-ec2-instance"
	PlatformSsmInstance               = "aws-ssm-instance"
	PlatformEcrImage                  = "aws-ecr-image"
	PlatformEcrRepository             = "aws-ecr-repository"
	PlatformEcsTaskdefinition         = "aws-ecs-taskdefinition"
	PlatformRoute53Hostedzone         = "aws-route53-hostedzone"
	PlatformMskCluster                = "aws-msk-cluster"
	PlatformMqBroker                  = "aws-mq-broker"
	PlatformEksCluster                = "aws-eks-cluster"
	PlatformSecretsmanagerSecret      = "aws-secretsmanager-secret"
	PlatformElasticacheCluster        = "aws-elasticache-cluster"
	PlatformCloudfrontDistribution    = "aws-cloudfront-distribution"
	PlatformNeptuneCluster            = "aws-neptune-cluster"
	PlatformEmrCluster                = "aws-emr-cluster"
	PlatformDocumentdbCluster         = "aws-documentdb-cluster"
	PlatformMemorydbCluster           = "aws-memorydb-cluster"
	PlatformCodebuildProject          = "aws-codebuild-project"
	PlatformCognitoUserpool           = "aws-cognito-userpool"
	PlatformTransferServer            = "aws-transfer-server"
	PlatformApigatewayv2Api           = "aws-apigatewayv2-api"
	PlatformAthenaWorkgroup           = "aws-athena-workgroup"
	PlatformAppstreamFleet            = "aws-appstream-fleet"
	PlatformBatchJobdefinition        = "aws-batch-jobdefinition"
	PlatformDirectoryserviceDirectory = "aws-directoryservice-directory"
	PlatformDocumentdbInstance        = "aws-documentdb-instance"
	PlatformSnsTopic                  = "aws-sns-topic"
	PlatformSqsQueue                  = "aws-sqs-queue"
)

var Platforms = []*plugin.PlatformInfo{
	{Name: PlatformAccount, Title: "AWS Account", Kind: []string{"api"}, Runtime: []string{"aws"}},
	{Name: PlatformS3Bucket, Title: "AWS S3 Bucket", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformCloudtrailTrail, Title: "AWS CloudTrail Trail", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformRdsDbinstance, Title: "AWS RDS DB Instance", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformRdsDbcluster, Title: "AWS RDS DB Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformRdsSnapshot, Title: "AWS RDS Snapshot", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformDynamodbTable, Title: "AWS DynamoDB Table", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformDynamodbGlobaltable, Title: "AWS DynamoDB Global Table", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformRedshiftCluster, Title: "AWS Redshift Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformVpc, Title: "AWS VPC", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSecurityGroup, Title: "AWS Security Group", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEbsVolume, Title: "AWS EBS Volume", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEbsSnapshot, Title: "AWS EBS Snapshot", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformIamUser, Title: "AWS IAM User", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformIamGroup, Title: "AWS IAM Group", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformCloudwatchLoggroup, Title: "AWS CloudWatch Log Group", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformLambdaFunction, Title: "AWS Lambda Function", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEcsContainer, Title: "AWS ECS Container", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEcsInstance, Title: "AWS ECS Instance", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEfsFilesystem, Title: "AWS EFS Filesystem", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformGatewayRestapi, Title: "AWS Gateway REST API", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformElbLoadbalancer, Title: "AWS ELB Load Balancer", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEsDomain, Title: "AWS ES Domain", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformOpensearchDomain, Title: "AWS OpenSearch Domain", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformKmsKey, Title: "AWS KMS Key", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSagemakerNotebookinstance, Title: "AWS SageMaker Notebook Instance", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSagemakerProcessingjob, Title: "AWS SageMaker Processing Job", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSagemakerTrainingjob, Title: "AWS SageMaker Training Job", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSagemakerDomain, Title: "AWS SageMaker Domain", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSagemakerModel, Title: "AWS SageMaker Model", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEc2Instance, Title: "AWS EC2 Instance", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSsmInstance, Title: "AWS SSM Instance", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEcrImage, Title: "AWS ECR Image", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEcrRepository, Title: "AWS ECR Repository", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEcsTaskdefinition, Title: "AWS ECS Task Definition", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformRoute53Hostedzone, Title: "AWS Route 53 Hosted Zone", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformMskCluster, Title: "AWS MSK Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformMqBroker, Title: "AWS MQ Broker", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEksCluster, Title: "AWS EKS Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSecretsmanagerSecret, Title: "AWS Secrets Manager Secret", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformElasticacheCluster, Title: "AWS ElastiCache Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformCloudfrontDistribution, Title: "AWS CloudFront Distribution", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformNeptuneCluster, Title: "AWS Neptune Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformEmrCluster, Title: "AWS EMR Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformDocumentdbCluster, Title: "AWS DocumentDB Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformMemorydbCluster, Title: "AWS MemoryDB Cluster", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformCodebuildProject, Title: "AWS CodeBuild Project", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformCognitoUserpool, Title: "AWS Cognito User Pool", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformTransferServer, Title: "AWS Transfer Family Server", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformApigatewayv2Api, Title: "AWS API Gateway V2 API", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformAthenaWorkgroup, Title: "AWS Athena Workgroup", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformAppstreamFleet, Title: "AWS AppStream Fleet", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformBatchJobdefinition, Title: "AWS Batch Job Definition", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformDirectoryserviceDirectory, Title: "AWS Directory Service Directory", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformDocumentdbInstance, Title: "AWS DocumentDB Instance", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSnsTopic, Title: "AWS SNS Topic", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
	{Name: PlatformSqsQueue, Title: "AWS SQS Queue", Kind: []string{"aws-object"}, Runtime: []string{"aws"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static descriptor for a platform name, or nil if
// the name is not in the catalog.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
