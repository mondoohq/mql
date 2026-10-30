// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/inventory"

func (a *AwsConnection) PlatformInfo() *inventory.Platform {
	return GetPlatformForObject(a.PlatformOverride, a.accountId)
}

func GetPlatformForObject(platformName string, accountId string) *inventory.Platform {
	if platformName == "" {
		platformName = "aws"
	}

	// Fall back to a generic AWS object for names not in the static catalog, so
	// new object types keep working before they are added to Platforms.
	pi := PlatformByName(platformName)
	if pi == nil {
		return &inventory.Platform{
			Name:                  platformName,
			Title:                 "Amazon Web Services",
			Kind:                  "aws-object",
			Runtime:               "aws",
			TechnologyUrlSegments: getTechnologyUrlSegments(accountId, platformName),
		}
	}

	p := &inventory.Platform{}
	pi.Apply(p)
	if platformName == "aws" {
		p.TechnologyUrlSegments = []string{"aws", accountId, "account"}
	} else {
		p.TechnologyUrlSegments = getTechnologyUrlSegments(accountId, platformName)
	}
	return p
}

func getTechnologyUrlSegments(accountId string, platformName string) []string {
	return []string{"aws", accountId, getServiceName(platformName)}
}

func getServiceName(platformName string) string {
	switch platformName {
	case "aws-s3-bucket":
		return "s3"
	case "aws-cloudtrail-trail":
		return "cloudtrail"
	case "aws-rds-dbinstance":
		return "rds"
	case "aws-rds-dbcluster":
		return "rds"
	case "aws-rds-snapshot":
		return "rds"
	case "aws-dynamodb-table", "aws-dynamodb-globaltable":
		return "dynamodb"
	case "aws-redshift-cluster":
		return "redshift"
	case "aws-vpc":
		return "vpc"
	case "aws-security-group":
		return "ec2"
	case "aws-ebs-volume":
		return "ec2"
	case "aws-ebs-snapshot":
		return "ec2"
	case "aws-iam-user":
		return "iam"
	case "aws-iam-group":
		return "iam"
	case "aws-cloudwatch-loggroup":
		return "cloudwatch"
	case "aws-lambda-function":
		return "lambda"
	case "aws-ecs-container":
		return "ecs"
	case "aws-efs-filesystem":
		return "efs"
	case "aws-gateway-restapi":
		return "apigateway"
	case "aws-elb-loadbalancer":
		return "elb"
	case "aws-es-domain":
		return "es"
	case "aws-opensearch-domain":
		return "opensearch"
	case "aws-kms-key":
		return "kms"
	case "aws-sagemaker-notebookinstance":
		return "sagemaker"
	case "aws-sagemaker-processingjob":
		return "sagemaker"
	case "aws-sagemaker-trainingjob":
		return "sagemaker"
	case "aws-sagemaker-domain":
		return "sagemaker"
	case "aws-sagemaker-model":
		return "sagemaker"
	case "aws-ec2-instance":
		return "ec2"
	case "aws-ssm-instance":
		return "ec2"
	case "aws-ecr-image":
		return "ecr"
	case "aws-ecr-repository":
		return "ecr"
	case "aws-ecs-taskdefinition":
		return "ecs"
	case "aws-route53-hostedzone":
		return "route53"
	case "aws-msk-cluster":
		return "msk"
	case "aws-mq-broker":
		return "mq"
	case "aws-elasticache-cluster":
		return "elasticache"
	case "aws-cloudfront-distribution":
		return "cloudfront"
	case "aws-neptune-cluster":
		return "neptune"
	case "aws-emr-cluster":
		return "emr"
	case "aws-documentdb-cluster":
		return "documentdb"
	case "aws-memorydb-cluster":
		return "memorydb"
	case "aws-codebuild-project":
		return "codebuild"
	case "aws-cognito-userpool":
		return "cognito"
	case "aws-transfer-server":
		return "transfer"
	case "aws-apigatewayv2-api":
		return "apigateway"
	case "aws-athena-workgroup":
		return "athena"
	case "aws-appstream-fleet":
		return "appstream"
	case "aws-batch-jobdefinition":
		return "batch"
	case "aws-directoryservice-directory":
		return "ds"
	case "aws-documentdb-instance":
		return "documentdb"
	case "aws-sns-topic":
		return "sns"
	case "aws-sqs-queue":
		return "sqs"
	}
	return "other"
}
