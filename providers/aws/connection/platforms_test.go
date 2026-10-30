// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoveryPlatformNames are the platform names the discovery code can hand to
// GetPlatformForObject (the outputs of getPlatformName in
// resources/discovery_conversion.go). Every one must be in the static catalog.
// If discovery learns a new object type, add it here AND to Platforms.
var discoveryPlatformNames = []string{
	"aws-apigatewayv2-api", "aws-appstream-fleet", "aws-athena-workgroup",
	"aws-batch-jobdefinition", "aws-directoryservice-directory", "aws-documentdb-instance",
	"aws-cloudfront-distribution", "aws-cloudtrail-trail", "aws-cloudwatch-loggroup",
	"aws-documentdb-cluster", "aws-dynamodb-table", "aws-ebs-snapshot", "aws-ebs-volume",
	"aws-ec2-instance", "aws-ecr-image", "aws-ecr-repository", "aws-ecs-container",
	"aws-ecs-instance", "aws-ecs-taskdefinition", "aws-efs-filesystem", "aws-eks-cluster",
	"aws-elasticache-cluster", "aws-elb-loadbalancer", "aws-emr-cluster", "aws-es-domain",
	"aws-gateway-restapi", "aws-iam-group", "aws-iam-user", "aws-kms-key",
	"aws-lambda-function", "aws-mq-broker", "aws-msk-cluster", "aws-neptune-cluster",
	"aws-opensearch-domain", "aws-rds-dbcluster", "aws-rds-dbinstance", "aws-redshift-cluster",
	"aws-route53-hostedzone", "aws-s3-bucket", "aws-sagemaker-notebookinstance",
	"aws-sagemaker-processingjob", "aws-sagemaker-trainingjob", "aws-secretsmanager-secret",
	"aws-security-group", "aws-sns-topic", "aws-sqs-queue", "aws-ssm-instance", "aws-vpc",
}

func TestPlatformCatalogComplete(t *testing.T) {
	// every discoverable name is in the catalog
	for _, name := range discoveryPlatformNames {
		assert.NotNil(t, PlatformByName(name), "discovery emits %q but it is not in the static catalog", name)
	}

	// every catalog entry is consistent with what the runtime builds for it
	for _, pi := range Platforms {
		p := GetPlatformForObject(pi.Name, "123456789012")
		assert.Equal(t, pi.Name, p.Name)
		assert.Equal(t, pi.Title, p.Title, "title drift for %q", pi.Name)
		assert.True(t, pi.Consistent(p), "kind/runtime of %q not in declared set: kind=%q runtime=%q", pi.Name, p.Kind, p.Runtime)
	}
}

func TestGetPlatformForObjectParity(t *testing.T) {
	acc := "123456789012"

	// account root: empty and explicit "aws" both yield the api platform
	for _, name := range []string{"", "aws"} {
		p := GetPlatformForObject(name, acc)
		assert.Equal(t, "aws", p.Name)
		assert.Equal(t, "AWS Account", p.Title)
		assert.Equal(t, "api", p.Kind)
		assert.Equal(t, "aws", p.Runtime)
		assert.Equal(t, []string{"aws", acc, "account"}, p.TechnologyUrlSegments)
	}

	// a known object
	p := GetPlatformForObject("aws-s3-bucket", acc)
	assert.Equal(t, "aws-s3-bucket", p.Name)
	assert.Equal(t, "AWS S3 Bucket", p.Title)
	assert.Equal(t, "aws-object", p.Kind)
	assert.Equal(t, "aws", p.Runtime)
	assert.Equal(t, []string{"aws", acc, "s3"}, p.TechnologyUrlSegments)

	// messaging objects resolve to their own service segment, not the "other" fallback
	assert.Equal(t, []string{"aws", acc, "sns"}, GetPlatformForObject("aws-sns-topic", acc).TechnologyUrlSegments)
	assert.Equal(t, []string{"aws", acc, "sqs"}, GetPlatformForObject("aws-sqs-queue", acc).TechnologyUrlSegments)

	// an unknown object name falls back to a generic AWS object
	u := GetPlatformForObject("aws-brand-new-thing", acc)
	require.Equal(t, "aws-brand-new-thing", u.Name)
	assert.Equal(t, "Amazon Web Services", u.Title)
	assert.Equal(t, "aws-object", u.Kind)
	assert.Equal(t, "aws", u.Runtime)
	assert.Equal(t, []string{"aws", acc, "other"}, u.TechnologyUrlSegments)
}
