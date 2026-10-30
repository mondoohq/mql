// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoveredObjectShapes is every (service, objectType) pair that discover()
// builds an awsObject with. Keep it in sync when adding a discovery target --
// the point of this list is that adding a target without a matching
// getPlatformName case is caught here rather than in production.
var discoveredObjectShapes = []struct{ service, objectType string }{
	{"apigatewayv2", "api"},
	{"appstream", "fleet"},
	{"athena", "workgroup"},
	{"batch", "jobdefinition"},
	{"cloudfront", "distribution"},
	{"cloudtrail", "trail"},
	{"cloudwatch", "loggroup"},
	{"codebuild", "project"},
	{"cognito", "userpool"},
	{"documentdb", "cluster"},
	{"documentdb", "instance"},
	{"ds", "directory"},
	{"dynamodb", "globaltable"},
	{"dynamodb", "table"},
	{"ec2", "instance"},
	{"ec2", "securitygroup"},
	{"ec2", "snapshot"},
	{"ec2", "volume"},
	{"ecr", "image"},
	{"ecr", "repository"},
	{"ecs", "container"},
	{"ecs", "instance"},
	{"ecs", "taskdefinition"},
	{"efs", "filesystem"},
	{"eks", "cluster"},
	{"elasticache", "cluster"},
	{"elb", "loadbalancer"},
	{"emr", "cluster"},
	{"es", "domain"},
	{"gateway", "restapi"},
	{"iam", "group"},
	{"iam", "user"},
	{"kms", "key"},
	{"lambda", "function"},
	{"memorydb", "cluster"},
	{"mq", "broker"},
	{"msk", "cluster"},
	{"neptune", "cluster"},
	{"opensearch", "domain"},
	{"rds", "dbcluster"},
	{"rds", "dbinstance"},
	{"redshift", "cluster"},
	{"route53", "hostedzone"},
	{"s3", "bucket"},
	{"sagemaker", "domain"},
	{"sagemaker", "model"},
	{"sagemaker", "notebookinstance"},
	{"sagemaker", "processingjob"},
	{"sagemaker", "trainingjob"},
	{"secretsmanager", "secret"},
	{"sns", "topic"},
	{"sqs", "queue"},
	{"ssm", "instance"},
	{"transfer", "server"},
	{"vpc", "vpc"},
}

// TestGetPlatformNameCoversEveryDiscoveredObject guards a silent-asset-loss
// class: MqlObjectToAsset returns nil when getPlatformName yields "", and the
// callers append that nil unconditionally, so the asset vanishes with only an
// unattributed log line. This is exactly how DynamoDB global tables stopped
// being discovered when their objectType was split off from "table".
func TestGetPlatformNameCoversEveryDiscoveredObject(t *testing.T) {
	for _, shape := range discoveredObjectShapes {
		t.Run(shape.service+"/"+shape.objectType, func(t *testing.T) {
			name := getPlatformName(awsObject{
				service:    shape.service,
				objectType: shape.objectType,
			})
			require.NotEmpty(t, name,
				"discover() emits service=%q objectType=%q but getPlatformName has no case for it, "+
					"so every such asset is silently dropped", shape.service, shape.objectType)
		})
	}
}

// TestMondooObjectIDIsUniquePerShape guards the sibling class: two different
// discovered object shapes must never produce the same platform id, or the
// assets merge and one disappears from the inventory.
func TestMondooObjectIDIsUniquePerShape(t *testing.T) {
	seen := map[string]string{}
	for _, shape := range discoveredObjectShapes {
		id := MondooObjectID(awsObject{
			account:    "123456789012",
			region:     "us-east-1",
			service:    shape.service,
			objectType: shape.objectType,
			id:         "same-name",
		})
		key := shape.service + "/" + shape.objectType
		if prev, dup := seen[id]; dup {
			assert.Failf(t, "platform id collision",
				"%s and %s produce the same platform id %q", prev, key, id)
		}
		seen[id] = key
	}
}
