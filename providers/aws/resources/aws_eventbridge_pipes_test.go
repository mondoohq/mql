// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/pipes"
	pipes_types "github.com/aws/aws-sdk-go-v2/service/pipes/types"
	"github.com/stretchr/testify/assert"
)

func TestPipeSourceType(t *testing.T) {
	cases := []struct {
		name string
		arn  string
		sp   *pipes_types.PipeSourceParameters
		want string
	}{
		// Parameters block populated — type is determined by which inner pointer is set
		{"sqs via params", "", &pipes_types.PipeSourceParameters{SqsQueueParameters: &pipes_types.PipeSourceSqsQueueParameters{}}, "sqs"},
		{"kinesis via params", "", &pipes_types.PipeSourceParameters{KinesisStreamParameters: &pipes_types.PipeSourceKinesisStreamParameters{}}, "kinesisStream"},
		{"dynamodb via params", "", &pipes_types.PipeSourceParameters{DynamoDBStreamParameters: &pipes_types.PipeSourceDynamoDBStreamParameters{}}, "dynamodbStream"},
		{"activeMQ via params", "", &pipes_types.PipeSourceParameters{ActiveMQBrokerParameters: &pipes_types.PipeSourceActiveMQBrokerParameters{}}, "activeMQ"},
		{"rabbitMQ via params", "", &pipes_types.PipeSourceParameters{RabbitMQBrokerParameters: &pipes_types.PipeSourceRabbitMQBrokerParameters{}}, "rabbitMQ"},
		{"msk via params", "", &pipes_types.PipeSourceParameters{ManagedStreamingKafkaParameters: &pipes_types.PipeSourceManagedStreamingKafkaParameters{}}, "msk"},
		{"selfManagedKafka via params", "", &pipes_types.PipeSourceParameters{SelfManagedKafkaParameters: &pipes_types.PipeSourceSelfManagedKafkaParameters{}}, "selfManagedKafka"},

		// No parameters block — fall back to ARN inspection
		{"sqs via ARN only", "arn:aws:sqs:us-east-1:111:my-queue", nil, "sqs"},
		{"kinesis via ARN only", "arn:aws:kinesis:us-east-1:111:stream/foo", nil, "kinesisStream"},
		{"dynamodb via ARN only", "arn:aws:dynamodb:us-east-1:111:table/foo/stream/2024", nil, "dynamodbStream"},
		{"mq via ARN only", "arn:aws:mq:us-east-1:111:broker:foo:b-uuid", nil, "activeMQ"},
		{"kafka via ARN only", "arn:aws:kafka:us-east-1:111:cluster/foo/uuid", nil, "msk"},

		// Empty / unknown
		{"empty ARN, nil params", "", nil, "unknown"},
		{"unknown ARN, nil params", "arn:aws:lambda:us-east-1:111:function:foo", nil, "unknown"},

		// Parameters takes priority over ARN
		{"params win over ARN", "arn:aws:sqs:us-east-1:111:fake", &pipes_types.PipeSourceParameters{KinesisStreamParameters: &pipes_types.PipeSourceKinesisStreamParameters{}}, "kinesisStream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pipeSourceType(tc.arn, tc.sp))
		})
	}
}

func TestPipeTargetType(t *testing.T) {
	cases := []struct {
		name string
		arn  string
		tp   *pipes_types.PipeTargetParameters
		want string
	}{
		{"lambda via params", "", &pipes_types.PipeTargetParameters{LambdaFunctionParameters: &pipes_types.PipeTargetLambdaFunctionParameters{}}, "lambda"},
		{"stepFunctions via params", "", &pipes_types.PipeTargetParameters{StepFunctionStateMachineParameters: &pipes_types.PipeTargetStateMachineParameters{}}, "stepFunctions"},
		{"sqs via params", "", &pipes_types.PipeTargetParameters{SqsQueueParameters: &pipes_types.PipeTargetSqsQueueParameters{}}, "sqs"},
		{"kinesis via params", "", &pipes_types.PipeTargetParameters{KinesisStreamParameters: &pipes_types.PipeTargetKinesisStreamParameters{}}, "kinesisStream"},
		{"ecsTask via params", "", &pipes_types.PipeTargetParameters{EcsTaskParameters: &pipes_types.PipeTargetEcsTaskParameters{}}, "ecsTask"},
		{"batchJob via params", "", &pipes_types.PipeTargetParameters{BatchJobParameters: &pipes_types.PipeTargetBatchJobParameters{}}, "batchJob"},
		{"cloudwatchLogs via params", "", &pipes_types.PipeTargetParameters{CloudWatchLogsParameters: &pipes_types.PipeTargetCloudWatchLogsParameters{}}, "cloudwatchLogs"},
		{"eventBridge via params", "", &pipes_types.PipeTargetParameters{EventBridgeEventBusParameters: &pipes_types.PipeTargetEventBridgeEventBusParameters{}}, "eventBridge"},
		{"redshiftData via params", "", &pipes_types.PipeTargetParameters{RedshiftDataParameters: &pipes_types.PipeTargetRedshiftDataParameters{}}, "redshiftData"},
		{"sagemakerPipeline via params", "", &pipes_types.PipeTargetParameters{SageMakerPipelineParameters: &pipes_types.PipeTargetSageMakerPipelineParameters{}}, "sagemakerPipeline"},
		{"timestream via params", "", &pipes_types.PipeTargetParameters{TimestreamParameters: &pipes_types.PipeTargetTimestreamParameters{}}, "timestream"},
		{"http via params", "", &pipes_types.PipeTargetParameters{HttpParameters: &pipes_types.PipeTargetHttpParameters{}}, "http"},

		// ARN fallbacks
		{"lambda via ARN", "arn:aws:lambda:us-east-1:111:function:foo", nil, "lambda"},
		{"stepFunctions via ARN", "arn:aws:states:us-east-1:111:stateMachine:foo", nil, "stepFunctions"},
		{"sqs via ARN", "arn:aws:sqs:us-east-1:111:foo", nil, "sqs"},
		{"kinesis via ARN", "arn:aws:kinesis:us-east-1:111:stream/foo", nil, "kinesisStream"},
		{"logs via ARN", "arn:aws:logs:us-east-1:111:log-group:foo", nil, "cloudwatchLogs"},
		{"events via ARN", "arn:aws:events:us-east-1:111:event-bus/foo", nil, "eventBridge"},

		{"unknown", "arn:aws:s3:::bucket", nil, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pipeTargetType(tc.arn, tc.tp))
		})
	}
}

func TestMqBrokerCredentialSecretArn(t *testing.T) {
	t.Run("nil returns empty", func(t *testing.T) {
		assert.Equal(t, "", mqBrokerCredentialSecretArn(nil))
	})
	t.Run("BasicAuth returns the secret ARN", func(t *testing.T) {
		got := mqBrokerCredentialSecretArn(&pipes_types.MQBrokerAccessCredentialsMemberBasicAuth{
			Value: "arn:aws:secretsmanager:us-east-1:111:secret:foo",
		})
		assert.Equal(t, "arn:aws:secretsmanager:us-east-1:111:secret:foo", got)
	})
}

func TestMskCredentialDetails(t *testing.T) {
	cases := []struct {
		name          string
		creds         pipes_types.MSKAccessCredentials
		wantCredType  string
		wantSecretArn string
	}{
		{"nil → IAM", nil, "iam", ""},
		{"client cert TLS",
			&pipes_types.MSKAccessCredentialsMemberClientCertificateTlsAuth{Value: "arn:aws:secretsmanager:us-east-1:111:secret:cert"},
			"ClientCertificateTlsAuth", "arn:aws:secretsmanager:us-east-1:111:secret:cert"},
		{"sasl scram 512",
			&pipes_types.MSKAccessCredentialsMemberSaslScram512Auth{Value: "arn:aws:secretsmanager:us-east-1:111:secret:scram"},
			"SaslScram512Auth", "arn:aws:secretsmanager:us-east-1:111:secret:scram"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotArn := mskCredentialDetails(tc.creds)
			assert.Equal(t, tc.wantCredType, gotType, "credType")
			assert.Equal(t, tc.wantSecretArn, gotArn, "secretArn")
		})
	}
}

func TestSelfManagedKafkaCredentialDetails(t *testing.T) {
	cases := []struct {
		name          string
		creds         pipes_types.SelfManagedKafkaAccessConfigurationCredentials
		wantCredType  string
		wantSecretArn string
	}{
		{"nil", nil, "", ""},
		{"basic",
			&pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberBasicAuth{Value: "arn:basic"},
			"BasicAuth", "arn:basic"},
		{"sasl scram 256",
			&pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberSaslScram256Auth{Value: "arn:scram256"},
			"SaslScram256Auth", "arn:scram256"},
		{"sasl scram 512",
			&pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberSaslScram512Auth{Value: "arn:scram512"},
			"SaslScram512Auth", "arn:scram512"},
		{"client cert TLS",
			&pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberClientCertificateTlsAuth{Value: "arn:cert"},
			"ClientCertificateTlsAuth", "arn:cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotArn := selfManagedKafkaCredentialDetails(tc.creds)
			assert.Equal(t, tc.wantCredType, gotType, "credType")
			assert.Equal(t, tc.wantSecretArn, gotArn, "secretArn")
		})
	}
}

func TestPipeFilterCriteriaFromDescribe(t *testing.T) {
	t.Run("nil describe", func(t *testing.T) {
		assert.Nil(t, pipeFilterCriteriaFromDescribe(nil))
	})
	t.Run("nil source params", func(t *testing.T) {
		assert.Nil(t, pipeFilterCriteriaFromDescribe(&pipes.DescribePipeOutput{}))
	})
	t.Run("nil filter criteria", func(t *testing.T) {
		assert.Nil(t, pipeFilterCriteriaFromDescribe(&pipes.DescribePipeOutput{
			SourceParameters: &pipes_types.PipeSourceParameters{},
		}))
	})
	t.Run("returns the criteria when present", func(t *testing.T) {
		fc := &pipes_types.FilterCriteria{
			Filters: []pipes_types.Filter{{Pattern: new(`{"source":["aws.s3"]}`)}},
		}
		got := pipeFilterCriteriaFromDescribe(&pipes.DescribePipeOutput{
			SourceParameters: &pipes_types.PipeSourceParameters{FilterCriteria: fc},
		})
		assert.Same(t, fc, got)
	})
}

//go:fix inline
func ptr[T any](v T) *T { return new(v) }
