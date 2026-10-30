// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/pipes"
	pipes_types "github.com/aws/aws-sdk-go-v2/service/pipes/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsEventbridge) pipes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPipes(conn), 5)
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

func (a *mqlAwsEventbridge) getPipes(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("eventbridge>getPipes>calling aws with region %s", region)

			svc := conn.Pipes(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListPipes(ctx, &pipes.ListPipesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("pipes not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, pipe := range resp.Pipes {
					mqlPipe, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe",
						map[string]*llx.RawData{
							"__id":         llx.StringDataPtr(pipe.Arn),
							"arn":          llx.StringDataPtr(pipe.Arn),
							"name":         llx.StringDataPtr(pipe.Name),
							"region":       llx.StringData(region),
							"source":       llx.StringDataPtr(pipe.Source),
							"target":       llx.StringDataPtr(pipe.Target),
							"enrichment":   llx.StringDataPtr(pipe.Enrichment),
							"currentState": llx.StringData(string(pipe.CurrentState)),
							"desiredState": llx.StringData(string(pipe.DesiredState)),
							"stateReason":  llx.StringDataPtr(pipe.StateReason),
							"createdAt":    llx.TimeDataPtr(pipe.CreationTime),
							"updatedAt":    llx.TimeDataPtr(pipe.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					mqlPipeRes := mqlPipe.(*mqlAwsEventbridgePipe)
					mqlPipeRes.cacheName = pipe.Name
					mqlPipeRes.cacheRegion = region
					res = append(res, mqlPipeRes)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEventbridgePipeInternal struct {
	cacheName     *string
	cacheRegion   string
	cacheRoleArn  *string
	cacheDescribe *pipes.DescribePipeOutput
	fetched       bool
	lock          sync.Mutex
}

func (a *mqlAwsEventbridgePipe) fetchDetails() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	if a.cacheName == nil {
		a.fetched = true
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Pipes(a.cacheRegion)
	ctx := context.Background()

	resp, err := svc.DescribePipe(ctx, &pipes.DescribePipeInput{
		Name: a.cacheName,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("pipe", *a.cacheName).Msg("access denied describing pipe")
			a.fetched = true
			return nil
		}
		return err
	}

	a.cacheRoleArn = resp.RoleArn
	a.cacheDescribe = resp
	if resp.Description != nil {
		a.Description = plugin.TValue[string]{Data: *resp.Description, State: plugin.StateIsSet}
	} else {
		a.Description = plugin.TValue[string]{Data: "", State: plugin.StateIsNull | plugin.StateIsSet}
	}
	tags := make(map[string]any)
	for k, v := range resp.Tags {
		tags[k] = v
	}
	a.Tags = plugin.TValue[map[string]any]{Data: tags, State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsEventbridgePipe) description() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsEventbridgePipe) tags() (map[string]any, error) {
	return nil, a.fetchDetails()
}

func (a *mqlAwsEventbridgePipe) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// kmsKey resolves the customer-managed CMK used for at-rest encryption of pipe state.
func (a *mqlAwsEventbridgePipe) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.KmsKeyIdentifier == nil || *a.cacheDescribe.KmsKeyIdentifier == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheDescribe.KmsKeyIdentifier)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// hasFilters reports whether the source has any filter criteria configured.
func (a *mqlAwsEventbridgePipe) hasFilters() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	fc := pipeFilterCriteriaFromDescribe(a.cacheDescribe)
	return fc != nil && len(fc.Filters) > 0, nil
}

func pipeFilterCriteriaFromDescribe(desc *pipes.DescribePipeOutput) *pipes_types.FilterCriteria {
	if desc == nil || desc.SourceParameters == nil {
		return nil
	}
	return desc.SourceParameters.FilterCriteria
}

// filterCriteria exposes the source filter patterns.
func (a *mqlAwsEventbridgePipe) filterCriteria() (*mqlAwsEventbridgePipeFilterCriteria, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	fc := pipeFilterCriteriaFromDescribe(a.cacheDescribe)
	if fc == nil {
		a.FilterCriteria.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newPipeFilterCriteria(a.MqlRuntime, a.Arn.Data, fc)
}

func newPipeFilterCriteria(runtime *plugin.Runtime, parentArn string, fc *pipes_types.FilterCriteria) (*mqlAwsEventbridgePipeFilterCriteria, error) {
	patterns := []any{}
	if fc != nil {
		for _, f := range fc.Filters {
			if f.Pattern != nil {
				patterns = append(patterns, *f.Pattern)
			}
		}
	}
	res, err := CreateResource(runtime, "aws.eventbridge.pipe.filterCriteria", map[string]*llx.RawData{
		"__id":    llx.StringData(parentArn + "/filterCriteria"),
		"filters": llx.ArrayData(patterns, types.String),
		"count":   llx.IntData(int64(len(patterns))),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeFilterCriteria), nil
}

// ----- ARN-prefix dispatch -----

// pipeResolveArn returns a typed mql resource for a known AWS ARN prefix, or
// nil if the ARN is empty or unrecognised. The caller is responsible for
// setting StateIsNull|StateIsSet on its field when nil is returned.
func pipeResolveArn(runtime *plugin.Runtime, arnVal string) (plugin.Resource, error) {
	arnVal = strings.TrimSpace(arnVal)
	if arnVal == "" {
		return nil, nil
	}
	switch {
	case strings.HasPrefix(arnVal, "arn:aws:sqs:"):
		return NewResource(runtime, "aws.sqs.queue", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:sns:"):
		return NewResource(runtime, "aws.sns.topic", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:kinesis:"):
		return NewResource(runtime, "aws.kinesis.stream", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:firehose:"):
		return NewResource(runtime, "aws.kinesis.firehoseDeliveryStream", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:dynamodb:") && strings.Contains(arnVal, ":table/"):
		// Both source (with /stream/) and target use the same table init.
		return NewResource(runtime, "aws.dynamodb.table", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:mq:"):
		return NewResource(runtime, "aws.mq.broker", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:kafka:"):
		return NewResource(runtime, "aws.msk.cluster", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:lambda:"):
		return NewResource(runtime, "aws.lambda.function", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:states:"):
		return NewResource(runtime, "aws.stepfunctions.stateMachine", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:logs:") && strings.Contains(arnVal, ":log-group:"):
		return NewResource(runtime, "aws.cloudwatch.loggroup", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:events:") && strings.Contains(arnVal, ":event-bus/"):
		// aws.eventbridge.eventBus has neither an id() method nor an init, so
		// without an explicit "__id" every bus reached this way lands on the
		// empty cache key and each pipe reports the first pipe's bus. The ARN is
		// the key the collection path stores under, so this also resolves to the
		// fully populated bus instead of one carrying nothing but its ARN.
		return NewResource(runtime, "aws.eventbridge.eventBus", map[string]*llx.RawData{
			"__id": llx.StringData(arnVal),
			"arn":  llx.StringData(arnVal),
		})
	case strings.HasPrefix(arnVal, "arn:aws:batch:") && strings.Contains(arnVal, ":job-queue/"):
		// Same for aws.batch.jobQueue. aws.batch.job.jobQueue() already keys on
		// the ARN for exactly this reason.
		return NewResource(runtime, "aws.batch.jobQueue", map[string]*llx.RawData{
			"__id": llx.StringData(arnVal),
			"arn":  llx.StringData(arnVal),
		})
	case strings.HasPrefix(arnVal, "arn:aws:redshift:"):
		return NewResource(runtime, "aws.redshift.cluster", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:ecs:") && strings.Contains(arnVal, ":task-definition/"):
		return NewResource(runtime, "aws.ecs.taskDefinition", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	case strings.HasPrefix(arnVal, "arn:aws:secretsmanager:"):
		return NewResource(runtime, "aws.secretsmanager.secret", map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	}
	return nil, nil
}

// ----- sourceParameters -----

func (a *mqlAwsEventbridgePipe) sourceParameters() (*mqlAwsEventbridgePipeSourceParameters, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.SourceParameters == nil {
		a.SourceParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	sp := a.cacheDescribe.SourceParameters
	srcType := pipeSourceType(a.Source.Data, sp)
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters", map[string]*llx.RawData{
		"__id": llx.StringData(a.Arn.Data + "/sourceParameters"),
		"type": llx.StringData(srcType),
	})
	if err != nil {
		return nil, err
	}
	mqlSP := res.(*mqlAwsEventbridgePipeSourceParameters)
	mqlSP.cachePipeArn = a.Arn.Data
	mqlSP.cacheRegion = a.cacheRegion
	mqlSP.cacheSP = sp
	mqlSP.cacheSourceArn = a.Source.Data
	return mqlSP, nil
}

func pipeSourceType(sourceArn string, sp *pipes_types.PipeSourceParameters) string {
	if sp != nil {
		switch {
		case sp.SqsQueueParameters != nil:
			return "sqs"
		case sp.KinesisStreamParameters != nil:
			return "kinesisStream"
		case sp.DynamoDBStreamParameters != nil:
			return "dynamodbStream"
		case sp.ActiveMQBrokerParameters != nil:
			return "activeMQ"
		case sp.RabbitMQBrokerParameters != nil:
			return "rabbitMQ"
		case sp.ManagedStreamingKafkaParameters != nil:
			return "msk"
		case sp.SelfManagedKafkaParameters != nil:
			return "selfManagedKafka"
		}
	}
	// Fall back to ARN inspection (some sources have no parameters block).
	switch {
	case strings.HasPrefix(sourceArn, "arn:aws:sqs:"):
		return "sqs"
	case strings.HasPrefix(sourceArn, "arn:aws:kinesis:"):
		return "kinesisStream"
	case strings.HasPrefix(sourceArn, "arn:aws:dynamodb:"):
		return "dynamodbStream"
	case strings.HasPrefix(sourceArn, "arn:aws:mq:"):
		return "activeMQ"
	case strings.HasPrefix(sourceArn, "arn:aws:kafka:"):
		return "msk"
	}
	return "unknown"
}

type mqlAwsEventbridgePipeSourceParametersInternal struct {
	cachePipeArn   string
	cacheRegion    string
	cacheSourceArn string
	cacheSP        *pipes_types.PipeSourceParameters
}

func (a *mqlAwsEventbridgePipeSourceParameters) sqs() (*mqlAwsEventbridgePipeSourceParametersSqs, error) {
	if a.cacheSP == nil || a.cacheSP.SqsQueueParameters == nil {
		a.Sqs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.SqsQueueParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.sqs", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/sqs"),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeSourceParametersSqs), nil
}

func (a *mqlAwsEventbridgePipeSourceParameters) kinesisStream() (*mqlAwsEventbridgePipeSourceParametersKinesisStream, error) {
	if a.cacheSP == nil || a.cacheSP.KinesisStreamParameters == nil {
		a.KinesisStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.KinesisStreamParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.kinesisStream", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/kinesisStream"),
		"startingPosition":               llx.StringData(string(p.StartingPosition)),
		"startingPositionTimestamp":      llx.TimeDataPtr(p.StartingPositionTimestamp),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
		"maximumRecordAgeInSeconds":      llx.IntDataDefault(p.MaximumRecordAgeInSeconds, 0),
		"maximumRetryAttempts":           llx.IntDataDefault(p.MaximumRetryAttempts, 0),
		"parallelizationFactor":          llx.IntDataDefault(p.ParallelizationFactor, 0),
		"onPartialBatchItemFailure":      llx.StringData(string(p.OnPartialBatchItemFailure)),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeSourceParametersKinesisStream)
	if p.DeadLetterConfig != nil && p.DeadLetterConfig.Arn != nil {
		mqlRes.cacheDlqArn = *p.DeadLetterConfig.Arn
	}
	mqlRes.cachePipeArn = a.cachePipeArn
	return mqlRes, nil
}

type mqlAwsEventbridgePipeSourceParametersKinesisStreamInternal struct {
	cachePipeArn string
	cacheDlqArn  string
}

func (a *mqlAwsEventbridgePipeSourceParametersKinesisStream) deadLetterConfig() (*mqlAwsEventbridgePipeDeadLetterConfig, error) {
	if a.cacheDlqArn == "" {
		a.DeadLetterConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newPipeDeadLetterConfig(a.MqlRuntime, a.cachePipeArn+"/sourceParameters/kinesisStream", a.cacheDlqArn)
}

func (a *mqlAwsEventbridgePipeSourceParameters) dynamodbStream() (*mqlAwsEventbridgePipeSourceParametersDynamodbStream, error) {
	if a.cacheSP == nil || a.cacheSP.DynamoDBStreamParameters == nil {
		a.DynamodbStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.DynamoDBStreamParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.dynamodbStream", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/dynamodbStream"),
		"startingPosition":               llx.StringData(string(p.StartingPosition)),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
		"maximumRecordAgeInSeconds":      llx.IntDataDefault(p.MaximumRecordAgeInSeconds, 0),
		"maximumRetryAttempts":           llx.IntDataDefault(p.MaximumRetryAttempts, 0),
		"parallelizationFactor":          llx.IntDataDefault(p.ParallelizationFactor, 0),
		"onPartialBatchItemFailure":      llx.StringData(string(p.OnPartialBatchItemFailure)),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeSourceParametersDynamodbStream)
	if p.DeadLetterConfig != nil && p.DeadLetterConfig.Arn != nil {
		mqlRes.cacheDlqArn = *p.DeadLetterConfig.Arn
	}
	mqlRes.cachePipeArn = a.cachePipeArn
	return mqlRes, nil
}

type mqlAwsEventbridgePipeSourceParametersDynamodbStreamInternal struct {
	cachePipeArn string
	cacheDlqArn  string
}

func (a *mqlAwsEventbridgePipeSourceParametersDynamodbStream) deadLetterConfig() (*mqlAwsEventbridgePipeDeadLetterConfig, error) {
	if a.cacheDlqArn == "" {
		a.DeadLetterConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newPipeDeadLetterConfig(a.MqlRuntime, a.cachePipeArn+"/sourceParameters/dynamodbStream", a.cacheDlqArn)
}

func (a *mqlAwsEventbridgePipeSourceParameters) activeMQ() (*mqlAwsEventbridgePipeSourceParametersActiveMQ, error) {
	if a.cacheSP == nil || a.cacheSP.ActiveMQBrokerParameters == nil {
		a.ActiveMQ.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.ActiveMQBrokerParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.activeMQ", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/activeMQ"),
		"queueName":                      llx.StringDataPtr(p.QueueName),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeSourceParametersActiveMQ)
	mqlRes.cacheSecretArn = mqBrokerCredentialSecretArn(p.Credentials)
	return mqlRes, nil
}

type mqlAwsEventbridgePipeSourceParametersActiveMQInternal struct {
	cacheSecretArn string
}

func (a *mqlAwsEventbridgePipeSourceParametersActiveMQ) credentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	return resolvePipeSecret(a.MqlRuntime, a.cacheSecretArn, &a.CredentialsSecret)
}

func (a *mqlAwsEventbridgePipeSourceParameters) rabbitMQ() (*mqlAwsEventbridgePipeSourceParametersRabbitMQ, error) {
	if a.cacheSP == nil || a.cacheSP.RabbitMQBrokerParameters == nil {
		a.RabbitMQ.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.RabbitMQBrokerParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.rabbitMQ", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/rabbitMQ"),
		"queueName":                      llx.StringDataPtr(p.QueueName),
		"virtualHost":                    llx.StringDataPtr(p.VirtualHost),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeSourceParametersRabbitMQ)
	mqlRes.cacheSecretArn = mqBrokerCredentialSecretArn(p.Credentials)
	return mqlRes, nil
}

type mqlAwsEventbridgePipeSourceParametersRabbitMQInternal struct {
	cacheSecretArn string
}

func (a *mqlAwsEventbridgePipeSourceParametersRabbitMQ) credentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	return resolvePipeSecret(a.MqlRuntime, a.cacheSecretArn, &a.CredentialsSecret)
}

func mqBrokerCredentialSecretArn(creds pipes_types.MQBrokerAccessCredentials) string {
	if creds == nil {
		return ""
	}
	if v, ok := creds.(*pipes_types.MQBrokerAccessCredentialsMemberBasicAuth); ok {
		return v.Value
	}
	return ""
}

func (a *mqlAwsEventbridgePipeSourceParameters) msk() (*mqlAwsEventbridgePipeSourceParametersMsk, error) {
	if a.cacheSP == nil || a.cacheSP.ManagedStreamingKafkaParameters == nil {
		a.Msk.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.ManagedStreamingKafkaParameters
	credType, secretArn := mskCredentialDetails(p.Credentials)
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.msk", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/msk"),
		"topicName":                      llx.StringDataPtr(p.TopicName),
		"consumerGroupId":                llx.StringDataPtr(p.ConsumerGroupID),
		"startingPosition":               llx.StringData(string(p.StartingPosition)),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
		"credentialsType":                llx.StringData(credType),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeSourceParametersMsk)
	mqlRes.cacheSecretArn = secretArn
	return mqlRes, nil
}

type mqlAwsEventbridgePipeSourceParametersMskInternal struct {
	cacheSecretArn string
}

func (a *mqlAwsEventbridgePipeSourceParametersMsk) credentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	return resolvePipeSecret(a.MqlRuntime, a.cacheSecretArn, &a.CredentialsSecret)
}

func mskCredentialDetails(creds pipes_types.MSKAccessCredentials) (string, string) {
	if creds == nil {
		return "iam", ""
	}
	switch v := creds.(type) {
	case *pipes_types.MSKAccessCredentialsMemberClientCertificateTlsAuth:
		return "ClientCertificateTlsAuth", v.Value
	case *pipes_types.MSKAccessCredentialsMemberSaslScram512Auth:
		return "SaslScram512Auth", v.Value
	}
	return "", ""
}

func (a *mqlAwsEventbridgePipeSourceParameters) selfManagedKafka() (*mqlAwsEventbridgePipeSourceParametersSelfManagedKafka, error) {
	if a.cacheSP == nil || a.cacheSP.SelfManagedKafkaParameters == nil {
		a.SelfManagedKafka.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheSP.SelfManagedKafkaParameters
	credType, secretArn := selfManagedKafkaCredentialDetails(p.Credentials)
	caSecret := ""
	if p.ServerRootCaCertificate != nil {
		caSecret = *p.ServerRootCaCertificate
	}
	bootstrap := []any{}
	for _, b := range p.AdditionalBootstrapServers {
		bootstrap = append(bootstrap, b)
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.sourceParameters.selfManagedKafka", map[string]*llx.RawData{
		"__id":                           llx.StringData(a.cachePipeArn + "/sourceParameters/selfManagedKafka"),
		"topicName":                      llx.StringDataPtr(p.TopicName),
		"consumerGroupId":                llx.StringDataPtr(p.ConsumerGroupID),
		"startingPosition":               llx.StringData(string(p.StartingPosition)),
		"batchSize":                      llx.IntDataDefault(p.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(p.MaximumBatchingWindowInSeconds, 0),
		"additionalBootstrapServers":     llx.ArrayData(bootstrap, types.String),
		"credentialsType":                llx.StringData(credType),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeSourceParametersSelfManagedKafka)
	mqlRes.cacheSecretArn = secretArn
	mqlRes.cacheCaSecretArn = caSecret
	if p.Vpc != nil {
		mqlRes.cacheSubnetIds = p.Vpc.Subnets
		mqlRes.cacheSGIds = p.Vpc.SecurityGroup
	}
	mqlRes.cacheRegion = a.cacheRegion
	return mqlRes, nil
}

type mqlAwsEventbridgePipeSourceParametersSelfManagedKafkaInternal struct {
	cacheSecretArn   string
	cacheCaSecretArn string
	cacheSubnetIds   []string
	cacheSGIds       []string
	cacheRegion      string
}

func (a *mqlAwsEventbridgePipeSourceParametersSelfManagedKafka) credentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	return resolvePipeSecret(a.MqlRuntime, a.cacheSecretArn, &a.CredentialsSecret)
}

func (a *mqlAwsEventbridgePipeSourceParametersSelfManagedKafka) serverRootCaCertificateSecret() (*mqlAwsSecretsmanagerSecret, error) {
	return resolvePipeSecret(a.MqlRuntime, a.cacheCaSecretArn, &a.ServerRootCaCertificateSecret)
}

func (a *mqlAwsEventbridgePipeSourceParametersSelfManagedKafka) subnets() ([]any, error) {
	return resolvePipeSubnetsByID(a.MqlRuntime, a.cacheRegion, a.cacheSubnetIds)
}

func (a *mqlAwsEventbridgePipeSourceParametersSelfManagedKafka) securityGroups() ([]any, error) {
	return resolvePipeSecurityGroupsByID(a.MqlRuntime, a.cacheRegion, a.cacheSGIds)
}

func selfManagedKafkaCredentialDetails(creds pipes_types.SelfManagedKafkaAccessConfigurationCredentials) (string, string) {
	if creds == nil {
		return "", ""
	}
	switch v := creds.(type) {
	case *pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberBasicAuth:
		return "BasicAuth", v.Value
	case *pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberSaslScram256Auth:
		return "SaslScram256Auth", v.Value
	case *pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberSaslScram512Auth:
		return "SaslScram512Auth", v.Value
	case *pipes_types.SelfManagedKafkaAccessConfigurationCredentialsMemberClientCertificateTlsAuth:
		return "ClientCertificateTlsAuth", v.Value
	}
	return "", ""
}

// filterCriteria on sourceParameters mirrors the pipe-level field but is exposed
// here so audits that walk the parameters tree can find it without reaching back up.
func (a *mqlAwsEventbridgePipeSourceParameters) filterCriteria() (*mqlAwsEventbridgePipeFilterCriteria, error) {
	if a.cacheSP == nil || a.cacheSP.FilterCriteria == nil {
		a.FilterCriteria.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newPipeFilterCriteria(a.MqlRuntime, a.cachePipeArn+"/sourceParameters", a.cacheSP.FilterCriteria)
}

// ----- enrichmentParameters -----

func (a *mqlAwsEventbridgePipe) enrichmentParameters() (*mqlAwsEventbridgePipeEnrichmentParameters, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.EnrichmentParameters == nil {
		a.EnrichmentParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	ep := a.cacheDescribe.EnrichmentParameters
	inputTemplate := ""
	if ep.InputTemplate != nil {
		inputTemplate = *ep.InputTemplate
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.enrichmentParameters", map[string]*llx.RawData{
		"__id":          llx.StringData(a.Arn.Data + "/enrichmentParameters"),
		"inputTemplate": llx.StringData(inputTemplate),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeEnrichmentParameters)
	mqlRes.cachePipeArn = a.Arn.Data
	mqlRes.cacheEP = ep
	return mqlRes, nil
}

type mqlAwsEventbridgePipeEnrichmentParametersInternal struct {
	cachePipeArn string
	cacheEP      *pipes_types.PipeEnrichmentParameters
}

func (a *mqlAwsEventbridgePipeEnrichmentParameters) http() (*mqlAwsEventbridgePipeTargetParametersHttp, error) {
	if a.cacheEP == nil || a.cacheEP.HttpParameters == nil {
		a.Http.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	hp := a.cacheEP.HttpParameters
	headerKeys := mapKeys(hp.HeaderParameters)
	queryKeys := mapKeys(hp.QueryStringParameters)
	pathVals := []any{}
	for _, v := range hp.PathParameterValues {
		pathVals = append(pathVals, v)
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.http", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.cachePipeArn + "/enrichmentParameters/http"),
		"headerParameterKeys":      llx.ArrayData(headerKeys, types.String),
		"queryStringParameterKeys": llx.ArrayData(queryKeys, types.String),
		"pathParameterValues":      llx.ArrayData(pathVals, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersHttp), nil
}

func mapKeys(m map[string]string) []any {
	keys := []any{}
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ----- targetParameters -----

func (a *mqlAwsEventbridgePipe) targetParameters() (*mqlAwsEventbridgePipeTargetParameters, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil {
		a.TargetParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	tp := a.cacheDescribe.TargetParameters
	tgtType := pipeTargetType(a.Target.Data, tp)
	inputTemplate := ""
	if tp != nil && tp.InputTemplate != nil {
		inputTemplate = *tp.InputTemplate
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters", map[string]*llx.RawData{
		"__id":          llx.StringData(a.Arn.Data + "/targetParameters"),
		"type":          llx.StringData(tgtType),
		"inputTemplate": llx.StringData(inputTemplate),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeTargetParameters)
	mqlRes.cachePipeArn = a.Arn.Data
	mqlRes.cacheRegion = a.cacheRegion
	mqlRes.cacheTP = tp
	return mqlRes, nil
}

func pipeTargetType(targetArn string, tp *pipes_types.PipeTargetParameters) string {
	if tp != nil {
		switch {
		case tp.LambdaFunctionParameters != nil:
			return "lambda"
		case tp.StepFunctionStateMachineParameters != nil:
			return "stepFunctions"
		case tp.SqsQueueParameters != nil:
			return "sqs"
		case tp.KinesisStreamParameters != nil:
			return "kinesisStream"
		case tp.EcsTaskParameters != nil:
			return "ecsTask"
		case tp.BatchJobParameters != nil:
			return "batchJob"
		case tp.CloudWatchLogsParameters != nil:
			return "cloudwatchLogs"
		case tp.EventBridgeEventBusParameters != nil:
			return "eventBridge"
		case tp.RedshiftDataParameters != nil:
			return "redshiftData"
		case tp.SageMakerPipelineParameters != nil:
			return "sagemakerPipeline"
		case tp.TimestreamParameters != nil:
			return "timestream"
		case tp.HttpParameters != nil:
			return "http"
		}
	}
	switch {
	case strings.HasPrefix(targetArn, "arn:aws:lambda:"):
		return "lambda"
	case strings.HasPrefix(targetArn, "arn:aws:states:"):
		return "stepFunctions"
	case strings.HasPrefix(targetArn, "arn:aws:sqs:"):
		return "sqs"
	case strings.HasPrefix(targetArn, "arn:aws:kinesis:"):
		return "kinesisStream"
	case strings.HasPrefix(targetArn, "arn:aws:logs:"):
		return "cloudwatchLogs"
	case strings.HasPrefix(targetArn, "arn:aws:events:"):
		return "eventBridge"
	}
	return "unknown"
}

type mqlAwsEventbridgePipeTargetParametersInternal struct {
	cachePipeArn string
	cacheRegion  string
	cacheTP      *pipes_types.PipeTargetParameters
}

func (a *mqlAwsEventbridgePipeTargetParameters) lambda() (*mqlAwsEventbridgePipeTargetParametersLambda, error) {
	if a.cacheTP == nil || a.cacheTP.LambdaFunctionParameters == nil {
		a.Lambda.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.lambda", map[string]*llx.RawData{
		"__id":           llx.StringData(a.cachePipeArn + "/targetParameters/lambda"),
		"invocationType": llx.StringData(string(a.cacheTP.LambdaFunctionParameters.InvocationType)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersLambda), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) stepFunctions() (*mqlAwsEventbridgePipeTargetParametersStepFunctions, error) {
	if a.cacheTP == nil || a.cacheTP.StepFunctionStateMachineParameters == nil {
		a.StepFunctions.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.stepFunctions", map[string]*llx.RawData{
		"__id":           llx.StringData(a.cachePipeArn + "/targetParameters/stepFunctions"),
		"invocationType": llx.StringData(string(a.cacheTP.StepFunctionStateMachineParameters.InvocationType)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersStepFunctions), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) sqs() (*mqlAwsEventbridgePipeTargetParametersSqs, error) {
	if a.cacheTP == nil || a.cacheTP.SqsQueueParameters == nil {
		a.Sqs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.SqsQueueParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.sqs", map[string]*llx.RawData{
		"__id":                   llx.StringData(a.cachePipeArn + "/targetParameters/sqs"),
		"messageGroupId":         llx.StringDataPtr(p.MessageGroupId),
		"messageDeduplicationId": llx.StringDataPtr(p.MessageDeduplicationId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersSqs), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) kinesisStream() (*mqlAwsEventbridgePipeTargetParametersKinesisStream, error) {
	if a.cacheTP == nil || a.cacheTP.KinesisStreamParameters == nil {
		a.KinesisStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.KinesisStreamParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.kinesisStream", map[string]*llx.RawData{
		"__id":         llx.StringData(a.cachePipeArn + "/targetParameters/kinesisStream"),
		"partitionKey": llx.StringDataPtr(p.PartitionKey),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersKinesisStream), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) ecsTask() (*mqlAwsEventbridgePipeTargetParametersEcsTask, error) {
	if a.cacheTP == nil || a.cacheTP.EcsTaskParameters == nil {
		a.EcsTask.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.EcsTaskParameters
	cps, _ := convert.JsonToDictSlice(p.CapacityProviderStrategy)
	pc, _ := convert.JsonToDictSlice(p.PlacementConstraints)
	ps, _ := convert.JsonToDictSlice(p.PlacementStrategy)
	tags := map[string]any{}
	for _, t := range p.Tags {
		if t.Key != nil {
			val := ""
			if t.Value != nil {
				val = *t.Value
			}
			tags[*t.Key] = val
		}
	}
	enableExecCmd := false
	if p.EnableExecuteCommand {
		enableExecCmd = true
	}
	enableMgdTags := false
	if p.EnableECSManagedTags {
		enableMgdTags = true
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.ecsTask", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.cachePipeArn + "/targetParameters/ecsTask"),
		"launchType":               llx.StringData(string(p.LaunchType)),
		"platformVersion":          llx.StringDataPtr(p.PlatformVersion),
		"enableExecuteCommand":     llx.BoolData(enableExecCmd),
		"enableECSManagedTags":     llx.BoolData(enableMgdTags),
		"propagateTags":            llx.StringData(string(p.PropagateTags)),
		"taskCount":                llx.IntDataDefault(p.TaskCount, 0),
		"referenceId":              llx.StringDataPtr(p.ReferenceId),
		"group":                    llx.StringDataPtr(p.Group),
		"capacityProviderStrategy": llx.ArrayData(cps, types.Dict),
		"placementConstraints":     llx.ArrayData(pc, types.Dict),
		"placementStrategy":        llx.ArrayData(ps, types.Dict),
		"tags":                     llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeTargetParametersEcsTask)
	if p.TaskDefinitionArn != nil {
		mqlRes.cacheTaskDefArn = *p.TaskDefinitionArn
	}
	mqlRes.cachePipeArn = a.cachePipeArn
	mqlRes.cacheRegion = a.cacheRegion
	if p.NetworkConfiguration != nil && p.NetworkConfiguration.AwsvpcConfiguration != nil {
		mqlRes.cacheAssignPublicIp = string(p.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp)
		mqlRes.cacheSubnetIds = p.NetworkConfiguration.AwsvpcConfiguration.Subnets
		mqlRes.cacheSGIds = p.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups
		mqlRes.cacheHasNetworkConfig = true
	}
	return mqlRes, nil
}

type mqlAwsEventbridgePipeTargetParametersEcsTaskInternal struct {
	cachePipeArn          string
	cacheRegion           string
	cacheTaskDefArn       string
	cacheHasNetworkConfig bool
	cacheAssignPublicIp   string
	cacheSubnetIds        []string
	cacheSGIds            []string
}

func (a *mqlAwsEventbridgePipeTargetParametersEcsTask) taskDefinition() (*mqlAwsEcsTaskDefinition, error) {
	if a.cacheTaskDefArn == "" {
		a.TaskDefinition.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.taskDefinition", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheTaskDefArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTaskDefinition), nil
}

func (a *mqlAwsEventbridgePipeTargetParametersEcsTask) networkConfiguration() (*mqlAwsEventbridgePipeTargetParametersEcsTaskNetworkConfiguration, error) {
	if !a.cacheHasNetworkConfig {
		a.NetworkConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.ecsTask.networkConfiguration", map[string]*llx.RawData{
		"__id":           llx.StringData(a.cachePipeArn + "/targetParameters/ecsTask/networkConfiguration"),
		"assignPublicIp": llx.StringData(a.cacheAssignPublicIp),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeTargetParametersEcsTaskNetworkConfiguration)
	mqlRes.cacheRegion = a.cacheRegion
	mqlRes.cacheSubnetIds = a.cacheSubnetIds
	mqlRes.cacheSGIds = a.cacheSGIds
	return mqlRes, nil
}

type mqlAwsEventbridgePipeTargetParametersEcsTaskNetworkConfigurationInternal struct {
	cacheRegion    string
	cacheSubnetIds []string
	cacheSGIds     []string
}

func (a *mqlAwsEventbridgePipeTargetParametersEcsTaskNetworkConfiguration) subnets() ([]any, error) {
	return resolvePipeSubnetsByID(a.MqlRuntime, a.cacheRegion, a.cacheSubnetIds)
}

func (a *mqlAwsEventbridgePipeTargetParametersEcsTaskNetworkConfiguration) securityGroups() ([]any, error) {
	return resolvePipeSecurityGroupsByID(a.MqlRuntime, a.cacheRegion, a.cacheSGIds)
}

func (a *mqlAwsEventbridgePipeTargetParameters) batchJob() (*mqlAwsEventbridgePipeTargetParametersBatchJob, error) {
	if a.cacheTP == nil || a.cacheTP.BatchJobParameters == nil {
		a.BatchJob.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.BatchJobParameters
	dependsOn, _ := convert.JsonToDictSlice(p.DependsOn)
	arrayProps, _ := convert.JsonToDict(p.ArrayProperties)
	retry, _ := convert.JsonToDict(p.RetryStrategy)

	envNames := []any{}
	hasEnv := false
	hasOverrides := p.ContainerOverrides != nil
	if hasOverrides {
		for _, ev := range p.ContainerOverrides.Environment {
			if ev.Name != nil {
				envNames = append(envNames, *ev.Name)
				hasEnv = true
			}
		}
	}
	params := map[string]any{}
	for k, v := range p.Parameters {
		params[k] = v
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.batchJob", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.cachePipeArn + "/targetParameters/batchJob"),
		"jobDefinition":            llx.StringDataPtr(p.JobDefinition),
		"jobName":                  llx.StringDataPtr(p.JobName),
		"dependsOn":                llx.ArrayData(dependsOn, types.Dict),
		"arrayProperties":          llx.DictData(arrayProps),
		"retryStrategy":            llx.DictData(retry),
		"hasContainerOverrides":    llx.BoolData(hasOverrides),
		"hasEnvironmentOverrides":  llx.BoolData(hasEnv),
		"environmentVariableNames": llx.ArrayData(envNames, types.String),
		"parameters":               llx.MapData(params, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersBatchJob), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) cloudwatchLogs() (*mqlAwsEventbridgePipeTargetParametersCloudwatchLogs, error) {
	if a.cacheTP == nil || a.cacheTP.CloudWatchLogsParameters == nil {
		a.CloudwatchLogs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.CloudWatchLogsParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.cloudwatchLogs", map[string]*llx.RawData{
		"__id":          llx.StringData(a.cachePipeArn + "/targetParameters/cloudwatchLogs"),
		"logStreamName": llx.StringDataPtr(p.LogStreamName),
		"timestamp":     llx.StringDataPtr(p.Timestamp),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersCloudwatchLogs), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) eventBridge() (*mqlAwsEventbridgePipeTargetParametersEventBridge, error) {
	if a.cacheTP == nil || a.cacheTP.EventBridgeEventBusParameters == nil {
		a.EventBridge.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.EventBridgeEventBusParameters
	resources := []any{}
	for _, r := range p.Resources {
		resources = append(resources, r)
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.eventBridge", map[string]*llx.RawData{
		"__id":       llx.StringData(a.cachePipeArn + "/targetParameters/eventBridge"),
		"source":     llx.StringDataPtr(p.Source),
		"detailType": llx.StringDataPtr(p.DetailType),
		"endpointId": llx.StringDataPtr(p.EndpointId),
		"resources":  llx.ArrayData(resources, types.String),
		"time":       llx.StringDataPtr(p.Time),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersEventBridge), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) redshiftData() (*mqlAwsEventbridgePipeTargetParametersRedshiftData, error) {
	if a.cacheTP == nil || a.cacheTP.RedshiftDataParameters == nil {
		a.RedshiftData.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.RedshiftDataParameters
	stmts := []any{}
	for _, s := range p.Sqls {
		stmts = append(stmts, s)
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.redshiftData", map[string]*llx.RawData{
		"__id":              llx.StringData(a.cachePipeArn + "/targetParameters/redshiftData"),
		"database":          llx.StringDataPtr(p.Database),
		"dbUser":            llx.StringDataPtr(p.DbUser),
		"statementName":     llx.StringDataPtr(p.StatementName),
		"withEvent":         llx.BoolData(p.WithEvent),
		"sqlStatementCount": llx.IntData(int64(len(p.Sqls))),
		"hasSqlStatements":  llx.BoolData(len(p.Sqls) > 0),
		"sqlStatements":     llx.ArrayData(stmts, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeTargetParametersRedshiftData)
	if p.SecretManagerArn != nil {
		mqlRes.cacheSecretArn = *p.SecretManagerArn
	}
	return mqlRes, nil
}

type mqlAwsEventbridgePipeTargetParametersRedshiftDataInternal struct {
	cacheSecretArn string
}

func (a *mqlAwsEventbridgePipeTargetParametersRedshiftData) credentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	return resolvePipeSecret(a.MqlRuntime, a.cacheSecretArn, &a.CredentialsSecret)
}

func (a *mqlAwsEventbridgePipeTargetParameters) sagemakerPipeline() (*mqlAwsEventbridgePipeTargetParametersSagemakerPipeline, error) {
	if a.cacheTP == nil || a.cacheTP.SageMakerPipelineParameters == nil {
		a.SagemakerPipeline.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.SageMakerPipelineParameters
	keys := []any{}
	for _, kp := range p.PipelineParameterList {
		if kp.Name != nil {
			keys = append(keys, *kp.Name)
		}
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.sagemakerPipeline", map[string]*llx.RawData{
		"__id":                   llx.StringData(a.cachePipeArn + "/targetParameters/sagemakerPipeline"),
		"pipelineParameterNames": llx.ArrayData(keys, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersSagemakerPipeline), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) timestream() (*mqlAwsEventbridgePipeTargetParametersTimestream, error) {
	if a.cacheTP == nil || a.cacheTP.TimestreamParameters == nil {
		a.Timestream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTP.TimestreamParameters
	dim, _ := convert.JsonToDictSlice(p.DimensionMappings)
	multi, _ := convert.JsonToDictSlice(p.MultiMeasureMappings)
	single, _ := convert.JsonToDictSlice(p.SingleMeasureMappings)
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.timestream", map[string]*llx.RawData{
		"__id":                  llx.StringData(a.cachePipeArn + "/targetParameters/timestream"),
		"databaseName":          llx.StringData(""),
		"tableName":             llx.StringData(""),
		"timeFieldType":         llx.StringData(string(p.TimeFieldType)),
		"versionValue":          llx.StringDataPtr(p.VersionValue),
		"timeValue":             llx.StringDataPtr(p.TimeValue),
		"epochTimeUnit":         llx.StringData(string(p.EpochTimeUnit)),
		"dimensionMappings":     llx.ArrayData(dim, types.Dict),
		"multiMeasureMappings":  llx.ArrayData(multi, types.Dict),
		"singleMeasureMappings": llx.ArrayData(single, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersTimestream), nil
}

func (a *mqlAwsEventbridgePipeTargetParameters) http() (*mqlAwsEventbridgePipeTargetParametersHttp, error) {
	if a.cacheTP == nil || a.cacheTP.HttpParameters == nil {
		a.Http.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	hp := a.cacheTP.HttpParameters
	headerKeys := mapKeys(hp.HeaderParameters)
	queryKeys := mapKeys(hp.QueryStringParameters)
	pathVals := []any{}
	for _, v := range hp.PathParameterValues {
		pathVals = append(pathVals, v)
	}
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.targetParameters.http", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.cachePipeArn + "/targetParameters/http"),
		"headerParameterKeys":      llx.ArrayData(headerKeys, types.String),
		"queryStringParameterKeys": llx.ArrayData(queryKeys, types.String),
		"pathParameterValues":      llx.ArrayData(pathVals, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgePipeTargetParametersHttp), nil
}

// ----- logConfiguration -----

func (a *mqlAwsEventbridgePipe) logConfiguration() (*mqlAwsEventbridgePipeLogConfiguration, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.LogConfiguration == nil {
		a.LogConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	lc := a.cacheDescribe.LogConfiguration
	includes := []any{}
	for _, v := range lc.IncludeExecutionData {
		includes = append(includes, string(v))
	}
	hasAny := lc.CloudwatchLogsLogDestination != nil || lc.FirehoseLogDestination != nil || lc.S3LogDestination != nil
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.logConfiguration", map[string]*llx.RawData{
		"__id":                 llx.StringData(a.Arn.Data + "/logConfiguration"),
		"level":                llx.StringData(string(lc.Level)),
		"includeExecutionData": llx.ArrayData(includes, types.String),
		"hasAnyDestination":    llx.BoolData(hasAny),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeLogConfiguration)
	mqlRes.cachePipeArn = a.Arn.Data
	mqlRes.cacheLC = lc
	return mqlRes, nil
}

type mqlAwsEventbridgePipeLogConfigurationInternal struct {
	cachePipeArn string
	cacheLC      *pipes_types.PipeLogConfiguration
}

func (a *mqlAwsEventbridgePipeLogConfiguration) cloudwatchLogs() (*mqlAwsEventbridgePipeLogConfigurationCloudwatchLogs, error) {
	if a.cacheLC == nil || a.cacheLC.CloudwatchLogsLogDestination == nil {
		a.CloudwatchLogs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	d := a.cacheLC.CloudwatchLogsLogDestination
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.logConfiguration.cloudwatchLogs", map[string]*llx.RawData{
		"__id": llx.StringData(a.cachePipeArn + "/logConfiguration/cloudwatchLogs"),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeLogConfigurationCloudwatchLogs)
	if d.LogGroupArn != nil {
		mqlRes.cacheLogGroupArn = *d.LogGroupArn
	}
	return mqlRes, nil
}

type mqlAwsEventbridgePipeLogConfigurationCloudwatchLogsInternal struct {
	cacheLogGroupArn string
}

func (a *mqlAwsEventbridgePipeLogConfigurationCloudwatchLogs) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroupArn == "" {
		a.LogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheLogGroupArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsEventbridgePipeLogConfiguration) firehose() (*mqlAwsEventbridgePipeLogConfigurationFirehose, error) {
	if a.cacheLC == nil || a.cacheLC.FirehoseLogDestination == nil {
		a.Firehose.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	d := a.cacheLC.FirehoseLogDestination
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.logConfiguration.firehose", map[string]*llx.RawData{
		"__id": llx.StringData(a.cachePipeArn + "/logConfiguration/firehose"),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeLogConfigurationFirehose)
	if d.DeliveryStreamArn != nil {
		mqlRes.cacheFirehoseArn = *d.DeliveryStreamArn
	}
	return mqlRes, nil
}

type mqlAwsEventbridgePipeLogConfigurationFirehoseInternal struct {
	cacheFirehoseArn string
}

func (a *mqlAwsEventbridgePipeLogConfigurationFirehose) deliveryStream() (*mqlAwsKinesisFirehoseDeliveryStream, error) {
	if a.cacheFirehoseArn == "" {
		a.DeliveryStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kinesis.firehoseDeliveryStream", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheFirehoseArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKinesisFirehoseDeliveryStream), nil
}

func (a *mqlAwsEventbridgePipeLogConfiguration) s3() (*mqlAwsEventbridgePipeLogConfigurationS3, error) {
	if a.cacheLC == nil || a.cacheLC.S3LogDestination == nil {
		a.S3.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	d := a.cacheLC.S3LogDestination
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.pipe.logConfiguration.s3", map[string]*llx.RawData{
		"__id":         llx.StringData(a.cachePipeArn + "/logConfiguration/s3"),
		"bucketOwner":  llx.StringDataPtr(d.BucketOwner),
		"prefix":       llx.StringDataPtr(d.Prefix),
		"outputFormat": llx.StringData(string(d.OutputFormat)),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeLogConfigurationS3)
	if d.BucketName != nil {
		mqlRes.cacheBucketName = *d.BucketName
	}
	return mqlRes, nil
}

type mqlAwsEventbridgePipeLogConfigurationS3Internal struct {
	cacheBucketName string
}

func (a *mqlAwsEventbridgePipeLogConfigurationS3) bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheBucketName == "" {
		a.Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket", map[string]*llx.RawData{
		"name": llx.StringData(a.cacheBucketName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

// ----- deadLetterConfig -----

func newPipeDeadLetterConfig(runtime *plugin.Runtime, parentId string, dlqArn string) (*mqlAwsEventbridgePipeDeadLetterConfig, error) {
	res, err := CreateResource(runtime, "aws.eventbridge.pipe.deadLetterConfig", map[string]*llx.RawData{
		"__id": llx.StringData(parentId + "/deadLetterConfig"),
		"arn":  llx.StringData(dlqArn),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgePipeDeadLetterConfig)
	mqlRes.cacheDlqArn = dlqArn
	return mqlRes, nil
}

type mqlAwsEventbridgePipeDeadLetterConfigInternal struct {
	cacheDlqArn string
}

func (a *mqlAwsEventbridgePipeDeadLetterConfig) queue() (*mqlAwsSqsQueue, error) {
	if !strings.HasPrefix(a.cacheDlqArn, "arn:aws:sqs:") {
		a.Queue.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sqs.queue", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheDlqArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSqsQueue), nil
}

func (a *mqlAwsEventbridgePipeDeadLetterConfig) topic() (*mqlAwsSnsTopic, error) {
	if !strings.HasPrefix(a.cacheDlqArn, "arn:aws:sns:") {
		a.Topic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sns.topic", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheDlqArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSnsTopic), nil
}

// ----- shared helpers -----

func resolvePipeSecret(runtime *plugin.Runtime, secretArn string, field *plugin.TValue[*mqlAwsSecretsmanagerSecret]) (*mqlAwsSecretsmanagerSecret, error) {
	if secretArn == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.secretsmanager.secret", map[string]*llx.RawData{
		"arn": llx.StringData(secretArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

const pipeSubnetArnFmt = "arn:aws:ec2:%s:%s:subnet/%s"

func resolvePipeSubnetsByID(runtime *plugin.Runtime, region string, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, id := range ids {
		ref, err := NewResource(runtime, "aws.vpc.subnet", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(pipeSubnetArnFmt, region, conn.AccountId(), id)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func resolvePipeSecurityGroupsByID(runtime *plugin.Runtime, region string, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, id := range ids {
		ref, err := NewResource(runtime, "aws.ec2.securitygroup", map[string]*llx.RawData{
			"arn": llx.StringData(NewSecurityGroupArn(region, conn.AccountId(), id)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}
