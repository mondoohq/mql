// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesis_types "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// channelDescribeConcurrency caps the per-region fan-out of DescribeChannel
// calls. Kinesis has no batch describe for channels, so listing them costs
// 1 + N round-trips; fanning out shrinks the wall clock.
const channelDescribeConcurrency = 10

// channelDelivery is the destination view of a channel, flattened out of the
// two mutually exclusive shapes DescribeChannel returns.
//
// A channel delivers either to a general purpose bucket
// (S3DestinationConfiguration) or to Iceberg streaming tables
// (S3TablesDestinationConfiguration), never both, and the fields that matter
// for review live at different depths in each. Flattening once here keeps
// every accessor off the nested pointer walk, where a missing nil check turns
// an unset optional into a panic rather than a null.
type channelDelivery struct {
	dataFreshnessInSeconds *int32
	bucketARN              *string
	expectedBucketOwner    *string
	compressionType        string
	storageClass           string
	outputKeyTemplate      *string
	dlqBucketARN           *string
	dlqBucketOwner         *string
	dlqErrorOutputPrefix   *string
	tables                 []kinesis_types.S3TablesConfiguration
}

// channelDeliveryFrom reads the destination configuration off a channel
// description.
//
// Every nested struct on the path is optional in the SDK even where the API
// documents it as required, so each hop is guarded: a channel still being
// created, or one read under partial permissions, arrives with the
// destination pointer nil and must produce null fields rather than a panic.
func channelDeliveryFrom(desc *kinesis_types.ChannelDescription) channelDelivery {
	var out channelDelivery
	if desc == nil {
		return out
	}

	if s3 := desc.S3DestinationConfiguration; s3 != nil {
		out.dataFreshnessInSeconds = s3.DataFreshnessInSeconds
		if store := s3.StorageConfiguration; store != nil {
			out.bucketARN = store.BucketARN
			out.expectedBucketOwner = store.ExpectedBucketOwner
			out.compressionType = string(store.CompressionType)
			out.storageClass = string(store.StorageClass)
			out.outputKeyTemplate = store.OutputKeyTemplate
		}
		if dlq := s3.DeadLetterQueueS3Configuration; dlq != nil {
			out.dlqBucketARN = dlq.BucketARN
			out.dlqBucketOwner = dlq.ExpectedBucketOwner
			out.dlqErrorOutputPrefix = dlq.ErrorOutputPrefix
		}
		return out
	}

	if tables := desc.S3TablesDestinationConfiguration; tables != nil {
		out.dataFreshnessInSeconds = tables.DataFreshnessInSeconds
		out.tables = tables.S3TablesConfigurationList
		if dlq := tables.DeadLetterQueueS3Configuration; dlq != nil {
			out.dlqBucketARN = dlq.BucketARN
			out.dlqBucketOwner = dlq.ExpectedBucketOwner
			out.dlqErrorOutputPrefix = dlq.ErrorOutputPrefix
		}
	}
	return out
}

// channelTableCacheID builds the cache key for one streaming table.
//
// A table is named by its table bucket, its namespace, and its own name, and
// all three are needed: the same table name legitimately appears in two
// namespaces, and the same namespace in two table buckets. The channel ARN
// leads because two channels may write to the same table.
func channelTableCacheID(channelARN, tableBucketARN, namespace, name string) string {
	return fmt.Sprintf("%s/table/%s/%s/%s", channelARN, tableBucketARN, namespace, name)
}

// --- Channel listing ---

func (a *mqlAwsKinesis) channels() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getChannels(conn), 5)
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

func (a *mqlAwsKinesis) getChannels(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("kinesis>getChannels>calling aws with region %s", region)

			svc := conn.Kinesis(region)
			ctx := context.Background()
			res := []any{}

			paginator := kinesis.NewListChannelsPaginator(svc, &kinesis.ListChannelsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("kinesis delivery channels are not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range page.ChannelSummaries {
					mqlChannel, err := newMqlAwsKinesisChannel(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlChannel)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsKinesisChannel(runtime *plugin.Runtime, region string, summary kinesis_types.ChannelSummary) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "aws.kinesis.channel", map[string]*llx.RawData{
		"__id":            llx.StringDataPtr(summary.ChannelARN),
		"arn":             llx.StringDataPtr(summary.ChannelARN),
		"name":            llx.StringDataPtr(summary.ChannelName),
		"region":          llx.StringData(region),
		"status":          llx.StringData(string(summary.ChannelStatus)),
		"statusReason":    llx.StringDataPtr(summary.ChannelStatusReason),
		"destinationType": llx.StringData(string(summary.ChannelDestinationType)),
		"createdAt":       llx.TimeDataPtr(summary.ChannelCreationTimestamp),
	})
	if err != nil {
		return nil, err
	}

	// The source stream ARNs come free with the list, so caching them here
	// keeps sourceStreams off the DescribeChannel path entirely.
	cast := res.(*mqlAwsKinesisChannel)
	cast.cacheRegion = region
	for _, stream := range summary.Streams {
		if stream.StreamARN != nil && *stream.StreamARN != "" {
			cast.cacheStreamARNs = append(cast.cacheStreamARNs, *stream.StreamARN)
		}
	}
	return res, nil
}

func (a *mqlAwsKinesisChannel) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsKinesisChannelInternal struct {
	cacheRegion     string
	cacheStreamARNs []string
	descOnce        sync.Once
	desc            *kinesis_types.ChannelDescription
	descErr         error
}

// fetchDescription reads the channel configuration, which the list API does
// not carry. An access denial leaves desc nil so the configuration fields
// resolve to null rather than to a value nobody read.
func (a *mqlAwsKinesisChannel) fetchDescription() (*kinesis_types.ChannelDescription, error) {
	a.descOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Kinesis(a.cacheRegion)
		channelArn := a.Arn.Data

		out, err := svc.DescribeChannel(context.Background(), &kinesis.DescribeChannelInput{
			ChannelARN: &channelArn,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("channel", channelArn).Msg("access denied describing kinesis channel")
				return
			}
			a.descErr = err
			return
		}
		a.desc = out.ChannelDescription
	})
	return a.desc, a.descErr
}

func (a *mqlAwsKinesisChannel) delivery() (channelDelivery, error) {
	desc, err := a.fetchDescription()
	if err != nil {
		return channelDelivery{}, err
	}
	return channelDeliveryFrom(desc), nil
}

func (a *mqlAwsKinesisChannel) sourceStreams() ([]any, error) {
	res := []any{}
	for _, streamArn := range a.cacheStreamARNs {
		mqlStream, err := NewResource(a.MqlRuntime, "aws.kinesis.stream",
			map[string]*llx.RawData{"arn": llx.StringData(streamArn)})
		if err != nil {
			log.Warn().Err(err).Str("stream", streamArn).Msg("could not resolve kinesis channel source stream")
			continue
		}
		res = append(res, mqlStream)
	}
	return res, nil
}

func (a *mqlAwsKinesisChannel) iamRole() (*mqlAwsIamRole, error) {
	desc, err := a.fetchDescription()
	if err != nil {
		return nil, err
	}
	if desc == nil || desc.ServiceExecutionRoleARN == nil || *desc.ServiceExecutionRoleARN == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(desc.ServiceExecutionRoleARN)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsKinesisChannel) encryptionType() (string, error) {
	desc, err := a.fetchDescription()
	if err != nil {
		return "", err
	}
	if desc == nil || desc.EncryptionConfiguration == nil {
		a.EncryptionType = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return string(desc.EncryptionConfiguration.EncryptionType), nil
}

func (a *mqlAwsKinesisChannel) kmsKey() (*mqlAwsKmsKey, error) {
	desc, err := a.fetchDescription()
	if err != nil {
		return nil, err
	}
	if desc == nil || desc.EncryptionConfiguration == nil {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveKmsKeyRef(a.MqlRuntime, desc.EncryptionConfiguration.KeyId, a.cacheRegion, &a.KmsKey.State)
}

// cloudWatchLogs returns the logging block, or nil when the channel reports
// none. Logging is what records a delivery failure, so a channel with none is
// a channel whose delivery errors go unrecorded.
func (a *mqlAwsKinesisChannel) cloudWatchLogs() (*kinesis_types.CloudWatchLogs, error) {
	desc, err := a.fetchDescription()
	if err != nil {
		return nil, err
	}
	if desc == nil || desc.LoggingConfiguration == nil {
		return nil, nil
	}
	return desc.LoggingConfiguration.CloudWatchLogs, nil
}

func (a *mqlAwsKinesisChannel) cloudWatchLogsEnabled() (bool, error) {
	logs, err := a.cloudWatchLogs()
	if err != nil {
		return false, err
	}
	if logs == nil || logs.Enabled == nil {
		a.CloudWatchLogsEnabled = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *logs.Enabled, nil
}

func (a *mqlAwsKinesisChannel) cloudWatchLogGroupName() (string, error) {
	logs, err := a.cloudWatchLogs()
	if err != nil {
		return "", err
	}
	if logs == nil || logs.LogGroupName == nil {
		a.CloudWatchLogGroupName = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *logs.LogGroupName, nil
}

func (a *mqlAwsKinesisChannel) cloudWatchLogStreamName() (string, error) {
	logs, err := a.cloudWatchLogs()
	if err != nil {
		return "", err
	}
	if logs == nil || logs.LogStreamName == nil {
		a.CloudWatchLogStreamName = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *logs.LogStreamName, nil
}

func (a *mqlAwsKinesisChannel) dataFreshnessInSeconds() (int64, error) {
	delivery, err := a.delivery()
	if err != nil {
		return 0, err
	}
	if delivery.dataFreshnessInSeconds == nil {
		a.DataFreshnessInSeconds = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		return 0, nil
	}
	return int64(*delivery.dataFreshnessInSeconds), nil
}

func (a *mqlAwsKinesisChannel) destinationBucket() (*mqlAwsS3Bucket, error) {
	delivery, err := a.delivery()
	if err != nil {
		return nil, err
	}
	if delivery.bucketARN == nil || *delivery.bucketARN == "" {
		a.DestinationBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(delivery.bucketARN)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsKinesisChannel) destinationBucketOwner() (string, error) {
	delivery, err := a.delivery()
	if err != nil {
		return "", err
	}
	if delivery.expectedBucketOwner == nil {
		a.DestinationBucketOwner = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *delivery.expectedBucketOwner, nil
}

func (a *mqlAwsKinesisChannel) destinationCompressionType() (string, error) {
	delivery, err := a.delivery()
	if err != nil {
		return "", err
	}
	if delivery.compressionType == "" {
		a.DestinationCompressionType = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return delivery.compressionType, nil
}

func (a *mqlAwsKinesisChannel) destinationStorageClass() (string, error) {
	delivery, err := a.delivery()
	if err != nil {
		return "", err
	}
	if delivery.storageClass == "" {
		a.DestinationStorageClass = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return delivery.storageClass, nil
}

func (a *mqlAwsKinesisChannel) destinationOutputKeyTemplate() (string, error) {
	delivery, err := a.delivery()
	if err != nil {
		return "", err
	}
	if delivery.outputKeyTemplate == nil {
		a.DestinationOutputKeyTemplate = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *delivery.outputKeyTemplate, nil
}

func (a *mqlAwsKinesisChannel) deadLetterBucket() (*mqlAwsS3Bucket, error) {
	delivery, err := a.delivery()
	if err != nil {
		return nil, err
	}
	if delivery.dlqBucketARN == nil || *delivery.dlqBucketARN == "" {
		a.DeadLetterBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(delivery.dlqBucketARN)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsKinesisChannel) deadLetterBucketOwner() (string, error) {
	delivery, err := a.delivery()
	if err != nil {
		return "", err
	}
	if delivery.dlqBucketOwner == nil {
		a.DeadLetterBucketOwner = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *delivery.dlqBucketOwner, nil
}

func (a *mqlAwsKinesisChannel) deadLetterErrorOutputPrefix() (string, error) {
	delivery, err := a.delivery()
	if err != nil {
		return "", err
	}
	if delivery.dlqErrorOutputPrefix == nil {
		a.DeadLetterErrorOutputPrefix = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *delivery.dlqErrorOutputPrefix, nil
}

func (a *mqlAwsKinesisChannel) tables() ([]any, error) {
	delivery, err := a.delivery()
	if err != nil {
		return nil, err
	}

	channelArn := a.Arn.Data
	res := []any{}
	for _, table := range delivery.tables {
		tableBucketArn := convert.ToValue(table.TableBucketARN)
		namespace := convert.ToValue(table.Namespace)
		name := convert.ToValue(table.TableName)

		mqlTable, err := CreateResource(a.MqlRuntime, "aws.kinesis.channel.table", map[string]*llx.RawData{
			"__id":            llx.StringData(channelTableCacheID(channelArn, tableBucketArn, namespace, name)),
			"tableBucketArn":  llx.StringData(tableBucketArn),
			"namespace":       llx.StringData(namespace),
			"name":            llx.StringData(name),
			"compressionType": llx.StringData(string(table.CompressionType)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTable)
	}
	return res, nil
}

func (a *mqlAwsKinesisChannelTable) id() (string, error) {
	return a.__id, nil
}
