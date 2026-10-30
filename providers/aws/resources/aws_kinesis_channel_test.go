// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	kinesis_types "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A general purpose S3 destination must surface the bucket, the expected
// owner, and the dead-letter configuration, each of which sits at a different
// depth in the response. Reading any one of them off the wrong nested struct
// yields a zero value, which reports "no cross-account guard configured" on a
// channel that has one.
func TestChannelDeliveryFrom_S3Destination(t *testing.T) {
	desc := &kinesis_types.ChannelDescription{
		S3DestinationConfiguration: &kinesis_types.S3DestinationDescription{
			DataFreshnessInSeconds: aws.Int32(600),
			StorageConfiguration: &kinesis_types.S3StorageConfiguration{
				BucketARN:           aws.String("arn:aws:s3:::records-archive"),
				ExpectedBucketOwner: aws.String("111111111111"),
				CompressionType:     kinesis_types.S3CompressionTypeGzip,
				StorageClass:        kinesis_types.S3StorageClassIntelligentTiering,
				OutputKeyTemplate:   aws.String("{timestamp:yyyy/MM/dd}/"),
			},
			DeadLetterQueueS3Configuration: &kinesis_types.DeadLetterQueueS3Configuration{
				BucketARN:           aws.String("arn:aws:s3:::records-dlq"),
				ExpectedBucketOwner: aws.String("222222222222"),
				ErrorOutputPrefix:   aws.String("errors/"),
			},
		},
	}

	got := channelDeliveryFrom(desc)

	require.NotNil(t, got.dataFreshnessInSeconds)
	assert.Equal(t, int32(600), *got.dataFreshnessInSeconds)
	require.NotNil(t, got.bucketARN)
	assert.Equal(t, "arn:aws:s3:::records-archive", *got.bucketARN)
	require.NotNil(t, got.expectedBucketOwner)
	assert.Equal(t, "111111111111", *got.expectedBucketOwner)
	assert.Equal(t, "GZIP", got.compressionType)
	assert.Equal(t, "INTELLIGENT_TIERING", got.storageClass)
	require.NotNil(t, got.outputKeyTemplate)
	assert.Equal(t, "{timestamp:yyyy/MM/dd}/", *got.outputKeyTemplate)
	require.NotNil(t, got.dlqBucketARN)
	assert.Equal(t, "arn:aws:s3:::records-dlq", *got.dlqBucketARN)
	require.NotNil(t, got.dlqBucketOwner)
	assert.Equal(t, "222222222222", *got.dlqBucketOwner)
	require.NotNil(t, got.dlqErrorOutputPrefix)
	assert.Equal(t, "errors/", *got.dlqErrorOutputPrefix)
	// An S3 channel writes no Iceberg tables.
	assert.Empty(t, got.tables)
}

// The two destination shapes carry the dead-letter queue and the freshness
// window in different structs. A reader that only walks the S3 branch reports
// both as absent for every streaming-table channel.
func TestChannelDeliveryFrom_S3TablesDestination(t *testing.T) {
	desc := &kinesis_types.ChannelDescription{
		S3TablesDestinationConfiguration: &kinesis_types.S3TablesDestinationDescription{
			DataFreshnessInSeconds: aws.Int32(300),
			DeadLetterQueueS3Configuration: &kinesis_types.DeadLetterQueueS3Configuration{
				BucketARN:           aws.String("arn:aws:s3:::tables-dlq"),
				ExpectedBucketOwner: aws.String("333333333333"),
			},
			S3TablesConfigurationList: []kinesis_types.S3TablesConfiguration{
				{
					TableBucketARN:  aws.String("arn:aws:s3tables:us-east-1:333333333333:bucket/analytics"),
					Namespace:       aws.String("events"),
					TableName:       aws.String("clicks"),
					CompressionType: kinesis_types.S3TablesCompressionTypeZstd,
				},
			},
		},
	}

	got := channelDeliveryFrom(desc)

	require.NotNil(t, got.dataFreshnessInSeconds)
	assert.Equal(t, int32(300), *got.dataFreshnessInSeconds)
	require.NotNil(t, got.dlqBucketARN)
	assert.Equal(t, "arn:aws:s3:::tables-dlq", *got.dlqBucketARN)

	require.Len(t, got.tables, 1)
	assert.Equal(t, "arn:aws:s3tables:us-east-1:333333333333:bucket/analytics", *got.tables[0].TableBucketARN)
	assert.Equal(t, "events", *got.tables[0].Namespace)
	assert.Equal(t, "clicks", *got.tables[0].TableName)
	assert.Equal(t, kinesis_types.S3TablesCompressionTypeZstd, got.tables[0].CompressionType)

	// A streaming-table channel has no general purpose bucket. Reporting one
	// would send destinationBucket at a bucket that is not the destination.
	assert.Nil(t, got.bucketARN)
	assert.Nil(t, got.expectedBucketOwner)
	assert.Empty(t, got.compressionType)
	assert.Empty(t, got.storageClass)
	assert.Nil(t, got.outputKeyTemplate)
}

// Every nested struct on the destination path is an SDK pointer, so a channel
// mid-creation, or one read under partial permissions, arrives with them nil.
// The extraction has to yield nulls rather than panic.
func TestChannelDeliveryFrom_AbsentAndPartial(t *testing.T) {
	tests := []struct {
		name string
		desc *kinesis_types.ChannelDescription
	}{
		{"nil description", nil},
		{"no destination configured", &kinesis_types.ChannelDescription{}},
		{
			"s3 destination with nil storage and dlq",
			&kinesis_types.ChannelDescription{
				S3DestinationConfiguration: &kinesis_types.S3DestinationDescription{},
			},
		},
		{
			"tables destination with nil dlq and empty list",
			&kinesis_types.ChannelDescription{
				S3TablesDestinationConfiguration: &kinesis_types.S3TablesDestinationDescription{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := channelDeliveryFrom(tc.desc)
			assert.Nil(t, got.bucketARN)
			assert.Nil(t, got.expectedBucketOwner)
			assert.Nil(t, got.dlqBucketARN)
			assert.Nil(t, got.dlqBucketOwner)
			assert.Nil(t, got.dlqErrorOutputPrefix)
			assert.Nil(t, got.dataFreshnessInSeconds)
			assert.Empty(t, got.tables)
		})
	}
}

// A channel writing two tables that differ only in namespace, or only in
// table bucket, must produce two distinct cache keys. A key that drops either
// dimension collapses the pair, and CreateResource then returns the cached
// first table for the second one.
func TestChannelTableCacheID_Distinct(t *testing.T) {
	channel := "arn:aws:kinesis:us-east-1:444444444444:channel/deliver"

	sameNameDifferentNamespace := channelTableCacheID(channel, "arn:aws:s3tables:::bucket/a", "raw", "clicks")
	otherNamespace := channelTableCacheID(channel, "arn:aws:s3tables:::bucket/a", "curated", "clicks")
	assert.NotEqual(t, sameNameDifferentNamespace, otherNamespace)

	otherTableBucket := channelTableCacheID(channel, "arn:aws:s3tables:::bucket/b", "raw", "clicks")
	assert.NotEqual(t, sameNameDifferentNamespace, otherTableBucket)

	otherChannel := channelTableCacheID("arn:aws:kinesis:us-east-1:444444444444:channel/other", "arn:aws:s3tables:::bucket/a", "raw", "clicks")
	assert.NotEqual(t, sameNameDifferentNamespace, otherChannel)
}
