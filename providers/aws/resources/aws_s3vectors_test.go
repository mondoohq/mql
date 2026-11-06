// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3vtypes "github.com/aws/aws-sdk-go-v2/service/s3vectors/types"
	"github.com/stretchr/testify/assert"
)

func TestS3VectorsEncryption(t *testing.T) {
	// Synthetic: KMS-encrypted bucket.
	sse, key := s3VectorsEncryption(&s3vtypes.EncryptionConfiguration{
		SseType:   s3vtypes.SseTypeAwsKms,
		KmsKeyArn: aws.String("arn:aws:kms:us-east-1:123456789012:key/k1"),
	})
	assert.Equal(t, "aws:kms", sse)
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/k1", key)

	// Synthetic: S3 managed keys never resolve to a KMS key.
	sse, key = s3VectorsEncryption(&s3vtypes.EncryptionConfiguration{
		SseType:   s3vtypes.SseTypeAes256,
		KmsKeyArn: aws.String("arn:aws:kms:us-east-1:123456789012:key/stale"),
	})
	assert.Equal(t, "AES256", sse)
	assert.Empty(t, key)

	// Synthetic: no configuration reads as unknown.
	sse, key = s3VectorsEncryption(nil)
	assert.Empty(t, sse)
	assert.Empty(t, key)
}

func TestS3VectorBucketArnOfIndex(t *testing.T) {
	// Synthetic: ARN shape from the S3 Vectors API reference.
	assert.Equal(t, "arn:aws:s3vectors:us-east-1:123456789012:bucket/kb-vectors",
		s3VectorBucketArnOfIndex("arn:aws:s3vectors:us-east-1:123456789012:bucket/kb-vectors/index/docs"))
	assert.Empty(t, s3VectorBucketArnOfIndex("arn:aws:s3vectors:us-east-1:123456789012:bucket/kb-vectors"))
	assert.Empty(t, s3VectorBucketArnOfIndex("not-an-arn"))
	assert.Empty(t, s3VectorBucketArnOfIndex(""))
}
