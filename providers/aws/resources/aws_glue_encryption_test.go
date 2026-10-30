// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	glue_types "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlueS3Encryption(t *testing.T) {
	t.Run("nil encryption configuration", func(t *testing.T) {
		assert.Nil(t, glueS3Encryption(nil))
	})

	t.Run("empty S3Encryption list", func(t *testing.T) {
		// The SDK models S3Encryption as a slice, so a configuration that
		// encrypts only CloudWatch logs leaves it empty. Indexing [0] without
		// this guard panics the whole scan.
		assert.Nil(t, glueS3Encryption(&glue_types.EncryptionConfiguration{
			CloudWatchEncryption: &glue_types.CloudWatchEncryption{
				CloudWatchEncryptionMode: glue_types.CloudWatchEncryptionModeSsekms,
			},
		}))
	})

	t.Run("returns the configured entry", func(t *testing.T) {
		keyArn := "arn:aws:kms:us-east-1:123456789012:key/abc"
		got := glueS3Encryption(&glue_types.EncryptionConfiguration{
			S3Encryption: []glue_types.S3Encryption{{
				S3EncryptionMode: glue_types.S3EncryptionModeSsekms,
				KmsKeyArn:        &keyArn,
			}},
		})
		require.NotNil(t, got)
		assert.Equal(t, glue_types.S3EncryptionModeSsekms, got.S3EncryptionMode)
		require.NotNil(t, got.KmsKeyArn)
		assert.Equal(t, keyArn, *got.KmsKeyArn)
	})

	t.Run("returns a pointer into the slice, not a copy of the zero value", func(t *testing.T) {
		// Taking the address of a range variable instead of &enc.S3Encryption[0]
		// is the classic way to break this; the returned pointer must alias the
		// caller's slice.
		enc := &glue_types.EncryptionConfiguration{
			S3Encryption: []glue_types.S3Encryption{{
				S3EncryptionMode: glue_types.S3EncryptionModeSses3,
			}},
		}
		assert.Same(t, &enc.S3Encryption[0], glueS3Encryption(enc))
	})
}
