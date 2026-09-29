// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
)

func TestS3BlockedEncryptionTypes(t *testing.T) {
	assert.Nil(t, s3BlockedEncryptionTypes(nil), "an unreported setting is null, not nothing blocked")
	assert.Equal(t, []any{}, s3BlockedEncryptionTypes(&s3types.BlockedEncryptionTypes{}))
	assert.Equal(t, []any{"SSE-C"}, s3BlockedEncryptionTypes(&s3types.BlockedEncryptionTypes{
		EncryptionType: []s3types.EncryptionType{s3types.EncryptionTypeSseC},
	}))
}
