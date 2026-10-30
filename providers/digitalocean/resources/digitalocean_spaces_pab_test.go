// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicAccessBlockedValue(t *testing.T) {
	allOn := &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(true),
		BlockPublicPolicy:     aws.Bool(true),
		IgnorePublicAcls:      aws.Bool(true),
		RestrictPublicBuckets: aws.Bool(true),
	}
	partial := &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(true),
		BlockPublicPolicy:     aws.Bool(false),
		IgnorePublicAcls:      aws.Bool(true),
		RestrictPublicBuckets: aws.Bool(true),
	}

	t.Run("all four controls on", func(t *testing.T) {
		v, err := publicAccessBlockedValue(allOn, nil)
		require.NoError(t, err)
		require.NotNil(t, v)
		assert.True(t, *v)
	})

	t.Run("one control off", func(t *testing.T) {
		v, err := publicAccessBlockedValue(partial, nil)
		require.NoError(t, err)
		require.NotNil(t, v)
		assert.False(t, *v)
	})

	t.Run("service does not implement the control", func(t *testing.T) {
		// This is every DigitalOcean account: Spaces answers 501 because it
		// has no block-public-access feature at all. Reporting false here
		// would state as fact that public access is not blocked, when
		// nothing was ever read. The field has to be null.
		v, err := publicAccessBlockedValue(nil, &smithy.GenericAPIError{Code: "NotImplemented"})
		require.NoError(t, err)
		assert.Nil(t, v)
	})

	t.Run("bucket has no configuration", func(t *testing.T) {
		// On a service that does implement the control, "no configuration"
		// is a real answer and it means nothing is blocked.
		v, err := publicAccessBlockedValue(nil, &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"})
		require.NoError(t, err)
		require.NotNil(t, v)
		assert.False(t, *v)
	})

	t.Run("success with no configuration block", func(t *testing.T) {
		v, err := publicAccessBlockedValue(nil, nil)
		require.NoError(t, err)
		require.NotNil(t, v)
		assert.False(t, *v)
	})

	t.Run("transport failure is not an answer", func(t *testing.T) {
		// A network blip must not degrade into a posture claim.
		_, err := publicAccessBlockedValue(nil, errors.New("dial tcp: i/o timeout"))
		require.Error(t, err)
	})
}
