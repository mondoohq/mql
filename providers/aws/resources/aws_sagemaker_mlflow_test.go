// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestTrackingServerActive(t *testing.T) {
	// Synthetic: both states and the unreported case.
	assert.Equal(t, true, trackingServerActive(sagemakertypes.IsTrackingServerActiveActive).Value)
	assert.Equal(t, false, trackingServerActive(sagemakertypes.IsTrackingServerActiveInactive).Value)
	assert.Nil(t, trackingServerActive("").Value)
}

func TestSagemakerOptionalFields(t *testing.T) {
	// Synthetic: absent values are null, not zero values.
	var s plugin.TValue[string]
	_, err := sagemakerOptString(nil, &s)
	require.NoError(t, err)
	assert.True(t, s.IsNull())

	s = plugin.TValue[string]{}
	_, err = sagemakerOptString(aws.String(""), &s)
	require.NoError(t, err)
	assert.True(t, s.IsNull())

	s = plugin.TValue[string]{}
	got, err := sagemakerOptString(aws.String("https://t-abc.us-east-1.experiments.sagemaker.aws"), &s)
	require.NoError(t, err)
	assert.Equal(t, "https://t-abc.us-east-1.experiments.sagemaker.aws", got)
	assert.False(t, s.IsNull())

	var b plugin.TValue[bool]
	_, err = sagemakerOptBool(nil, &b)
	require.NoError(t, err)
	assert.True(t, b.IsNull())

	b = plugin.TValue[bool]{}
	v, err := sagemakerOptBool(aws.Bool(false), &b)
	require.NoError(t, err)
	assert.False(t, v)
	assert.False(t, b.IsNull(), "an explicit false is a value")
}
