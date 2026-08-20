// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/stretchr/testify/assert"
)

// TestAutoMLInputChannelCacheKey pins that an AutoML job's input channels are
// told apart by position.
//
// A channel has nothing else that distinguishes it. The target attribute names
// the column the job predicts and is identical across every channel of a job,
// so keying on it merged the training and validation channels into one row and
// made the validation dataset's S3 URI unreachable.
func TestAutoMLInputChannelCacheKey(t *testing.T) {
	const jobArn = "arn:aws:sagemaker:us-east-1:000000000000:automl-job/my-job"

	t.Run("channels of one job do not collide", func(t *testing.T) {
		train := autoMLInputChannelCacheKey(jobArn, 0)
		validation := autoMLInputChannelCacheKey(jobArn, 1)
		assert.NotEqual(t, train, validation)
	})

	t.Run("the same channel keys the same", func(t *testing.T) {
		assert.Equal(t,
			autoMLInputChannelCacheKey(jobArn, 1),
			autoMLInputChannelCacheKey(jobArn, 1))
	})

	t.Run("channels of different jobs do not collide", func(t *testing.T) {
		other := "arn:aws:sagemaker:us-east-1:000000000000:automl-job/other-job"
		assert.NotEqual(t,
			autoMLInputChannelCacheKey(jobArn, 0),
			autoMLInputChannelCacheKey(other, 0))
	})

	t.Run("the key is scoped to its job", func(t *testing.T) {
		assert.Equal(t, jobArn+"/inputChannel/0", autoMLInputChannelCacheKey(jobArn, 0))
	})
}

// TestAutoMLTargetAttributeName pins where the target column is read from on a
// V2 AutoML job.
//
// V1 reported it on every input channel; V2 reports it once, on the
// problem-type config. Only a tabular job has a target column, so every other
// problem type has to read null rather than empty - an empty string would claim
// the job named no target, which is a different statement from having none.
func TestAutoMLTargetAttributeName(t *testing.T) {
	t.Run("tabular job reports its target column", func(t *testing.T) {
		target := "churn"
		got := autoMLTargetAttributeName(&sagemakertypes.AutoMLProblemTypeConfigMemberTabularJobConfig{
			Value: sagemakertypes.TabularJobConfig{TargetAttributeName: &target},
		})
		if assert.NotNil(t, got) {
			assert.Equal(t, "churn", *got)
		}
	})

	t.Run("a tabular job that names no target reads null", func(t *testing.T) {
		assert.Nil(t, autoMLTargetAttributeName(
			&sagemakertypes.AutoMLProblemTypeConfigMemberTabularJobConfig{
				Value: sagemakertypes.TabularJobConfig{},
			}))
	})

	t.Run("a problem type with no target column reads null", func(t *testing.T) {
		assert.Nil(t, autoMLTargetAttributeName(
			&sagemakertypes.AutoMLProblemTypeConfigMemberTextClassificationJobConfig{
				Value: sagemakertypes.TextClassificationJobConfig{},
			}))
		assert.Nil(t, autoMLTargetAttributeName(
			&sagemakertypes.AutoMLProblemTypeConfigMemberTimeSeriesForecastingJobConfig{
				Value: sagemakertypes.TimeSeriesForecastingJobConfig{},
			}))
	})

	t.Run("an absent config reads null", func(t *testing.T) {
		assert.Nil(t, autoMLTargetAttributeName(nil))
	})
}
