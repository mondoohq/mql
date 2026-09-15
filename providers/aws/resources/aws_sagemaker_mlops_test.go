// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

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
