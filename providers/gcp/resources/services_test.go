// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceUsageQuotaRetryer(t *testing.T) {
	quotaErr := status.Error(codes.ResourceExhausted, "Quota exceeded for quota metric 'List available/disabled services requests'")

	t.Run("retries a quota rejection a bounded number of times", func(t *testing.T) {
		r := newServiceUsageQuotaRetryer()
		for i := 0; i < serviceUsageMaxRetries; i++ {
			pause, retry := r.Retry(quotaErr)
			assert.True(t, retry, "attempt %d", i+1)
			assert.LessOrEqual(t, pause, 60*time.Second)
		}
		_, retry := r.Retry(quotaErr)
		assert.False(t, retry, "a project over quota for good must still answer with the error")
	})

	t.Run("does not retry other failures", func(t *testing.T) {
		for _, err := range []error{
			status.Error(codes.PermissionDenied, "serviceusage.services.list denied"),
			status.Error(codes.NotFound, "project not found"),
			errors.New("connection reset by peer"),
		} {
			_, retry := newServiceUsageQuotaRetryer().Retry(err)
			assert.False(t, retry, err.Error())
		}
	})

	t.Run("each call starts with a fresh attempt budget", func(t *testing.T) {
		first := newServiceUsageQuotaRetryer()
		for i := 0; i < serviceUsageMaxRetries; i++ {
			first.Retry(quotaErr)
		}
		_, retry := newServiceUsageQuotaRetryer().Retry(quotaErr)
		assert.True(t, retry)
	})
}
