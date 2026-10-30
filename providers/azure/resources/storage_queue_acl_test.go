// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/assert"
)

// The regression this guards: classifying a transport failure as "unreadable"
// would turn a network blip into a null field, and a policy that treats null as
// "nothing to check" would pass on data that was never read.
func TestIsQueueDataPlaneUnreadable(t *testing.T) {
	respErr := func(code int) error {
		return &azcore.ResponseError{StatusCode: code, RawResponse: &http.Response{StatusCode: code}}
	}

	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound} {
		assert.True(t, isQueueDataPlaneUnreadable(respErr(code)), "status %d", code)
	}

	for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		assert.False(t, isQueueDataPlaneUnreadable(respErr(code)), "status %d", code)
	}

	assert.False(t, isQueueDataPlaneUnreadable(errors.New("connection reset by peer")))
	assert.False(t, isQueueDataPlaneUnreadable(nil))
}
