// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batchStatusHasNoBody gates whether a sub-response reaches the deserializer.
// Getting it wrong in either direction is a real bug: too narrow and a
// body-less success panics the parse, too wide and a real payload is silently
// dropped.
func TestBatchStatusHasNoBody(t *testing.T) {
	tests := []struct {
		name string
		code int32
		want bool
	}{
		{"204 no content", http.StatusNoContent, true},
		{"205 reset content", http.StatusResetContent, true},
		{"200 ok carries a body", http.StatusOK, false},
		{"201 created carries a body", http.StatusCreated, false},
		{"202 accepted carries a body", http.StatusAccepted, false},
		{"206 partial content carries a body", http.StatusPartialContent, false},
		{"403 is handled by the non-2xx guard", http.StatusForbidden, false},
		{"404 is handled by the non-2xx guard", http.StatusNotFound, false},
		{"429 is handled by the non-2xx guard", http.StatusTooManyRequests, false},
		{"zero value", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, batchStatusHasNoBody(tc.code))
		})
	}
}

// The two guards in batchGet must partition every status code: a non-2xx is an
// error, a body-less 2xx is an absence, and everything else is parsed. A code
// falling through both that has no body is exactly the 204 case that panicked.
func TestBatchStatusGuardsPartitionAllCodes(t *testing.T) {
	isFailure := func(code int32) bool { return code < 200 || code >= 300 }

	for code := int32(100); code < 600; code++ {
		failure := isFailure(code)
		noBody := batchStatusHasNoBody(code)
		assert.Falsef(t, failure && noBody,
			"status %d is classified as both a failure and a body-less success", code)

		if noBody {
			assert.Truef(t, code >= 200 && code < 300,
				"only a 2xx should reach the body-less branch, got %d", code)
		}
	}

	assert.True(t, batchStatusHasNoBody(http.StatusNoContent),
		"204 must be caught before the parse: it is a success, so the non-2xx guard lets it through, "+
			"and GetBatchResponseById panics on the absent body")
}

// batchEach must hand each chunk's results over before it sends the next
// chunk, so a fetch over every user of a large tenant never holds more than
// one chunk of raw responses. A failed sub-request or a failing callback is
// recorded for its key alone.
func TestBatchEachStreamsChunks(t *testing.T) {
	const n = 2*batchChunkSize + 7
	routes := map[string]fakeRoute{}
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("u%02d", i)
		routes["/users/"+keys[i]] = fakeRoute{status: http.StatusOK, body: `{"id":"` + keys[i] + `"}`}
	}
	routes["/users/u03"] = fakeRoute{status: http.StatusForbidden, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`}
	f := newFakeGraph(t, routes)
	client := f.client()
	ctx := context.Background()

	sentWhenSeen := map[string]int{}
	errs, statuses, err := batchEach(ctx, client.GetAdapter(), keys,
		func(key string) (*abstractions.RequestInformation, error) {
			return client.Users().ByUserId(key).ToGetRequestInformation(ctx, nil)
		},
		models.CreateUserFromDiscriminatorValue,
		func(key string, u *models.User) error {
			assert.Equal(t, key, *u.GetId())
			f.mu.Lock()
			sentWhenSeen[key] = len(f.steps)
			f.mu.Unlock()
			if key == "u40" {
				return errors.New("convert failed")
			}
			return nil
		})
	require.NoError(t, err)

	assert.Len(t, sentWhenSeen, n-1, "every key but the failed one reaches the callback")
	for i, key := range keys {
		if key == "u03" {
			continue
		}
		chunkEnd := min((i/batchChunkSize+1)*batchChunkSize, n)
		assert.Equalf(t, chunkEnd, sentWhenSeen[key], "%s was handed over after a later chunk was sent", key)
	}
	assert.Equal(t, int32(http.StatusForbidden), statuses["u03"])
	assert.EqualError(t, errs["u03"], "batch request failed with status 403")
	assert.EqualError(t, errs["u40"], "convert failed")
	assert.Len(t, errs, 2)
	assert.Len(t, statuses, n)
}
