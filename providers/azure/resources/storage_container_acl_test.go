// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	armstorage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azqueue/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoredAccessPolicyNormalization(t *testing.T) {
	str := func(s string) *string { return &s }
	ts := func(s string) *time.Time {
		parsed, err := time.Parse(time.RFC3339, s)
		require.NoError(t, err)
		return &parsed
	}

	t.Run("no policies is an empty list, never nil", func(t *testing.T) {
		require.NotNil(t, blobStoredAccessPolicies(nil))
		require.NotNil(t, queueStoredAccessPolicies(nil))
		require.NotNil(t, tableStoredAccessPolicies(nil))
	})

	t.Run("nil entries are skipped", func(t *testing.T) {
		assert.Empty(t, blobStoredAccessPolicies([]*container.SignedIdentifier{nil, nil}))
		assert.Empty(t, queueStoredAccessPolicies([]*azqueue.SignedIdentifier{nil, nil}))
		assert.Empty(t, tableStoredAccessPolicies([]*armstorage.TableSignedIdentifier{nil, nil}))
	})

	// The three services ship three SignedIdentifier types for the same four
	// values, and armstorage names the timestamps StartTime/ExpiryTime where
	// the data-plane SDKs name them Start/Expiry. Reading the wrong pair off
	// any one of them leaves every policy on that service reporting no expiry,
	// which is the same answer a genuinely non-expiring policy gives.
	t.Run("every service maps onto the same four values", func(t *testing.T) {
		start, expiry := ts("2026-01-02T03:04:05Z"), ts("2027-01-02T03:04:05Z")
		want := storedAccessPolicy{id: str("readers"), permission: str("rl"), startTime: start, expiryTime: expiry}

		blob := blobStoredAccessPolicies([]*container.SignedIdentifier{{
			ID:           str("readers"),
			AccessPolicy: &container.AccessPolicy{Permission: str("rl"), Start: start, Expiry: expiry},
		}})
		require.Len(t, blob, 1)
		assert.Equal(t, want, blob[0])

		queue := queueStoredAccessPolicies([]*azqueue.SignedIdentifier{{
			ID:           str("readers"),
			AccessPolicy: &azqueue.AccessPolicy{Permission: str("rl"), Start: start, Expiry: expiry},
		}})
		require.Len(t, queue, 1)
		assert.Equal(t, want, queue[0])

		table := tableStoredAccessPolicies([]*armstorage.TableSignedIdentifier{{
			ID:           str("readers"),
			AccessPolicy: &armstorage.TableAccessPolicy{Permission: str("rl"), StartTime: start, ExpiryTime: expiry},
		}})
		require.Len(t, table, 1)
		assert.Equal(t, want, table[0])
	})

	t.Run("a policy with no access policy still reports its id", func(t *testing.T) {
		res := blobStoredAccessPolicies([]*container.SignedIdentifier{{ID: str("orphan")}})
		require.Len(t, res, 1)
		assert.Equal(t, storedAccessPolicy{id: str("orphan")}, res[0])
	})

	// An absent timestamp has to stay nil so the resource reports null. Zeroing
	// it would publish 1 January year 1 as a real expiry, and a check for
	// "expires in the past" would then pass on a policy that never expires.
	t.Run("absent times stay nil, not zero-valued", func(t *testing.T) {
		res := blobStoredAccessPolicies([]*container.SignedIdentifier{{
			ID:           str("perm"),
			AccessPolicy: &container.AccessPolicy{Permission: str("r")},
		}})
		require.Len(t, res, 1)
		assert.Nil(t, res[0].startTime)
		assert.Nil(t, res[0].expiryTime)
	})
}

// The regression this guards: classifying a transport failure as "unreadable"
// would turn a network blip into a null field, and a policy that treats null as
// "nothing to check" would pass on data that was never read.
func TestIsBlobDataPlaneUnreadable(t *testing.T) {
	respErr := func(code int) error {
		return &azcore.ResponseError{StatusCode: code, RawResponse: &http.Response{StatusCode: code}}
	}

	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound} {
		assert.True(t, isBlobDataPlaneUnreadable(respErr(code)), "status %d", code)
	}

	for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		assert.False(t, isBlobDataPlaneUnreadable(respErr(code)), "status %d", code)
	}

	assert.False(t, isBlobDataPlaneUnreadable(errors.New("connection reset by peer")))
	assert.False(t, isBlobDataPlaneUnreadable(nil))
}
