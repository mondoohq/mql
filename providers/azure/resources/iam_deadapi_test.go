// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/assert"
)

func armCodedError(status int, code string) error {
	return &azcore.ResponseError{StatusCode: status, ErrorCode: code}
}

// classicAdministrators returned ARM's 404 raw, so the field failed on every
// subscription: Azure retired the resource type on 31 August 2024 and removed it
// from the Microsoft.Authorization namespace rather than emptying it.
//
// The status is checked alongside the code deliberately. A genuinely missing
// subscription is also a 404, and that one must keep reporting as an error
// rather than as "no classic administrators".
func TestAzureClassicAdministratorsRetired(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "the retirement shape",
			err:  armCodedError(http.StatusNotFound, "InvalidResourceType"),
			want: true,
		},
		{
			name: "wrapped, as a pager returns it",
			err:  fmt.Errorf("listing failed: %w", armCodedError(http.StatusNotFound, "InvalidResourceType")),
			want: true,
		},
		{
			// The case the code check exists for.
			name: "a missing subscription is still an error",
			err:  armCodedError(http.StatusNotFound, "SubscriptionNotFound"),
		},
		{
			name: "a 404 with no code",
			err:  armCodedError(http.StatusNotFound, ""),
		},
		{
			name: "the right code on the wrong status",
			err:  armCodedError(http.StatusBadRequest, "InvalidResourceType"),
		},
		{
			name: "no permission to read the subscription is still an error",
			err:  armCodedError(http.StatusForbidden, "AuthorizationFailed"),
		},
		{
			// A network blip must never be reported as an authoritative empty.
			name: "a transport error is not a retirement",
			err:  errors.New("dial tcp: connection reset by peer"),
		},
		{name: "nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, azureClassicAdministratorsRetired(tc.err))
		})
	}
}

// A subscription's location list includes staging and edge regions most services
// never ship to, so a per-region fan-out hits NoRegisteredProviderFound
// routinely. It means there is nothing there, which is not the same as being
// unable to look -- so it is logged at debug and everything else stays a warning.
func TestAzureProviderNotInRegion(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "the provider is not deployed in that region",
			err:  armCodedError(http.StatusBadRequest, "NoRegisteredProviderFound"),
			want: true,
		},
		{
			// Matched on the code alone, because ARM has not been consistent
			// about which status it pairs this with.
			name: "the same code on another status",
			err:  armCodedError(http.StatusNotFound, "NoRegisteredProviderFound"),
			want: true,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("region westus: %w", armCodedError(http.StatusBadRequest, "NoRegisteredProviderFound")),
			want: true,
		},
		{
			// The case this must not swallow: it is the reason the warning
			// stream exists.
			name: "access denied is a real problem",
			err:  armCodedError(http.StatusForbidden, "AuthorizationFailed"),
		},
		{
			name: "throttling is a real problem",
			err:  armCodedError(http.StatusTooManyRequests, "TooManyRequests"),
		},
		{
			name: "a transport error is not an absence",
			err:  errors.New("context deadline exceeded"),
		},
		{name: "nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, azureProviderNotInRegion(tc.err))
		})
	}
}

// The two classifiers must not overlap: each one's shape must be rejected by the
// other, or a real regional problem could be reported as a retirement.
func TestDeadApiClassifiersAreDisjoint(t *testing.T) {
	retirement := armCodedError(http.StatusNotFound, "InvalidResourceType")
	notInRegion := armCodedError(http.StatusBadRequest, "NoRegisteredProviderFound")

	assert.False(t, azureProviderNotInRegion(retirement))
	assert.False(t, azureClassicAdministratorsRetired(notInRegion))
}
