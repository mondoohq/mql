// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ARM sends an error either wrapped in an "error" envelope or bare, and azcore
// only fills ResponseError.ErrorCode from the wrapped form. An allowlist keyed
// on ErrorCode alone therefore never matches a bare error, however many codes
// are added to it.
//
// This is not hypothetical: reading diagnostic settings across a subscription
// answers 400 ResourceTypeNotSupported for every resource type that cannot have
// them, bare, and that error must classify as not-applicable or one unsupported
// resource costs the whole list.
func TestAzureErrorCodeReadsBothEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "bare envelope, which azcore leaves ErrorCode empty for",
			body: `{"code":"ResourceTypeNotSupported","message":"The resource type 'microsoft.network/networkwatchers' does not support diagnostic settings."}`,
			want: "ResourceTypeNotSupported",
		},
		{
			name: "wrapped envelope",
			body: `{"error":{"code":"LongTermRetentionPolicyNotSupported","message":"Not supported for master."}}`,
			want: "LongTermRetentionPolicyNotSupported",
		},
		{
			name: "neither shape carries a code",
			body: `{"message":"something went wrong"}`,
			want: "",
		},
		{
			name: "body is not json",
			body: `<html>502</html>`,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, azureErrorCode(asResponseError(t, armError(http.StatusBadRequest, tc.body))))
		})
	}
}

// The classifier has to answer true for a withdrawn capability and false for a
// fault, and the bare-envelope case is the one that regressed silently.
func TestResourceTypeNotSupportedIsNotApplicable(t *testing.T) {
	notSupported := armError(http.StatusBadRequest,
		`{"code":"ResourceTypeNotSupported","message":"The resource type 'microsoft.network/networkwatchers' does not support diagnostic settings."}`)
	require.True(t, isAzureNotConfigured(notSupported),
		"a resource type that cannot have the feature is not a failure")

	// A 400 the allowlist does not name is our bug or a transient state, and
	// swallowing it would hide either.
	badRequest := armError(http.StatusBadRequest,
		`{"code":"InvalidApiVersionParameter","message":"The api-version is invalid."}`)
	assert.False(t, isAzureNotConfigured(badRequest),
		"an unlisted 400 must still propagate")
}
