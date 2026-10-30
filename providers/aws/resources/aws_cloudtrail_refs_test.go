// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
)

// trailDeniedErr builds the 403 shape Is400AccessDeniedError matches. apiErr
// itself is the shared helper from aws_disposition_test.go.
func trailDeniedErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 403}},
			Err:      apiErr("AccessDenied", "not authorized to perform iam:GetRole"),
		},
	}
}

func TestReferencedResourceUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			// The case this fix exists for: a trail keeps naming a role that has
			// been deleted.
			name: "deleted iam role",
			err:  apiErr("NoSuchEntity", "The role with name CloudTrailRoleForCloudWatchLogs cannot be found."),
			want: true,
		},
		{
			name: "deleted sns topic",
			err:  apiErr("NotFoundException", "Topic does not exist"),
			want: true,
		},
		{
			name: "deleted log group",
			err:  apiErr("ResourceNotFoundException", "The specified log group does not exist"),
			want: true,
		},
		{
			name: "not found",
			err:  apiErr("NotFound", "not found"),
			want: true,
		},
		{
			name: "access denied is permanent for this scan",
			err:  trailDeniedErr(),
			want: true,
		},

		// Everything below may resolve on a retry, so reporting the reference as
		// null would assert an absence that was never established.
		{
			name: "throttling must not look like an absent reference",
			err:  apiErr("ThrottlingException", "Rate exceeded"),
			want: false,
		},
		{
			name: "a service fault must not look like an absent reference",
			err:  apiErr("InternalFailure", "internal service error"),
			want: false,
		},
		{
			name: "a network failure carries no api error",
			err:  errors.New("dial tcp: lookup iam.amazonaws.com: no such host"),
			want: false,
		},
		{
			name: "retry exhaustion must not look like an absent reference",
			err:  errors.New("exceeded maximum number of attempts, 3, request send failed"),
			want: false,
		},
		{
			name: "nil is not a match",
			err:  nil,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, referencedResourceUnavailable(tc.err))
		})
	}
}

// The error travels back through NewResource and the init, so the classifier has
// to see through wrapping.
func TestReferencedResourceUnavailableThroughWrapping(t *testing.T) {
	gone := apiErr("NoSuchEntity", "The role cannot be found")
	assert.True(t, referencedResourceUnavailable(
		fmt.Errorf("could not resolve reference: %w", gone)))

	transient := apiErr("ThrottlingException", "Rate exceeded")
	assert.False(t, referencedResourceUnavailable(
		fmt.Errorf("could not resolve reference: %w", transient)))
}
