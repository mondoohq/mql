// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithy "github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// awsAPIError builds the error the SDK hands back for a failed call: an API
// error with a code, inside the HTTP response error that carries the status.
func awsAPIError(status int, code, msg string) error {
	return awsAPIErrorWithHeader(status, nil, code, msg)
}

func awsAPIErrorWithHeader(status int, header http.Header, code, msg string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status, Header: header}},
			Err:      &smithy.GenericAPIError{Code: code, Message: msg},
		},
	}
}

func TestClassifyAwsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want llx.ErrorKind
	}{
		// EC2 denies with a 400, which the HTTP status mapping leaves unclassified.
		{"ec2 denial on 400", awsAPIError(400, "UnauthorizedOperation", "You are not authorized to perform this operation."), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"denial on 403", awsAPIError(403, "AccessDeniedException", "User is not authorized to perform ec2:DescribeInstances"), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		// A bad credential answers 403, which the HTTP status mapping would call forbidden.
		{"invalid token on 403", awsAPIError(403, "InvalidClientTokenId", "The security token included in the request is invalid."), llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"expired token on 400", awsAPIError(400, "ExpiredToken", "The security token included in the request is expired"), llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"ec2 auth failure on 401", awsAPIError(401, "AuthFailure", "AWS was not able to validate the provided access credentials"), llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		// EC2 throttles with a 503, which the HTTP status mapping would call unavailable.
		{"ec2 throttle on 503", awsAPIError(503, "RequestLimitExceeded", "Request limit exceeded."), llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"throttle on 400", awsAPIError(400, "ThrottlingException", "Rate exceeded"), llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"unavailable on 503", awsAPIError(503, "Unavailable", "The server is temporarily unable to handle the request."), llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"not found on 404", awsAPIError(404, "NotFound", "not found"), llx.ErrorKind_ERROR_KIND_NOT_FOUND},
		{"api not in region", awsAPIError(400, "InvalidAction", "The action DescribeVerifiedAccessInstances is not valid for this web service."), llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"endpoint not in region", errors.New("dial tcp: lookup ec2.xx-east-9.amazonaws.com: no such host"), llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		// A service the account never turned on is not a denial, even when it
		// answers like one.
		{"macie not enabled on 403", awsAPIError(403, "AccessDeniedException", "Macie is not enabled"), llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"security lake not enabled", awsAPIError(404, "ResourceNotFoundException", "Security Lake isn't enabled for your account in any Regions"), llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"standalone account", &orgtypes.AWSOrganizationsNotInUseException{Message: aws.String("Your account is not a member of an organization.")}, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		// Nothing for the user to do, so no claim.
		{"internal error on 500", awsAPIError(500, "InternalError", "An internal error has occurred."), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"bad parameter on 400", awsAPIError(400, "InvalidParameterValue", "Value for parameter is invalid."), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
		{"plain error", errors.New("boom"), llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAwsError(tt.err, "ec2:DescribeInstances")
			assert.Equal(t, tt.want, llx.KindOf(got))
			if tt.want == llx.ErrorKind_ERROR_KIND_FORBIDDEN {
				assert.Equal(t, []string{"ec2:DescribeInstances"}, llx.ErrorDetailOf(got).GetPermissions())
			} else {
				assert.Empty(t, llx.ErrorDetailOf(got).GetPermissions(), "a grant fixes only a denial")
			}
			assert.Equal(t, tt.err.Error(), got.Error(), "the target's own words are kept")
			if tt.want == llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
				assert.Same(t, tt.err, got, "an unclassified error is returned untouched")
			}
		})
	}
}

func TestClassifyAwsErrorNil(t *testing.T) {
	assert.NoError(t, classifyAwsError(nil, "ec2:DescribeInstances"))
}

func TestClassifyAwsErrorUnauthenticatedIsAssetScoped(t *testing.T) {
	err := classifyAwsError(awsAPIError(403, "InvalidClientTokenId", "The security token included in the request is invalid."))
	assert.Equal(t, llx.ErrorScope_ERROR_SCOPE_ASSET, llx.ErrorDetailOf(err).GetScope())
}

func TestClassifyAwsErrorRetryAfter(t *testing.T) {
	header := http.Header{"Retry-After": []string{"5"}}

	t.Run("unavailable", func(t *testing.T) {
		err := classifyAwsError(awsAPIErrorWithHeader(503, header, "Unavailable", "try later"))
		require.ErrorIs(t, err, llx.ErrTargetUnavailable)
		assert.Equal(t, (5 * time.Second).Milliseconds(), llx.ErrorDetailOf(err).GetRetryAfterMs())
	})

	// A throttle recognized by its code, before the HTTP status mapping runs,
	// keeps the server's hint too.
	t.Run("throttle by error code", func(t *testing.T) {
		err := classifyAwsError(awsAPIErrorWithHeader(503, header, "RequestLimitExceeded", "Request limit exceeded."))
		require.ErrorIs(t, err, llx.ErrTooManyRequests)
		assert.Equal(t, (5 * time.Second).Milliseconds(), llx.ErrorDetailOf(err).GetRetryAfterMs())
	})
}

// Init lookups wrap the SDK error with the resource they were fetching; the
// classification must still find it underneath.
func TestClassifyAwsErrorThroughWrapping(t *testing.T) {
	inner := awsAPIError(400, "UnauthorizedOperation", "You are not authorized to perform this operation.")
	err := classifyAwsError(fmt.Errorf("fetching aws.ec2.ipam with id %q in region %s: %w", "ipam-1", "us-east-1", inner), "ec2:DescribeIpams")
	require.ErrorIs(t, err, llx.ErrForbidden)
	assert.Contains(t, err.Error(), "aws.ec2.ipam")
}

// A classification made further down the stack is not second-guessed.
func TestClassifyAwsErrorKeepsExistingKind(t *testing.T) {
	already := llx.NotApplicable(awsAPIError(403, "AccessDeniedException", "Macie is not enabled"))
	assert.Same(t, already, classifyAwsError(already, "macie2:GetMacieSession"))
}
