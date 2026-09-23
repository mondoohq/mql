// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	smithy "github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The aws mapping from an API failure to an mql ErrorKind (ADR 046 §2).
//
// AWS puts the meaning in the error code more often than in the HTTP status,
// so the checks below read the code first and fall back to the SDK's status
// mapping last:
//
//   - a denial answers 400 as often as 403 (EC2 UnauthorizedOperation), which
//     the status mapping would leave unclassified
//   - an invalid or expired credential answers 403 (InvalidClientTokenId),
//     which the status mapping would call forbidden
//   - EC2 throttles with 503 RequestLimitExceeded, which the status mapping
//     would call unavailable, and most other services throttle with a 400

// awsUnauthenticatedErrorCodes are the codes AWS answers when the credentials
// themselves are the problem: unknown, expired, or signed with the wrong
// secret. Different grants would not help; different credentials would.
var awsUnauthenticatedErrorCodes = map[string]struct{}{
	"AuthFailure":                 {},
	"ExpiredToken":                {},
	"ExpiredTokenException":       {},
	"InvalidAccessKeyId":          {},
	"InvalidClientTokenId":        {},
	"SignatureDoesNotMatch":       {},
	"UnrecognizedClientException": {},
}

// classifyAwsError classifies err for the caller to return. permissions names
// the grants the refused call needed, and rides along only when the answer is
// a denial.
//
// err is returned unchanged when it is nil, already classified, or makes no
// claim the user could act on. Region loops do not call this: a refusal in one
// region is a partial result, not a field error (ADR 046 §8).
func classifyAwsError(err error, permissions ...string) error {
	if err == nil || llx.KindOf(err) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return err
	}

	// A service the account never turned on answers with the vocabulary of a
	// denial (Macie: 401/403 AccessDeniedException), so these run before any
	// denial check.
	if isOrganizationsNotInUseError(err) || IsMacieNotEnabledError(err) || IsSecurityLakeNotEnabledError(err) {
		return llx.NotApplicable(err)
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if _, ok := awsUnauthenticatedErrorCodes[code]; ok {
			return llx.Unauthenticated(err, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
		}
		// The SDK's own list, the one its retryer backs off on.
		if _, ok := retry.DefaultThrottleErrorCodes[code]; ok {
			return llx.TooManyRequests(err)
		}
	}

	if Is400AccessDeniedError(err) {
		var opts []llx.ErrorOption
		if len(permissions) > 0 {
			opts = append(opts, llx.WithPermissions(permissions...))
		}
		return llx.Forbidden(err, opts...)
	}

	if IsServiceNotAvailableInRegionError(err) {
		return llx.NotApplicable(err)
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response != nil && respErr.Response.Response != nil {
		return plugin.ClassifyHTTPStatus(err, respErr.HTTPStatusCode(), respErr.Response.Header)
	}
	return err
}
