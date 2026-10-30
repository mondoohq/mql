// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// apiErr builds an error shaped like the one a real SDK call returns: the API
// error wrapped in an OperationError, which is what callers actually get.
func apiErr(code, message string) error {
	return &smithy.OperationError{
		ServiceID:     "test",
		OperationName: "TestOp",
		Err:           &smithy.GenericAPIError{Code: code, Message: message},
	}
}

func TestClassifyAccessDeniedIsUnreadable(t *testing.T) {
	for _, code := range []string{
		"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
		"AuthorizationError", "AuthFailure", "InvalidClientTokenId",
	} {
		t.Run(code, func(t *testing.T) {
			require.Equal(t, dispositionUnreadable, classifyError("ecr", apiErr(code, "nope")))
		})
	}
}

func TestClassifyAbsentServiceIsEmpty(t *testing.T) {
	for _, code := range []string{
		"OptInRequired", "UnknownOperationException", "InvalidAction",
		"SubscriptionRequiredException",
	} {
		t.Run(code, func(t *testing.T) {
			require.Equal(t, dispositionEmpty, classifyError("bedrock", apiErr(code, "not here")))
		})
	}
}

func TestClassifyRealFailuresAreFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"throttling", apiErr("ThrottlingException", "Rate exceeded")},
		{"internal error", apiErr("InternalServerError", "boom")},
		{"validation", apiErr("ValidationException", "bad parameter")},
		{"plain error", errors.New("something went wrong")},
		// Retry exhaustion on its own is a throttle or a 5xx, and the caller has
		// to see it. Only exhaustion *plus* a send failure means the endpoint is
		// not really there.
		{"retries exhausted alone", errors.New("exceeded maximum number of attempts")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, dispositionFail, classifyError("ecr", tc.err))
		})
	}
}

func TestClassifyTransportRegionMissIsEmpty(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"dns miss", errors.New(`dial tcp: lookup bedrock.us-west-1.amazonaws.com: no such host`)},
		{"unknown endpoint", errors.New("UnknownEndpoint: endpoint not found")},
		{"unresolvable", errors.New("could not resolve endpoint")},
		{"send failure exhaustion", errors.New("exceeded maximum number of attempts, request send failed")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, dispositionEmpty, classifyError("bedrock", tc.err))
		})
	}
}

// A service-not-enabled message must read as empty, while a genuine permission
// gap on the same service and the same error code must not. Collapsing the two
// is what makes a data-classification policy pass on an account nobody can read.
func TestClassifyMacieDistinguishesNotEnabledFromDenied(t *testing.T) {
	notEnabled := apiErr("AccessDeniedException", "Macie is not enabled")
	require.Equal(t, dispositionEmpty, classifyError("macie2", notEnabled))

	denied := apiErr("AccessDeniedException", "User is not authorized to perform macie2:ListFindings")
	require.Equal(t, dispositionUnreadable, classifyError("macie2", denied))
}

// The same message with a curly apostrophe must classify identically. AWS
// serves both forms, and a guard that only knows the ASCII spelling silently
// stops firing the day the service switches.
func TestClassifyToleratesCurlyApostrophe(t *testing.T) {
	ascii := apiErr("ResourceNotFoundException", "Amazon Macie isn't enabled for your account")
	curly := apiErr("ResourceNotFoundException", "Amazon Macie isn’t enabled for your account")

	require.Equal(t, dispositionEmpty, classifyError("macie2", ascii))
	require.Equal(t, dispositionEmpty, classifyError("macie2", curly),
		"curly apostrophe must classify the same as the ASCII spelling")
}

// The single-record config reads tolerate a bare not-found, because Macie
// answers that way when the feature was never configured in the region.
func TestClassifyMacieConfigScopeToleratesBareNotFound(t *testing.T) {
	err := apiErr("ResourceNotFoundException", "The request failed because the resource was not found")
	require.Equal(t, dispositionEmpty, classifyError("macie2/config", err))
}

// ...but a list endpoint gets no such licence. A not-found from ListFindings
// is a resource that vanished mid-read, and swallowing it would report a
// partial listing as a complete one.
func TestClassifyMacieListDoesNotSwallowBareNotFound(t *testing.T) {
	err := apiErr("ResourceNotFoundException", "The request failed because the resource was not found")
	require.Equal(t, dispositionFail, classifyError("macie2", err))
}

// An account that never onboarded to Macie answers the automated-discovery
// read with an access denial that never names Macie. That is an absent feature,
// not a permission gap, so it reads as empty rather than as a coverage gap.
func TestClassifyMacieConfigScopeTreatsNotOnboardedAsEmpty(t *testing.T) {
	err := apiErr("AccessDeniedException", "Account Id: [123456789012] has not been onboarded")
	require.Equal(t, dispositionEmpty, classifyError("macie2/config", err))

	// The list endpoints never see this wording, and must keep reporting a
	// denial as unreadable.
	require.Equal(t, dispositionUnreadable, classifyError("macie2", err))
}

// A scope still inherits the not-enabled rules from its bare service, so the
// narrow key only has to state where it differs.
func TestClassifyScopeInheritsServiceRules(t *testing.T) {
	notEnabled := apiErr("AccessDeniedException", "Macie is not enabled")
	require.Equal(t, dispositionEmpty, classifyError("macie2/config", notEnabled))

	denied := apiErr("AccessDeniedException", "User is not authorized to perform macie2:GetMacieSession")
	require.Equal(t, dispositionUnreadable, classifyError("macie2/config", denied))
}

// The not-enabled wording still reads as empty on the list endpoints, which is
// the whole point of keeping that rule on the bare service.
func TestClassifyMacieListStillHonoursNotEnabled(t *testing.T) {
	err := apiErr("ResourceNotFoundException", "Amazon Macie isn't enabled for your account")
	require.Equal(t, dispositionEmpty, classifyError("macie2", err))
}

// Coverage gaps are reported per service, not per endpoint scope.
func TestServiceNameStripsScope(t *testing.T) {
	require.Equal(t, "macie2", serviceName("macie2/config"))
	require.Equal(t, "ecr", serviceName("ecr"))
}

// A service rule must not leak into other services: Macie's not-enabled
// wording carries no meaning for, say, RDS.
func TestClassifyServiceRulesAreScoped(t *testing.T) {
	err := apiErr("AccessDeniedException", "Macie is not enabled")
	require.Equal(t, dispositionEmpty, classifyError("macie2", err))
	require.Equal(t, dispositionUnreadable, classifyError("rds", err),
		"another service's not-enabled wording must not be honoured here")
}

func TestClassifySecurityLakeNotEnabled(t *testing.T) {
	err := apiErr("ResourceNotFoundException", "Security Lake isn't enabled for your account in any Regions")
	require.Equal(t, dispositionEmpty, classifyError("securitylake", err))

	// A plain not-found from the same service is a real miss, not an absent
	// service, so it must still surface.
	other := apiErr("ResourceNotFoundException", "The subscriber could not be found")
	require.Equal(t, dispositionFail, classifyError("securitylake", other))
}

// Classification must survive arbitrary wrapping, since callers wrap freely.
func TestClassifyUnwrapsWrappedErrors(t *testing.T) {
	wrapped := fmt.Errorf("listing repositories: %w", apiErr("AccessDenied", "denied"))
	require.Equal(t, dispositionUnreadable, classifyError("ecr", wrapped))
}

func TestClassifyNilErrorDoesNotReportEmpty(t *testing.T) {
	// Nothing should be calling this with a nil error, but if it does it must
	// not answer "empty" and quietly drop a region's real results.
	require.Equal(t, dispositionFail, classifyError("ecr", nil))
}
