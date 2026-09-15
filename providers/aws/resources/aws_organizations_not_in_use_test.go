// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
)

// notInUseErr is what every Organizations call answers on a standalone account.
func notInUseErr() error {
	return &orgtypes.AWSOrganizationsNotInUseException{
		Message: strPtrOrg("Your account is not a member of an organization."),
	}
}

func strPtrOrg(s string) *string { return &s }

// orgDeniedErr is the 403 shape Is400AccessDeniedError matches, which is a
// different situation: the account may well be in an organization, we were
// simply not allowed to look.
func orgDeniedErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 403}},
			Err:      errors.New("AccessDeniedException: not authorized to perform organizations:DescribeOrganization"),
		},
	}
}

func TestIsOrganizationsNotInUseError(t *testing.T) {
	t.Run("the standalone-account answer is recognized", func(t *testing.T) {
		assert.True(t, isOrganizationsNotInUseError(notInUseErr()))
	})

	t.Run("through wrapping", func(t *testing.T) {
		assert.True(t, isOrganizationsNotInUseError(
			fmt.Errorf("describing organization: %w", notInUseErr())))
	})

	// Everything below leaves membership unknown rather than establishing it,
	// so treating any of them as "not in an organization" would report a
	// standalone account for one we failed to read.
	t.Run("a denial is not proof of anything", func(t *testing.T) {
		assert.False(t, isOrganizationsNotInUseError(orgDeniedErr()))
	})

	t.Run("a transport error is not proof of anything", func(t *testing.T) {
		assert.False(t, isOrganizationsNotInUseError(
			errors.New("dial tcp: lookup organizations.amazonaws.com: no such host")))
	})

	t.Run("nil is not a match", func(t *testing.T) {
		assert.False(t, isOrganizationsNotInUseError(nil))
	})
}

// The two classifiers answer different questions and must not collapse into
// each other: a denial keeps membership unknown, the not-in-use answer settles
// it. Both suppress the per-account description, but only one of them may ever
// be read as "this is a standalone account".
func TestNotInUseAndAccessDeniedStayDistinct(t *testing.T) {
	assert.True(t, isOrganizationsNotInUseError(notInUseErr()))
	assert.False(t, Is400AccessDeniedError(notInUseErr()),
		"the not-in-use answer must not be mistaken for a denial")

	assert.True(t, Is400AccessDeniedError(orgDeniedErr()))
	assert.False(t, isOrganizationsNotInUseError(orgDeniedErr()),
		"a denial must not be mistaken for a standalone account")
}
