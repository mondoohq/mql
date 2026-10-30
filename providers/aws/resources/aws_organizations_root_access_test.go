// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/stretchr/testify/assert"
)

func TestIsRootAccessNotConfigured(t *testing.T) {
	// Each of these establishes that no centralized root access feature is
	// enabled, so an empty list is the honest answer rather than a lost read.
	t.Run("the account is in no organization", func(t *testing.T) {
		assert.True(t, isRootAccessNotConfigured(&iamtypes.OrganizationNotFoundException{}))
	})

	t.Run("the organization runs in consolidated-billing mode", func(t *testing.T) {
		// The feature cannot be enabled at all in that mode.
		assert.True(t, isRootAccessNotConfigured(&iamtypes.OrganizationNotInAllFeaturesModeException{}))
	})

	t.Run("IAM has no trusted access in the organization", func(t *testing.T) {
		// Trusted access is the prerequisite, so without it nothing is enabled.
		assert.True(t, isRootAccessNotConfigured(&iamtypes.ServiceAccessNotEnabledException{}))
	})

	t.Run("through wrapping", func(t *testing.T) {
		assert.True(t, isRootAccessNotConfigured(
			fmt.Errorf("listing organizations features: %w", &iamtypes.OrganizationNotFoundException{})))
	})

	// These leave the answer unknown. Returning an empty list for them would
	// report centralized root access as switched off -- which is the finding --
	// on an organization we merely failed to read.
	t.Run("a denial is not proof that the feature is off", func(t *testing.T) {
		assert.False(t, isRootAccessNotConfigured(orgDeniedErr()))
	})

	t.Run("a transport error is not proof that the feature is off", func(t *testing.T) {
		assert.False(t, isRootAccessNotConfigured(
			errors.New("dial tcp: lookup iam.amazonaws.com: no such host")))
	})

	t.Run("nil is not a not-configured answer", func(t *testing.T) {
		assert.False(t, isRootAccessNotConfigured(nil))
	})

	// A plain member account cannot read this. That leaves the organization's
	// setting unknown, not off, so it must stay an error -- the empty list is
	// the finding.
	t.Run("a member account is not proof that the feature is off", func(t *testing.T) {
		assert.False(t, isRootAccessNotConfigured(
			&iamtypes.AccountNotManagementOrDelegatedAdministratorException{}))
	})
}

// TestTrustedAccessErrorClassification pins which errors
// trustedAccessServicePrincipals treats as an answer. ListAWSServiceAccess-
// ForOrganization models seven errors, and only AWSOrganizationsNotInUse-
// Exception establishes one; the policy-type exceptions belong to the policy
// operations and can never reach this path.
func TestTrustedAccessErrorClassification(t *testing.T) {
	t.Run("a standalone account has no trusted access to report", func(t *testing.T) {
		assert.True(t, isOrganizationsNotInUseError(notInUseErr()))
	})

	t.Run("a policy-type error cannot come from this API and is not an answer", func(t *testing.T) {
		// Guards the reason this predicate is not isPolicyTypeUnavailable:
		// matching these here would be dead code that reads as intent.
		assert.False(t, isOrganizationsNotInUseError(&orgtypes.PolicyTypeNotEnabledException{}))
		assert.False(t, isOrganizationsNotInUseError(&orgtypes.PolicyTypeNotAvailableForOrganizationException{}))
	})

	t.Run("a denial is not proof of no trusted access", func(t *testing.T) {
		assert.False(t, isOrganizationsNotInUseError(orgDeniedErr()))
	})
}
