// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/stretchr/testify/assert"
)

// noResourcePolicyErr is what DescribeResourcePolicy answers for an
// organization that has never delegated administration, which is the common
// case rather than an edge case.
func noResourcePolicyErr() error {
	return &orgtypes.ResourcePolicyNotFoundException{
		Message: strPtrOrg("We can't find a resource policy for your organization."),
	}
}

func TestIsResourcePolicyAbsent(t *testing.T) {
	t.Run("no delegation policy is an answer, not a failure", func(t *testing.T) {
		assert.True(t, isResourcePolicyAbsent(noResourcePolicyErr()))
	})

	t.Run("through wrapping", func(t *testing.T) {
		assert.True(t, isResourcePolicyAbsent(
			fmt.Errorf("describing resource policy: %w", noResourcePolicyErr())))
	})

	// A standalone account has no organization at all, so it certainly has no
	// delegation policy. Same answer, arrived at one step earlier.
	t.Run("a standalone account is also absence", func(t *testing.T) {
		assert.True(t, isResourcePolicyAbsent(notInUseErr()))
	})

	// Everything below leaves the question open. Reporting absence for any of
	// them would say the organization delegates nothing when we simply could
	// not find out -- and "delegates nothing" is the non-compliant finding, so
	// the error would manufacture a result rather than lose one.
	t.Run("a denial is not proof of absence", func(t *testing.T) {
		assert.False(t, isResourcePolicyAbsent(orgDeniedErr()))
	})

	t.Run("a transport error is not proof of absence", func(t *testing.T) {
		assert.False(t, isResourcePolicyAbsent(
			errors.New("dial tcp: lookup organizations.amazonaws.com: no such host")))
	})

	t.Run("nil is not absence", func(t *testing.T) {
		assert.False(t, isResourcePolicyAbsent(nil))
	})
}
