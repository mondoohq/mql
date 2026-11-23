// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
)

// Synthetic: policy and rule keys stay distinct across environments and fall
// back to the listing position when GitHub omits the id.
func TestEnvironmentChildID(t *testing.T) {
	prod := environmentChildID("github.environmentBranchPolicy", "acme", "app", "production", github.Ptr(int64(12)), 0)
	staging := environmentChildID("github.environmentBranchPolicy", "acme", "app", "staging", github.Ptr(int64(12)), 0)
	assert.Equal(t, "github.environmentBranchPolicy/acme/app/production/12", prod)
	assert.NotEqual(t, prod, staging)

	assert.Equal(t, "github.environmentBranchPolicy/acme/app/production/position/3",
		environmentChildID("github.environmentBranchPolicy", "acme", "app", "production", nil, 3))
}
