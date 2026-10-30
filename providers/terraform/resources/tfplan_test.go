// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
)

// TestTerraformPlanResourceChanges_NilPlan verifies that resourceChanges() does
// not panic when the connection carries no plan. conn.Plan() returns nil for
// non-plan assets (HCL/state), and this accessor dereferenced it without a
// guard while its sibling accessors guarded it. A zero-value Connection mirrors
// what NewStateConnection / an HCL connection produce (no plan set).
func TestTerraformPlanResourceChanges_NilPlan(t *testing.T) {
	runtime := &plugin.Runtime{Connection: &connection.Connection{}}
	p := &mqlTerraformPlan{}
	p.MqlRuntime = runtime

	res, err := p.resourceChanges()
	require.NoError(t, err)
	assert.Empty(t, res)
}
