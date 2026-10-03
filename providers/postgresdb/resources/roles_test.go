// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleColumnsSelectBypassRLS(t *testing.T) {
	// roleColumnsFor swaps exactly this column; keep the two in step
	assert.Contains(t, roleColumns, "r.rolbypassrls,")
	assert.Equal(t, "false AS rolbypassrls", columnForVersion(90224, pgVersion95, "r.rolbypassrls", "false"))
}
