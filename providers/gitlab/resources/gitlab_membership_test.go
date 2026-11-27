// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSubgroupPath(t *testing.T) {
	// Synthetic: group full paths.
	assert.False(t, isSubgroupPath("acme"))
	assert.False(t, isSubgroupPath("/acme/"), "surrounding slashes do not make a subgroup")
	assert.True(t, isSubgroupPath("acme/platform"))
	assert.True(t, isSubgroupPath("acme/platform/api"))
	assert.False(t, isSubgroupPath(""))
}
