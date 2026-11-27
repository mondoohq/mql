// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNeptuneClusterRefMatches(t *testing.T) {
	const arn = "arn:aws:rds:us-east-1:123456789012:cluster:graph"
	// Synthetic: a reference by ARN matches in any region.
	assert.True(t, neptuneClusterRefMatches(arn, arn, "graph", false))
	// Synthetic: a bare identifier matches only in the referring region.
	assert.True(t, neptuneClusterRefMatches("graph", arn, "graph", true))
	assert.False(t, neptuneClusterRefMatches("graph", arn, "graph", false))
	assert.False(t, neptuneClusterRefMatches("other", arn, "graph", true))
	assert.False(t, neptuneClusterRefMatches("", arn, "", true))
}
