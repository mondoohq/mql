// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEcsMetadataEndpointEnabled(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("enabled maps to true", func(t *testing.T) {
		got := ecsMetadataEndpointEnabled(strPtr("enabled"))
		require.NotNil(t, got)
		assert.True(t, *got)
	})

	t.Run("disabled maps to false", func(t *testing.T) {
		got := ecsMetadataEndpointEnabled(strPtr("disabled"))
		require.NotNil(t, got)
		assert.False(t, *got)
	})

	// A nil or unrecognized value must stay null. Collapsing it to false would
	// report the metadata endpoint as switched off on every instance whose
	// MetadataOptions the API omitted, which reads as hardened when it is not.
	t.Run("nil stays null", func(t *testing.T) {
		assert.Nil(t, ecsMetadataEndpointEnabled(nil))
	})

	t.Run("unrecognized value stays null", func(t *testing.T) {
		assert.Nil(t, ecsMetadataEndpointEnabled(strPtr("")))
		assert.Nil(t, ecsMetadataEndpointEnabled(strPtr("Enabled")))
		assert.Nil(t, ecsMetadataEndpointEnabled(strPtr("optional")))
	})
}
