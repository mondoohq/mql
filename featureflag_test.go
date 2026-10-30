// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mql

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFeatureFlags(t *testing.T) {
	f := Features{byte(MassQueries)}
	assert.True(t, f.IsActive(MassQueries))

	parsed, err := DecodeFeatures(f.Encode())
	require.NoError(t, err)
	assert.Equal(t, f, parsed)

	f = Features{}
	assert.False(t, f.IsActive(MassQueries))

	parsed, err = DecodeFeatures(f.Encode())
	require.NoError(t, err)
	assert.Equal(t, f, parsed)
}

func TestScanContentMode(t *testing.T) {
	// No mode active.
	assert.Equal(t, Feature(0), Features{}.ScanContentMode())
	assert.False(t, Features{}.ScanContentChecksumsActive())

	// Single modes resolve to themselves.
	for _, m := range []Feature{ScanContentModeShadow, ScanContentModeServerCompare, ScanContentModeClientCompare} {
		f := Features{byte(m)}
		assert.Equal(t, m, f.ScanContentMode())
		assert.True(t, f.ScanContentChecksumsActive())
	}

	// NoCompare is the kill switch: it wins over any other mode and disables
	// checksum work.
	f := Features{byte(ScanContentModeShadow), byte(ScanContentModeNoCompare)}
	assert.Equal(t, ScanContentModeNoCompare, f.ScanContentMode())
	assert.False(t, f.ScanContentChecksumsActive())

	// Contradictory sets degrade by declared precedence, strongest first.
	f = Features{byte(ScanContentModeShadow), byte(ScanContentModeClientCompare)}
	assert.Equal(t, ScanContentModeClientCompare, f.ScanContentMode())
}
