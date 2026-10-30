// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccessEntriesSupported(t *testing.T) {
	assert.False(t, accessEntriesSupported("CONFIG_MAP"))
	assert.True(t, accessEntriesSupported("API"))
	assert.True(t, accessEntriesSupported("API_AND_CONFIG_MAP"))
	// A cluster whose mode is unknown is listed, and an error surfaces.
	assert.True(t, accessEntriesSupported(""))
}
