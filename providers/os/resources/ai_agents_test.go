// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAntigravityCLIConfigDir(t *testing.T) {
	// Measured: agy 1.4.7 references ~/.gemini/config beside the IDE's
	// ~/.gemini/antigravity.
	assert.Equal(t, filepath.Join("/home/alice", ".gemini", "config"),
		antigravityCLIConfigDir(filepath.Join("/home/alice", defaultAntigravityConfigDir)))
	// Synthetic: a custom configPath names no CLI directory.
	assert.Equal(t, "", antigravityCLIConfigDir("/opt/antigravity"))
	assert.Equal(t, "", antigravityCLIConfigDir("/home/alice/.config/antigravity"))
	assert.Equal(t, "", antigravityCLIConfigDir(""))
}
