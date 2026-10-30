// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgentConfigDirs(t *testing.T) {
	assert.Equal(t, filepath.Join(".config", "devin"), devinDesktopConfigDir("darwin"))
	assert.Equal(t, filepath.Join(".config", "devin"), devinDesktopConfigDir("linux"))
	assert.Equal(t, filepath.Join("AppData", "Roaming", "devin"), devinDesktopConfigDir("windows"))

	assert.Equal(t, filepath.Join("Library", "Application Support", "io.quadrillion.qualia"), qualiaConfigDir("darwin"))
	assert.Equal(t, filepath.Join("AppData", "Roaming", "io.quadrillion.qualia"), qualiaConfigDir("windows"))
	assert.Equal(t, filepath.Join(".config", "io.quadrillion.qualia"), qualiaConfigDir("linux"))

	// anthropic-sdk-go uses XDG on macOS too, not ~/Library.
	assert.Equal(t, filepath.Join(".config", "anthropic"), anthropicCLIConfigDir("darwin"))
	assert.Equal(t, filepath.Join("AppData", "Roaming", "Anthropic"), anthropicCLIConfigDir("windows"))
}
