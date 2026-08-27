// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secureBootVar = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

func TestReadEfiVarBool(t *testing.T) {
	write := func(t *testing.T, data []byte) afero.Fs {
		t.Helper()
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, efiVarsDir+"/"+secureBootVar, data, 0o444))
		return fs
	}

	t.Run("enabled variable", func(t *testing.T) {
		// 4-byte attribute header + 1-byte data (0x01 = enabled)
		on, err := readEfiVarBool(nil, write(t, []byte{0x06, 0x00, 0x00, 0x00, 0x01}), secureBootVar)
		require.NoError(t, err)
		assert.True(t, on)
	})

	t.Run("disabled variable", func(t *testing.T) {
		// 4-byte attribute header + 1-byte data (0x00 = disabled)
		on, err := readEfiVarBool(nil, write(t, []byte{0x06, 0x00, 0x00, 0x00, 0x00}), secureBootVar)
		require.NoError(t, err)
		assert.False(t, on)
	})

	t.Run("missing variable reads as off", func(t *testing.T) {
		// firmware only exposes the variable once it has one, so absent is a
		// real answer rather than a failure
		on, err := readEfiVarBool(nil, afero.NewMemMapFs(), secureBootVar)
		require.NoError(t, err)
		assert.False(t, on)
	})

	t.Run("truncated file is an error, not off", func(t *testing.T) {
		// Only 3 bytes -- too short to contain attributes + data. Reporting
		// this as "Secure Boot disabled" would be a fabricated finding.
		_, err := readEfiVarBool(nil, write(t, []byte{0x06, 0x00, 0x00}), secureBootVar)
		assert.Error(t, err)
	})
}
