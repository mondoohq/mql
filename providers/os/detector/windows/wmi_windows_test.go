// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
)

func TestIntToString(t *testing.T) {
	t.Run("NULL returns empty string", func(t *testing.T) {
		assert.Equal(t, "", intToString(wmiquery.Row{"OSType": nil}, "OSType"))
	})

	t.Run("integer of any width returns its string representation", func(t *testing.T) {
		assert.Equal(t, "42", intToString(wmiquery.Row{"OSType": uint16(42)}, "OSType"))
		assert.Equal(t, "18", intToString(wmiquery.Row{"OSType": int32(18)}, "OSType"))
	})

	t.Run("zero returns 0", func(t *testing.T) {
		assert.Equal(t, "0", intToString(wmiquery.Row{"ProductType": uint32(0)}, "ProductType"))
	})
}

func TestGetWmiInformation_Integration(t *testing.T) {
	conn := &mockLocalConnection{}
	info, err := GetWmiInformation(conn)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.NotEmpty(t, info.Version, "Version should not be empty")
	assert.NotEmpty(t, info.BuildNumber, "BuildNumber should not be empty")
	assert.NotEmpty(t, info.Caption, "Caption should not be empty")
	assert.NotEmpty(t, info.SerialNumber, "SerialNumber should not be empty, as the wmic fallback reports it")
}
