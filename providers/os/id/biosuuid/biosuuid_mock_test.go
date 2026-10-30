// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package biosuuid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

// These tests use the existing SMBIOS testdata to verify end-to-end BiosUUID detection.
// The testdata files live in providers/os/resources/smbios/testdata/.

func TestBiosUUID_Linux(t *testing.T) {
	conn, err := mock.New(1, &inventory.Asset{}, mock.WithPath("../../resources/smbios/testdata/centos.toml"))
	require.NoError(t, err)

	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	uuid, err := BiosUUID(conn, platform)
	require.NoError(t, err)
	assert.Equal(t, "64f118d3-0060-4a4c-bf1f-a11d655c4d6f", uuid)
}

func TestBiosUUID_Windows(t *testing.T) {
	conn, err := mock.New(2, &inventory.Asset{}, mock.WithPath("../../resources/smbios/testdata/windows.toml"))
	require.NoError(t, err)

	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	uuid, err := BiosUUID(conn, platform)
	require.NoError(t, err)
	assert.Equal(t, "16bd4d56-6b98-23f9-493c-f6b14e7cfc0b", uuid)
}

func TestBiosUUID_macOS(t *testing.T) {
	conn, err := mock.New(3, &inventory.Asset{}, mock.WithPath("../../resources/smbios/testdata/macos.toml"))
	require.NoError(t, err)

	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	uuid, err := BiosUUID(conn, platform)
	require.NoError(t, err)
	assert.Equal(t, "e126775d-2368-4f51-9863-76d5df0c8108", uuid)
}
